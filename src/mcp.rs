//! Gate 7: `mcp serve`, an MCP server over stdio that offers HERCULES's checked read tools to another agent.
//!
//! Design: DESIGN_OSS_MCP_SERVER.md (approved 2026-10-30). A thin front end on the existing tool path: each
//! `tools/call` becomes the same envelope a model's call becomes (`tools::handle_envelope`), so it gets the
//! same validation, authority decision, receipt and transcript event. One server process is one run: when
//! stdin closes (or on SIGTERM/SIGINT) the run is closed and signed like a mission (attest.rs).
//!
//! Protocol: dual-era over stdio. Modern `2026-07-28` (stateless; `server/discover`, per-request `_meta`) and
//! legacy `2025-11-25` (`initialize` handshake), one era per process, fixed by the first request. Only tools
//! are offered, and only `fs_read`, `fs_list`, `fs_stat` and (when commands are enabled) `cmd_run`: every other
//! tool name is refused here, before the tool path, because the shared authority code still has v1 branches
//! (`test.*`, approval-file `shell.exec`) that a model's prompt never offers but an MCP client could name.
//! Nothing but protocol messages goes to stdout.

use crate::authority::AuthorityContext;
use crate::transcript::TranscriptWriter;
use serde_json::{json, Value};
use std::collections::HashSet;
use std::io;

pub const MODERN: &str = "2026-07-28";
pub const LEGACY: &str = "2025-11-25";
/// Longest message line accepted (bytes, without the newline).
pub const MAX_LINE_BYTES: usize = 1 << 20;
/// Limit protocol messages which do not consume the --max-calls tool budget.
pub const MAX_UNBUDGETED_MESSAGES: u64 = 65_536;
/// Hard bound on raw stdin bytes per signed MCP run (including oversized/malformed input).
/// This prevents huge messages from defeating a count-only budget.
pub const MAX_SESSION_INPUT_BYTES: u64 = 32 * 1024 * 1024;
/// tools/list and server/discover: the list is fixed for the life of the process (roots are chosen at start).
pub const LIST_TTL_MS: u64 = 86_400_000;
const META_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
const META_CLIENT: &str = "io.modelcontextprotocol/clientInfo";
const META_SERVER: &str = "io.modelcontextprotocol/serverInfo";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Era {
    Modern,
    Legacy,
}

impl Era {
    fn label(self) -> &'static str {
        match self {
            Era::Modern => MODERN,
            Era::Legacy => LEGACY,
        }
    }
}

/// What the server offers and what it may do. Built once at startup.
pub struct Server<'a> {
    pub auth: &'a AuthorityContext,
    pub max_calls: u64,
    pub era: Option<Era>,
    pub calls: u64,
    pub refused: u64,
    pub budget_refused: u64,
    pub executed: HashSet<String>,
    pub clients_claimed: Vec<Value>,
    tools: Vec<Value>,
    offered: Vec<&'static str>,
    instructions: String,
}

fn server_info() -> Value {
    json!({"name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION")})
}

fn receipt_meta_key() -> String {
    format!("{}/receipt", env!("CARGO_PKG_NAME"))
}

fn error(id: &Value, code: i64, message: &str, data: Option<Value>) -> Value {
    let mut e = json!({"code": code, "message": message});
    if let Some(d) = data {
        e["data"] = d;
    }
    json!({"jsonrpc": "2.0", "id": id, "error": e})
}

fn ok(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

impl<'a> Server<'a> {
    pub fn new(auth: &'a AuthorityContext, max_calls: u64) -> Self {
        let roots = if auth.roots.is_empty() { "none".to_string() } else { auth.roots.describe() };
        let enabled = auth.cmd.enabled().to_vec();
        let mut offered: Vec<&'static str> = vec!["fs.read", "fs.list", "fs.stat"];
        if !enabled.is_empty() {
            offered.push("cmd.run");
        }
        let where_ = format!(
            " Granted read-only roots: {roots}. This server has no sandbox: give absolute paths inside a root. Files such as .env, private keys and .git internals are always refused."
        );
        let tools = offered
            .iter()
            .filter_map(|t| crate::native::schema(t, &[]).map(|s| (t, s)))
            .map(|(t, s)| {
                let f = &s["function"];
                let mut desc = f["description"].as_str().unwrap_or("").to_string();
                desc.push_str(&where_);
                if *t == "cmd.run" {
                    desc.push_str(&format!(
                        " Enabled commands: {}. grep and rg search fixed strings only; sed supports only -n 'A,Bp'; shasum needs -a 256; git must start with -C <repo dir>.",
                        enabled.join(", ")
                    ));
                }
                json!({
                    "name": f["name"],
                    "description": desc,
                    "inputSchema": f["parameters"],
                    "annotations": {"readOnlyHint": true, "destructiveHint": false, "idempotentHint": true, "openWorldHint": false}
                })
            })
            .collect();
        let instructions = format!(
            "HERCULES read-only tools. Every call is validated, authorized and receipted; the run is signed when this server process ends.{where_} A refused call is recorded; do not retry the same path."
        );
        Server {
            auth,
            max_calls,
            era: None,
            calls: 0,
            refused: 0,
            budget_refused: 0,
            executed: HashSet::new(),
            clients_claimed: Vec::new(),
            tools,
            offered,
            instructions,
        }
    }

    /// The wire names offered, in order.
    pub fn tool_names(&self) -> Vec<String> {
        self.offered.iter().map(|t| crate::native::to_native(t)).collect()
    }

    fn with_meta(&self, mut result: Value) -> Value {
        if self.era == Some(Era::Modern) {
            result["resultType"] = json!("complete");
            result["_meta"][META_SERVER] = server_info();
        }
        result
    }

    /// Handle one message line. Returns the response line to write, if any.
    pub fn handle_line(&mut self, line: &[u8], tw: &mut TranscriptWriter) -> Option<Value> {
        let v: Value = match serde_json::from_slice(line) {
            Ok(v) => v,
            Err(e) => {
                tw.emit("mcp.request_refused", None, json!({"reason": "PARSE_ERROR", "bytes": line.len(), "sha256": crate::audit::sha256_bytes(line), "detail": e.to_string()}));
                return Some(error(&Value::Null, -32700, "Parse error", None));
            }
        };
        let Some(obj) = v.as_object() else {
            let reason = if v.is_array() { "JSON-RPC batch arrays are not supported" } else { "not a JSON-RPC object" };
            tw.emit("mcp.request_refused", None, json!({"reason": "INVALID_REQUEST", "detail": reason, "bytes": line.len(), "sha256": crate::audit::sha256_bytes(line)}));
            return Some(error(&Value::Null, -32600, reason, None));
        };
        let id = obj.get("id").cloned();
        let method = obj.get("method").and_then(Value::as_str);
        let id_ok = matches!(&id, Some(Value::String(_)) | Some(Value::Number(_)));
        if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") || (method.is_none() && id.is_some() && !obj.contains_key("result") && !obj.contains_key("error")) {
            tw.emit("mcp.request_refused", None, json!({"reason": "INVALID_REQUEST", "detail": "jsonrpc must be \"2.0\" and a request needs a method", "id": id}));
            return Some(error(id.as_ref().filter(|_| id_ok).unwrap_or(&Value::Null), -32600, "Invalid Request", None));
        }
        let Some(method) = method else {
            // A response from the client: this server never sends requests, so there is nothing to match.
            tw.emit("mcp.message_ignored", None, json!({"reason": "a response with no request from this server", "id": id}));
            return None;
        };
        let params = obj.get("params").cloned().unwrap_or(Value::Null);
        let Some(id) = id else {
            // Notifications get no response. notifications/cancelled can only name a request already answered
            // (requests are handled one at a time), so there is nothing to stop.
            tw.emit("mcp.notification", None, json!({"method": method}));
            return None;
        };
        if !id_ok {
            tw.emit("mcp.request_refused", None, json!({"reason": "INVALID_REQUEST", "detail": "id must be a string or a number", "method": method}));
            return Some(error(&Value::Null, -32600, "Invalid Request: id must be a string or a number", None));
        }
        let meta = params.get("_meta");
        let version = meta.and_then(|m| m.get(META_VERSION)).and_then(Value::as_str).map(str::to_string);
        let client = meta.and_then(|m| m.get(META_CLIENT)).cloned();
        tw.emit(
            "mcp.request",
            None,
            json!({"id": id, "method": method, "protocol_version": version, "client_info_claimed": client, "era": self.era.map(Era::label)}),
        );
        if let Some(c) = &client {
            if !self.clients_claimed.contains(c) && self.clients_claimed.len() < 16 {
                self.clients_claimed.push(c.clone());
            }
        }

        // The era: fixed by the first request, then held for the life of the process.
        if method == "initialize" {
            return Some(match self.era {
                None => {
                    self.era = Some(Era::Legacy);
                    if let Some(c) = params.get("clientInfo") {
                        if !self.clients_claimed.contains(c) && self.clients_claimed.len() < 16 {
                            self.clients_claimed.push(c.clone());
                        }
                    }
                    tw.emit("mcp.era", None, json!({"era": LEGACY, "requested": params.get("protocolVersion")}));
                    ok(
                        &id,
                        json!({
                            "protocolVersion": LEGACY,
                            "capabilities": {"tools": {"listChanged": false}},
                            "serverInfo": server_info(),
                            "instructions": self.instructions
                        }),
                    )
                }
                Some(Era::Legacy) => self.refuse(tw, &id, -32600, "initialize was already received by this server process"),
                Some(Era::Modern) => self.refuse(
                    tw,
                    &id,
                    -32600,
                    &format!("this server process is serving {MODERN} requests; start a new process for an initialize handshake"),
                ),
            });
        }
        match self.era {
            Some(Era::Legacy) => {}
            Some(Era::Modern) | None => {
                // Modern: every request names its version. server/discover is answered even without _meta,
                // because it is the stdio backward-compatibility probe.
                match version.as_deref() {
                    Some(MODERN) => {}
                    None if method == "server/discover" => {}
                    None => {
                        return Some(self.refuse(
                            tw,
                            &id,
                            -32602,
                            &format!("params._meta[\"{META_VERSION}\"] is required (this server speaks {MODERN}, or {LEGACY} after initialize)"),
                        ))
                    }
                    Some(other) => {
                        tw.emit("mcp.request_refused", None, json!({"id": id, "reason": "UNSUPPORTED_PROTOCOL_VERSION", "requested": other}));
                        self.refused += 1;
                        return Some(error(&id, -32022, "Unsupported protocol version", Some(json!({"supported": [MODERN], "requested": other}))));
                    }
                }
                if self.era.is_none() {
                    self.era = Some(Era::Modern);
                    tw.emit("mcp.era", None, json!({"era": MODERN}));
                }
            }
        }
        let era = self.era.unwrap_or(Era::Modern);
        match (method, era) {
            ("server/discover", Era::Modern) => Some(ok(
                &id,
                self.with_meta(json!({
                    "supportedVersions": [MODERN],
                    "capabilities": {"tools": {}},
                    "instructions": self.instructions,
                    "ttlMs": LIST_TTL_MS,
                    "cacheScope": "private"
                })),
            )),
            ("ping", Era::Legacy) => Some(ok(&id, json!({}))),
            ("notifications/initialized", _) => None,
            ("tools/list", _) => {
                if params.get("cursor").is_some_and(|c| !c.is_null()) {
                    return Some(self.refuse(tw, &id, -32602, "invalid cursor: this server returns its whole tool list in one page"));
                }
                let mut r = json!({"tools": self.tools});
                if era == Era::Modern {
                    r["ttlMs"] = json!(LIST_TTL_MS);
                    r["cacheScope"] = json!("private");
                }
                Some(ok(&id, self.with_meta(r)))
            }
            ("tools/call", _) => Some(self.call(&id, &params, tw)),
            _ => Some(self.refuse(tw, &id, -32601, &format!("Method not found: {method} (this server offers tools only, {} era)", era.label()))),
        }
    }

    fn refuse(&mut self, tw: &mut TranscriptWriter, id: &Value, code: i64, message: &str) -> Value {
        self.refused += 1;
        tw.emit("mcp.request_refused", None, json!({"id": id, "code": code, "detail": message}));
        error(id, code, message, None)
    }

    fn call(&mut self, id: &Value, params: &Value, tw: &mut TranscriptWriter) -> Value {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return self.refuse(tw, id, -32602, "tools/call needs params.name (a string)");
        };
        // The allowlist: only the offered wire names, never a dotted internal name or any other tool.
        let Some(internal) = self.offered.iter().find(|t| crate::native::to_native(t) == name).map(|t| t.to_string()) else {
            return self.refuse(tw, id, -32602, &format!("Unknown tool: {name} (offered: {})", self.tool_names().join(", ")));
        };
        let args = match params.get("arguments") {
            None | Some(Value::Null) => json!({}),
            Some(a @ Value::Object(_)) => a.clone(),
            Some(_) => return self.refuse(tw, id, -32602, "tools/call params.arguments must be an object"),
        };
        if self.calls >= self.max_calls {
            self.budget_refused += 1;
            let text = format!("[TOOL_RESULT] status=rejected code=CALL_BUDGET\nthis server process has run its {} calls (--max-calls); no more calls run here", self.max_calls);
            tw.emit("mcp.call_budget", None, json!({"id": id, "tool": name, "max_calls": self.max_calls}));
            return self.tool_result(id, &text, "rejected", Some("CALL_BUDGET".into()), None, false);
        }
        self.calls += 1;
        let n = self.calls;
        let rid = format!("mcp_{n}");
        let envelope = json!({"tool": internal, "args": args, "request_id": rid}).to_string();
        match crate::tools::handle_envelope(&envelope, &mut self.executed, tw, n, self.auth) {
            crate::tools::ToolTurn::Handled(r) => {
                let receipted = r.receipt.is_some();
                self.tool_result(id, &r.observation, &r.result_status, r.rejection_code, Some(&rid), receipted)
            }
            crate::tools::ToolTurn::NotTool => self.tool_result(id, "[TOOL_RESULT] status=tool_failure\nthe request was not handled", "tool_failure", None, Some(&rid), false),
        }
    }

    fn tool_result(&mut self, id: &Value, text: &str, status: &str, code: Option<String>, rid: Option<&str>, receipted: bool) -> Value {
        let mut r = json!({
            "content": [{"type": "text", "text": text}],
            "isError": status != "ok",
        });
        r["_meta"][receipt_meta_key()] = json!({
            "request_id": rid,
            "status": status,
            "code": code,
            "observation_sha256": crate::audit::sha256_text(text),
            "receipted": receipted
        });
        ok(id, self.with_meta(r))
    }
}

// ------------------------------------------------------------------------------------------------- stdio

pub enum Stop {
    StdinEof,
    Signal,
    WriteFailed(String),
    InputBudget,
}

impl Stop {
    pub fn label(&self) -> &'static str {
        match self {
            Stop::StdinEof => "STDIN_EOF",
            Stop::Signal => "SIGNAL",
            Stop::WriteFailed(_) => "EVIDENCE_WRITE_FAILED",
            Stop::InputBudget => "INPUT_BUDGET",
        }
    }
}

/// Serve until stdin closes, a signal arrives, or the transcript or stdout cannot be written.
/// Reads with poll(2) so SIGTERM/SIGINT end the run even while no message is arriving.
pub fn serve(server: &mut Server, tw: &mut TranscriptWriter) -> Stop {
    use std::sync::atomic::Ordering;
    let mut buf: Vec<u8> = Vec::new();
    let mut discarding = false; // inside an over-long line: drop bytes until its newline
    // Nonblocking writes allow prompt SIGTERM closeout even if the client stops reading.
    // O_NONBLOCK is shared with holders of the same open file description. Restore
    // the original flags on EVERY return path, before the signed closeout.
    let _stdout_mode = match StdoutModeGuard::enter() {
        Ok(mode) => mode,
        Err(e) => return Stop::WriteFailed(format!("stdout nonblocking setup: {e}")),
    };
    let mut bytes_read = 0u64;
    let mut unbudgeted = 0u64;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        if crate::gateway::CANCELLED.load(Ordering::SeqCst) {
            return Stop::Signal;
        }
        let mut pfd = libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 };
        // SAFETY: one valid pollfd for the duration of the call.
        let pr = unsafe { libc::poll(&mut pfd, 1, 200) };
        if pr < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Stop::StdinEof;
        }
        if pr == 0 {
            continue;
        }
        // SAFETY: reading into an owned buffer of the given length.
        let n = unsafe { libc::read(0, chunk.as_mut_ptr().cast(), chunk.len()) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Stop::StdinEof;
        }
        let eof = n == 0;
        if n > 0 && bump_session_input_bytes(&mut bytes_read, n as usize, tw) {
            return Stop::InputBudget;
        }
        buf.extend_from_slice(&chunk[..n as usize]);
        // Every complete line, plus at EOF a last line without its newline.
        loop {
            let line: Vec<u8> = match buf.iter().position(|b| *b == b'\n') {
                Some(i) => {
                    let l = buf[..i].to_vec();
                    buf.drain(..=i);
                    if discarding {
                        discarding = false;
                        continue;
                    }
                    l
                }
                None if eof && !buf.is_empty() && !discarding => std::mem::take(&mut buf),
                None => {
                    if buf.len() > MAX_LINE_BYTES && !discarding {
                        discarding = true;
                        tw.emit("mcp.request_refused", None, json!({"reason": "LINE_TOO_LONG", "max_bytes": MAX_LINE_BYTES}));
                        if bump_unbudgeted(&mut unbudgeted, tw) { return Stop::InputBudget; }
                        if let Err(e) = write_line(&error(&Value::Null, -32700, "Parse error: message line longer than 1 MiB", None)) {
                            return stdout_stop(e);
                        }
                    }
                    if discarding {
                        buf.clear();
                    }
                    break;
                }
            };
            let line = line.strip_suffix(b"\r").unwrap_or(&line);
            if line.iter().all(u8::is_ascii_whitespace) {
                continue;
            }
            if line.len() > MAX_LINE_BYTES {
                tw.emit("mcp.request_refused", None, json!({"reason": "LINE_TOO_LONG", "max_bytes": MAX_LINE_BYTES}));
                if bump_unbudgeted(&mut unbudgeted, tw) { return Stop::InputBudget; }
                if let Err(e) = write_line(&error(&Value::Null, -32700, "Parse error: message line longer than 1 MiB", None)) {
                    return stdout_stop(e);
                }
                continue;
            }
            let calls_before = server.calls;
            let resp = server.handle_line(line, tw);
            // All messages not charged as executed tool calls are independently
            // budgeted, including notifications, malformed input and budget refusals.
            if server.calls == calls_before && bump_unbudgeted(&mut unbudgeted, tw) {
                return Stop::InputBudget;
            }
            if let Some(detail) = tw.write_error() {
                return Stop::WriteFailed(detail.to_string());
            }
            if let Some(resp) = resp {
                let text = resp.to_string();
                tw.emit(
                    "mcp.response",
                    None,
                    json!({"id": resp.get("id"), "error_code": resp.pointer("/error/code"), "is_error": resp.pointer("/result/isError"), "sha256": crate::audit::sha256_text(&text)}),
                );
                if let Err(e) = write_line(&resp) {
                    return stdout_stop(e);
                }
            }
            if crate::gateway::CANCELLED.load(Ordering::SeqCst) {
                return Stop::Signal;
            }
        }
        if eof {
            return Stop::StdinEof;
        }
    }
}

fn bump_unbudgeted(count: &mut u64, tw: &mut TranscriptWriter) -> bool {
    *count = count.saturating_add(1);
    if *count > MAX_UNBUDGETED_MESSAGES {
        tw.emit("mcp.input_budget", None, json!({"unbudgeted_messages": *count, "max": MAX_UNBUDGETED_MESSAGES}));
        true
    } else {
        false
    }
}

fn stdout_stop(e: io::Error) -> Stop {
    if crate::gateway::CANCELLED.load(std::sync::atomic::Ordering::SeqCst) {
        Stop::Signal
    } else {
        Stop::WriteFailed(format!("stdout: {e}"))
    }
}

/// A scoped change, not a permanent mutation of the client-owned stdout pipe/TTY.
/// Dropped before mcp::serve returns to the signing/manifest path.
struct StdoutModeGuard {
    original_flags: libc::c_int,
    changed: bool,
}

impl StdoutModeGuard {
    fn enter() -> io::Result<Self> {
        let fd = libc::STDOUT_FILENO;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        let changed = flags & libc::O_NONBLOCK == 0;
        if changed && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { original_flags: flags, changed })
    }
}

impl Drop for StdoutModeGuard {
    fn drop(&mut self) {
        if self.changed {
            // Closing errors are handled by the caller when writes fail. This
            // restoration is best effort because Drop cannot return an error.
            let _ = unsafe { libc::fcntl(libc::STDOUT_FILENO, libc::F_SETFL, self.original_flags) };
        }
    }
}

fn bump_session_input_bytes(bytes: &mut u64, next: usize, tw: &mut TranscriptWriter) -> bool {
    *bytes = bytes.saturating_add(next as u64);
    if *bytes > MAX_SESSION_INPUT_BYTES {
        tw.emit("mcp.input_budget", None, json!({
            "reason": "SESSION_INPUT_BYTES", "bytes_read": *bytes, "max_bytes": MAX_SESSION_INPUT_BYTES
        }));
        true
    } else {
        false
    }
}

// Nonblocking stdout is essential: write_all/flush on an unread pipe would
// otherwise hide SIGTERM from the server's shutdown/signature path.
fn write_line(v: &Value) -> io::Result<()> {
    use std::sync::atomic::Ordering;
    let mut message = v.to_string().into_bytes();
    message.push(b'\n');
    let mut sent = 0usize;
    while sent < message.len() {
        if crate::gateway::CANCELLED.load(Ordering::SeqCst) {
            return Err(io::Error::new(io::ErrorKind::Interrupted, "signal while writing stdout"));
        }
        // SAFETY: message is owned, the slice remains alive during the call,
        // and stdout was set to O_NONBLOCK before the serve loop.
        let n = unsafe {
            libc::write(libc::STDOUT_FILENO, message[sent..].as_ptr().cast(), message.len() - sent)
        };
        if n > 0 {
            sent += n as usize;
            continue;
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "stdout wrote zero bytes"));
        }
        let e = io::Error::last_os_error();
        if e.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if e.kind() != io::ErrorKind::WouldBlock {
            return Err(e);
        }
        let mut pfd = libc::pollfd { fd: libc::STDOUT_FILENO, events: libc::POLLOUT, revents: 0 };
        // SAFETY: one valid pollfd for the duration of the call. Poll is bounded,
        // so the cancellation flag is checked at least every 100 ms.
        let pr = unsafe { libc::poll(&mut pfd, 1, 100) };
        if pr < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
        if pr > 0 && (pfd.revents & libc::POLLNVAL) != 0 {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "stdout poll invalid fd"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tw() -> (TranscriptWriter, String) {
        crate::features::set_build1(true);
        let p = std::env::temp_dir().join(format!(
            "hercules-mcp-{}-{}.ndjson",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let s = p.display().to_string();
        (TranscriptWriter::new(&s, "mcp-test").unwrap(), s)
    }

    #[test]
    fn unbudgeted_messages_have_a_hard_stop_with_a_transcript_event() {
        let (mut w, path) = tw();
        let mut count = 0u64;
        for _ in 0..MAX_UNBUDGETED_MESSAGES {
            assert!(!bump_unbudgeted(&mut count, &mut w));
        }
        assert!(bump_unbudgeted(&mut count, &mut w));
        w.finish().unwrap();
        let events = events(&path);
        assert_eq!(events.last().unwrap()["event"], "mcp.input_budget");
        // The violating 1,025th message is counted in the signed stop event;
        // exactly 1,024 prior messages were allowed through.
        assert_eq!(count, MAX_UNBUDGETED_MESSAGES + 1);
        assert_eq!(events.last().unwrap()["data"]["unbudgeted_messages"], MAX_UNBUDGETED_MESSAGES + 1);
        assert_eq!(events.last().unwrap()["data"]["max"], MAX_UNBUDGETED_MESSAGES);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_input_byte_limit_counts_oversized_and_normal_chunks() {
        let (mut w, path) = tw();
        let mut bytes = 0;
        assert!(!bump_session_input_bytes(&mut bytes, MAX_LINE_BYTES, &mut w));
        assert!(!bump_session_input_bytes(&mut bytes, (MAX_SESSION_INPUT_BYTES as usize) - MAX_LINE_BYTES, &mut w));
        assert!(bump_session_input_bytes(&mut bytes, 1, &mut w));
        w.finish().unwrap();
        let last = events(&path).pop().unwrap();
        assert_eq!(last["event"], "mcp.input_budget");
        assert_eq!(last["data"]["reason"], "SESSION_INPUT_BYTES");
        assert_eq!(last["data"]["bytes_read"], MAX_SESSION_INPUT_BYTES + 1);
        assert_eq!(last["data"]["max_bytes"], MAX_SESSION_INPUT_BYTES);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_heartbeat_volume_no_longer_hits_old_limit() {
        let (mut w, path) = tw();
        let mut count = 0;
        for _ in 0..2048 {
            assert!(!bump_unbudgeted(&mut count, &mut w));
        }
        assert!(count < MAX_UNBUDGETED_MESSAGES);
        w.finish().unwrap();
        assert!(!events(&path).iter().any(|e| e["event"] == "mcp.input_budget"));
        std::fs::remove_file(path).unwrap();
    }

    fn ctx(cmds: bool) -> AuthorityContext {
        let mut a = AuthorityContext::new(None, None, None).unwrap();
        let dir = std::env::temp_dir();
        a.roots = crate::roots::RootPolicy::new(vec![crate::roots::Root { name: "t".into(), path: std::fs::canonicalize(dir).unwrap() }], vec![]);
        a.cmd = crate::cmd::CmdPolicy::from_config(if cmds { None } else { Some(&[][..]) }, 5).unwrap();
        a
    }

    fn req(id: u64, method: &str, params: Value) -> Vec<u8> {
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string().into_bytes()
    }

    fn modern(extra: Value) -> Value {
        let mut p = extra;
        p["_meta"] = json!({META_VERSION: MODERN, "io.modelcontextprotocol/clientCapabilities": {}, META_CLIENT: {"name": "t", "version": "1"}});
        p
    }

    fn events(path: &str) -> Vec<Value> {
        std::fs::read_to_string(path).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    #[test]
    fn framing_errors() {
        let a = ctx(true);
        let mut s = Server::new(&a, 10);
        let (mut w, _) = tw();
        assert_eq!(s.handle_line(b"{not json", &mut w).unwrap()["error"]["code"], -32700);
        assert_eq!(s.handle_line(b"[1,2]", &mut w).unwrap()["error"]["code"], -32600);
        assert_eq!(s.handle_line(br#"{"jsonrpc":"1.0","id":1,"method":"tools/list"}"#, &mut w).unwrap()["error"]["code"], -32600);
        assert_eq!(s.handle_line(br#"{"jsonrpc":"2.0","id":{"a":1},"method":"tools/list"}"#, &mut w).unwrap()["error"]["code"], -32600);
        // Notifications and stray responses get no reply.
        assert!(s.handle_line(br#"{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}"#, &mut w).is_none());
        assert!(s.handle_line(br#"{"jsonrpc":"2.0","id":5,"result":{}}"#, &mut w).is_none());
        assert_eq!(s.era, None);
    }

    #[test]
    fn modern_era_and_versions() {
        let a = ctx(true);
        let mut s = Server::new(&a, 10);
        let (mut w, _) = tw();
        let d = s.handle_line(&req(1, "server/discover", json!({})), &mut w).unwrap();
        assert_eq!(d["result"]["supportedVersions"], json!([MODERN]));
        assert_eq!(d["result"]["resultType"], "complete");
        assert_eq!(d["result"]["cacheScope"], "private");
        assert!(d["result"]["ttlMs"].as_u64().is_some());
        assert_eq!(d["result"]["_meta"][META_SERVER]["name"], env!("CARGO_PKG_NAME"));
        assert_eq!(s.era, Some(Era::Modern));
        // Another version: -32022 with the supported list.
        let mut p = modern(json!({}));
        p["_meta"][META_VERSION] = json!("2025-06-18");
        let e = s.handle_line(&req(2, "tools/list", p), &mut w).unwrap();
        assert_eq!(e["error"]["code"], -32022);
        assert_eq!(e["error"]["data"], json!({"supported": [MODERN], "requested": "2025-06-18"}));
        // No version on a modern request (other than discover).
        assert_eq!(s.handle_line(&req(3, "tools/list", json!({})), &mut w).unwrap()["error"]["code"], -32602);
        // initialize after the modern era began, and legacy-only ping.
        assert_eq!(s.handle_line(&req(4, "initialize", json!({"protocolVersion": LEGACY})), &mut w).unwrap()["error"]["code"], -32600);
        assert_eq!(s.handle_line(&req(5, "ping", modern(json!({}))), &mut w).unwrap()["error"]["code"], -32601);
        assert_eq!(s.handle_line(&req(6, "resources/list", modern(json!({}))), &mut w).unwrap()["error"]["code"], -32601);
    }

    #[test]
    fn legacy_era() {
        let a = ctx(true);
        let mut s = Server::new(&a, 10);
        let (mut w, _) = tw();
        let i = s.handle_line(&req(1, "initialize", json!({"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "old", "version": "0"}})), &mut w).unwrap();
        assert_eq!(i["result"]["protocolVersion"], LEGACY);
        assert_eq!(i["result"]["capabilities"]["tools"]["listChanged"], false);
        assert!(i["result"].get("resultType").is_none());
        assert!(s.handle_line(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#, &mut w).is_none());
        assert_eq!(s.handle_line(&req(2, "ping", json!({})), &mut w).unwrap()["result"], json!({}));
        let l = s.handle_line(&req(3, "tools/list", json!({})), &mut w).unwrap();
        assert!(l["result"].get("ttlMs").is_none() && l["result"]["tools"].as_array().unwrap().len() == 4);
        assert_eq!(s.handle_line(&req(4, "initialize", json!({})), &mut w).unwrap()["error"]["code"], -32600);
        assert_eq!(s.handle_line(&req(5, "server/discover", json!({})), &mut w).unwrap()["error"]["code"], -32601);
        assert!(s.clients_claimed.contains(&json!({"name": "old", "version": "0"})));
    }

    #[test]
    fn tools_list_shape_and_order() {
        let a = ctx(true);
        let mut s = Server::new(&a, 10);
        let (mut w, _) = tw();
        let l = s.handle_line(&req(1, "tools/list", modern(json!({}))), &mut w).unwrap();
        let tools = l["result"]["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["fs_read", "fs_list", "fs_stat", "cmd_run"]);
        for t in tools {
            assert_eq!(t["inputSchema"]["type"], "object");
            assert_eq!(t["annotations"]["readOnlyHint"], true);
            assert!(t["description"].as_str().unwrap().contains(&a.roots.describe()));
        }
        assert!(tools[3]["description"].as_str().unwrap().contains("Enabled commands: "));
        assert_eq!(l["result"]["cacheScope"], "private");
        assert_eq!(s.handle_line(&req(2, "tools/list", modern(json!({"cursor": "x"}))), &mut w).unwrap()["error"]["code"], -32602);
        // No commands enabled: no cmd_run.
        let a2 = ctx(false);
        let s2 = Server::new(&a2, 10);
        assert_eq!(s2.tool_names(), ["fs_read", "fs_list", "fs_stat"]);
    }

    #[test]
    fn allowlist_refuses_before_the_tool_path() {
        let a = ctx(true);
        let mut s = Server::new(&a, 10);
        let (mut w, path) = tw();
        for name in ["test_echo", "test.echo", "shell_exec", "shell.exec", "fs_write", "fs.read", "answer_submit", "evidence_check", "nope"] {
            let r = s.handle_line(&req(1, "tools/call", modern(json!({"name": name, "arguments": {"text": "x"}}))), &mut w).unwrap();
            assert_eq!(r["error"]["code"], -32602, "{name}");
        }
        assert_eq!(s.calls, 0);
        drop(w);
        let ev = events(&path);
        assert!(ev.iter().all(|e| !e["event"].as_str().unwrap().starts_with("turn.")), "a refused name reached the tool path");
    }

    #[test]
    fn calls_get_receipts_and_the_budget_holds() {
        let a = ctx(true);
        let dir = std::env::temp_dir().join(format!("hercules-mcp-call-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = std::fs::canonicalize(&dir).unwrap().join("x.txt");
        std::fs::write(&file, "alpha\nbeta\n").unwrap();
        let mut s = Server::new(&a, 3);
        let (mut w, path) = tw();
        let call = |s: &mut Server, w: &mut TranscriptWriter, id: u64, name: &str, args: Value| s.handle_line(&req(id, "tools/call", modern(json!({"name": name, "arguments": args}))), w).unwrap();
        let r = call(&mut s, &mut w, 1, "fs_read", json!({"path": file.display().to_string()}));
        let text = r["result"]["content"][0]["text"].as_str().unwrap().to_string();
        assert_eq!(r["result"]["isError"], false, "{r}");
        assert!(text.contains("alpha"));
        let m = &r["result"]["_meta"][receipt_meta_key()];
        assert_eq!(m["request_id"], "mcp_1");
        assert_eq!(m["observation_sha256"], crate::audit::sha256_text(&text));
        assert_eq!(m["receipted"], true);
        // A refused read (relative path: no sandbox) and bad arguments are tool errors, not protocol errors.
        let r = call(&mut s, &mut w, 2, "fs_read", json!({"path": "x.txt"}));
        assert_eq!(r["result"]["isError"], true);
        let r = call(&mut s, &mut w, 3, "fs_read", json!({"path": file.display().to_string(), "request_id": "mine"}));
        assert_eq!(r["result"]["isError"], true);
        // The budget (3): the fourth call does not run.
        let r = call(&mut s, &mut w, 4, "fs_stat", json!({"path": file.display().to_string()}));
        assert_eq!(r["result"]["isError"], true);
        assert_eq!(r["result"]["_meta"][receipt_meta_key()]["code"], "CALL_BUDGET");
        assert_eq!((s.calls, s.budget_refused), (3, 1));
        drop(w);
        let ev = events(&path);
        let receipts: Vec<&Value> = ev.iter().filter(|e| e["event"] == "turn.tool_result").map(|e| &e["data"]["receipt"]).collect();
        assert_eq!(receipts[0]["observation_sha256"], crate::audit::sha256_text(&text));
        assert_eq!(receipts.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
