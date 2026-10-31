//! Native Model Gateway (Gate 03, extended for Gate 04 multi-turn messages).
//! Transport only. Model text is DATA: no exec, no spawn, no filesystem paths here.
//! Every response (and every stream chunk) must carry the exact requested model identity.
//! Timeout and operator cancellation are explicit non-success stop reasons. Retry policy: none.
//! Build 2: two wire formats behind one call. `ollama` (v1 and v2) is unchanged byte for
//! byte. `openai` (v2 only) speaks `/v1/chat/completions` to OpenAI-compatible servers,
//! with an optional bearer key that never leaves the request header.

use crate::errors::{AppError, ErrCat};
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub static CANCELLED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_sig: libc::c_int) {
    CANCELLED.store(true, Ordering::SeqCst);
}

pub fn install_signal_handlers() {
    let h: extern "C" fn(libc::c_int) = handle_signal;
    unsafe {
        libc::signal(libc::SIGINT, h as usize);
        libc::signal(libc::SIGTERM, h as usize);
    }
}

fn parse_endpoint(ep: &str) -> Result<(String, u16), AppError> {
    let rest = ep.strip_prefix("http://").ok_or_else(|| {
        AppError::new(
            ErrCat::ConfigInvalidValue,
            "gateway supports http:// endpoints only (local provider)",
        )
    })?;
    let rest = rest.trim_end_matches('/');
    let (host, port) = match rest.rsplit_once(':') {
        Some((h, p)) => (
            h.to_string(),
            p.parse::<u16>()
                .map_err(|_| AppError::new(ErrCat::ConfigInvalidValue, "bad endpoint port"))?,
        ),
        None => (rest.to_string(), 80),
    };
    if host.is_empty() {
        return Err(AppError::new(
            ErrCat::ConfigInvalidValue,
            "empty endpoint host",
        ));
    }
    Ok((host, port))
}

enum ChunkState {
    Size,
    Data(usize),
    CrlfAfterData(usize),
    Done,
}

struct Dechunker {
    state: ChunkState,
    size_line: Vec<u8>,
}

impl Dechunker {
    fn new() -> Self {
        Dechunker {
            state: ChunkState::Size,
            size_line: Vec::new(),
        }
    }
    fn feed(&mut self, mut data: &[u8], out: &mut Vec<u8>) -> Result<bool, AppError> {
        loop {
            match self.state {
                ChunkState::Done => return Ok(true),
                ChunkState::Size => {
                    let mut consumed = 0;
                    let mut newline = false;
                    for (i, b) in data.iter().enumerate() {
                        self.size_line.push(*b);
                        consumed = i + 1;
                        if *b == b'\n' {
                            newline = true;
                            break;
                        }
                    }
                    data = &data[consumed..];
                    if !newline {
                        return Ok(false);
                    }
                    let line = String::from_utf8_lossy(&self.size_line).to_string();
                    self.size_line.clear();
                    let sz_str = line.trim().split(';').next().unwrap_or("").trim();
                    if sz_str.is_empty() {
                        continue;
                    }
                    let sz = usize::from_str_radix(sz_str, 16).map_err(|_| {
                        AppError::new(
                            ErrCat::ResponseMalformed,
                            format!("bad chunk size line: {sz_str}"),
                        )
                    })?;
                    if sz == 0 {
                        self.state = ChunkState::Done;
                        return Ok(true);
                    }
                    self.state = ChunkState::Data(sz);
                }
                ChunkState::Data(remaining) => {
                    if data.is_empty() {
                        return Ok(false);
                    }
                    let take = remaining.min(data.len());
                    out.extend_from_slice(&data[..take]);
                    data = &data[take..];
                    if take == remaining {
                        self.state = ChunkState::CrlfAfterData(2);
                    } else {
                        self.state = ChunkState::Data(remaining - take);
                    }
                }
                ChunkState::CrlfAfterData(k) => {
                    if data.is_empty() {
                        return Ok(false);
                    }
                    let take = k.min(data.len());
                    data = &data[take..];
                    if take == k {
                        self.state = ChunkState::Size;
                    } else {
                        self.state = ChunkState::CrlfAfterData(k - take);
                    }
                }
            }
        }
    }
}

pub struct HttpResult {
    pub status: u16,
    pub body: Vec<u8>,
    pub lines: Vec<String>,
}

pub fn post(
    endpoint: &str,
    path: &str,
    request_body: &str,
    deadline: Instant,
    on_line: Option<&mut dyn FnMut(&str)>,
) -> Result<HttpResult, AppError> {
    post_with_headers(endpoint, path, request_body, deadline, on_line, &[])
}

/// `post` with extra request headers (Build 2: the openai bearer key). Header values
/// must not contain CR or LF; they are never echoed into errors or transcripts.
pub fn post_with_headers(
    endpoint: &str,
    path: &str,
    request_body: &str,
    deadline: Instant,
    mut on_line: Option<&mut dyn FnMut(&str)>,
    extra_headers: &[(&str, String)],
) -> Result<HttpResult, AppError> {
    for (k, v) in extra_headers {
        if k.contains(['\r', '\n', ':']) || v.contains(['\r', '\n']) {
            return Err(AppError::new(ErrCat::ConfigInvalidValue, "request header contains a line break"));
        }
    }
    let (host, port) = parse_endpoint(endpoint)?;
    let addrs: Vec<std::net::SocketAddr> = format!("{host}:{port}")
        .to_socket_addrs()
        .map_err(|e| AppError::new(ErrCat::ProviderConnect, format!("resolve: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(AppError::new(
            ErrCat::ProviderConnect,
            "no address resolved",
        ));
    }
    let mut stream_opt: Option<TcpStream> = None;
    let mut last_err = String::new();
    for addr in &addrs {
        match TcpStream::connect_timeout(addr, Duration::from_secs(3)) {
            Ok(s) => {
                stream_opt = Some(s);
                break;
            }
            Err(e) => {
                last_err = format!("{addr}: {e}");
            }
        }
    }
    let mut stream = stream_opt.ok_or_else(|| {
        AppError::new(
            ErrCat::ProviderConnect,
            format!("connect failed on all resolved addresses; last: {last_err}"),
        )
    })?;
    stream
        .set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| AppError::new(ErrCat::Internal, format!("set_read_timeout: {e}")))?;

    let mut extra = String::new();
    for (k, v) in extra_headers {
        extra.push_str(k);
        extra.push_str(": ");
        extra.push_str(v);
        extra.push_str("\r\n");
    }
    let req = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{request_body}",
        request_body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| AppError::new(ErrCat::ProviderConnect, format!("write: {e}")))?;

    let mut raw_head: Vec<u8> = Vec::new();
    let mut headers_done = false;
    let mut status: u16 = 0;
    let mut chunked = false;
    let mut content_length: Option<usize> = None;

    let mut body: Vec<u8> = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let mut lines: Vec<String> = Vec::new();
    let mut dech = Dechunker::new();
    let mut chunked_done = false;

    let push_body = |bytes: &[u8],
                     body: &mut Vec<u8>,
                     pending: &mut Vec<u8>,
                     lines: &mut Vec<String>,
                     on_line: &mut Option<&mut dyn FnMut(&str)>| {
        body.extend_from_slice(bytes);
        pending.extend_from_slice(bytes);
        while let Some(pos) = pending.iter().position(|&b| b == b'\n') {
            let mut line: Vec<u8> = pending.drain(..=pos).collect();
            if line.last() == Some(&b'\n') {
                line.pop();
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            let s = String::from_utf8_lossy(&line).to_string();
            if !s.trim().is_empty() {
                if let Some(cb) = on_line.as_deref_mut() {
                    cb(&s);
                }
                lines.push(s);
            }
        }
    };

    let mut buf = [0u8; 16384];
    loop {
        if CANCELLED.load(Ordering::SeqCst) {
            return Err(AppError::new(
                ErrCat::Cancelled,
                "operator cancellation (signal)",
            ));
        }
        if Instant::now() > deadline {
            return Err(AppError::new(ErrCat::Timeout, "deadline exceeded"));
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let mut incoming: &[u8] = &buf[..n];
                if !headers_done {
                    raw_head.extend_from_slice(incoming);
                    if raw_head.len() > 65536 {
                        return Err(AppError::new(
                            ErrCat::ResponseMalformed,
                            "headers too large",
                        ));
                    }
                    if let Some(pos) = raw_head.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head_text = String::from_utf8_lossy(&raw_head[..pos]).to_string();
                        let mut it = head_text.lines();
                        let status_line = it.next().unwrap_or("");
                        status = status_line
                            .split_whitespace()
                            .nth(1)
                            .and_then(|s| s.parse::<u16>().ok())
                            .ok_or_else(|| {
                                AppError::new(ErrCat::ResponseMalformed, "bad status line")
                            })?;
                        for h in it {
                            let hl = h.to_ascii_lowercase();
                            if hl.starts_with("transfer-encoding:") && hl.contains("chunked") {
                                chunked = true;
                            }
                            if let Some(v) = hl.strip_prefix("content-length:") {
                                content_length = v.trim().parse::<usize>().ok();
                            }
                        }
                        let leftover: Vec<u8> = raw_head[pos + 4..].to_vec();
                        headers_done = true;
                        if !leftover.is_empty() {
                            if chunked {
                                let mut decoded = Vec::new();
                                chunked_done = dech.feed(&leftover, &mut decoded)?;
                                push_body(
                                    &decoded,
                                    &mut body,
                                    &mut pending,
                                    &mut lines,
                                    &mut on_line,
                                );
                            } else {
                                push_body(
                                    &leftover,
                                    &mut body,
                                    &mut pending,
                                    &mut lines,
                                    &mut on_line,
                                );
                            }
                        }
                        incoming = &[];
                    }
                }
                if headers_done && !incoming.is_empty() {
                    if chunked {
                        let mut decoded = Vec::new();
                        chunked_done = dech.feed(incoming, &mut decoded)?;
                        push_body(&decoded, &mut body, &mut pending, &mut lines, &mut on_line);
                    } else {
                        push_body(incoming, &mut body, &mut pending, &mut lines, &mut on_line);
                    }
                }
                if headers_done {
                    if chunked && chunked_done {
                        break;
                    }
                    if let Some(cl) = content_length {
                        if body.len() >= cl {
                            break;
                        }
                    }
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                continue;
            }
            Err(e) => {
                return Err(AppError::new(ErrCat::ProviderConnect, format!("read: {e}")));
            }
        }
    }
    if !pending.is_empty() {
        let s = String::from_utf8_lossy(&pending).to_string();
        if !s.trim().is_empty() {
            if let Some(cb) = on_line.as_deref_mut() {
                cb(&s);
            }
            lines.push(s);
        }
        pending.clear();
    }
    if !headers_done {
        return Err(AppError::new(
            ErrCat::ResponseMalformed,
            "connection closed before headers",
        ));
    }
    Ok(HttpResult {
        status,
        body,
        lines,
    })
}

pub struct ChatArgs {
    /// "ollama" or "openai" (config `provider.kind`).
    pub provider: String,
    /// Bearer key for `openai`; ignored by `ollama`. Never logged.
    pub api_key: Option<String>,
    /// `openai` only: send `chat_template_kwargs.enable_thinking = false`.
    pub thinking_off: bool,
    pub endpoint: String,
    pub model: String,
    pub messages: Vec<(String, String)>, // (role, content) in order
    pub stream: bool,
    pub timeout: Duration,
    pub num_predict: i64,
    /// temperature 0 when true; otherwise the model's own sampling settings (seed still fixed).
    pub greedy: bool,
    /// Build 3.6 (`openai` only): native tool calling. The history is re-encoded into `tool_calls` /
    /// `role: tool` messages (native.rs), `tools` is sent when set, and `message.tool_calls` is returned as
    /// `native_calls` instead of being written into the text.
    pub native: bool,
    /// Build 3.6: the `tools` array for this request (None or empty: the key is not sent).
    pub tools: Option<Vec<serde_json::Value>>,
}

/// The Ollama `options` object a request sends.
pub fn chat_options(num_predict: i64, greedy: bool) -> serde_json::Value {
    if greedy {
        serde_json::json!({"temperature": 0, "seed": 7, "num_predict": num_predict})
    } else {
        serde_json::json!({"seed": 7, "num_predict": num_predict})
    }
}

pub struct ChatResult {
    /// Build 3.6: the calls in `message.tool_calls` (native mode only; empty otherwise).
    pub native_calls: Vec<crate::native::NativeCall>,
    /// Build 2 (openai): tool calls the server parsed out of the text into
    /// `message.tool_calls`, written back into `content` as native markup.
    pub server_tool_calls: usize,
    pub model_actual: String,
    pub content: String,
    pub thinking_present: bool,
    pub done_reason: String,
    pub http_status: u16,
    pub duration_ms: u128,
    pub chunk_count: usize,
    pub raw_lines: Vec<String>,
}

/// The request path each provider uses.
pub fn chat_path(provider: &str) -> &'static str {
    if provider == "openai" {
        OPENAI_CHAT_PATH
    } else {
        "/api/chat"
    }
}

pub const OPENAI_CHAT_PATH: &str = "/v1/chat/completions";

/// The sampling and length fields an `openai` request sends (recorded in evidence too).
/// `max_tokens` only when a limit is set; `temperature 0` only for greedy; seed fixed at 7.
pub fn openai_options(num_predict: i64, greedy: bool, thinking_off: bool) -> serde_json::Value {
    let mut o = serde_json::json!({"seed": 7});
    if num_predict > 0 {
        o["max_tokens"] = serde_json::json!(num_predict);
    }
    if greedy {
        o["temperature"] = serde_json::json!(0);
    }
    if thinking_off {
        o["chat_template_kwargs"] = serde_json::json!({"enable_thinking": false});
    }
    o
}

/// What a run records as its model options, per provider.
pub fn model_options(provider: &str, num_predict: i64, greedy: bool, thinking_off: bool) -> serde_json::Value {
    if provider == "openai" {
        openai_options(num_predict, greedy, thinking_off)
    } else {
        chat_options(num_predict, greedy)
    }
}

pub fn chat(a: &ChatArgs) -> Result<ChatResult, AppError> {
    if a.provider == "openai" {
        return chat_openai(a);
    }
    chat_ollama(a)
}

/// `message.tool_calls` (OpenAI shape) as `<tool_call>{"name": .., "arguments": {..}}</tool_call>`
/// lines. Arguments sent as a JSON string are parsed; arguments that are not a JSON
/// object are wrapped as `{"_arguments_not_json": ..}`, so tool validation rejects the
/// request by name (the model sees why) instead of the call being dropped.
pub fn server_tool_calls_as_markup(calls: &serde_json::Value) -> Vec<String> {
    let Some(arr) = calls.as_array() else { return Vec::new() };
    arr.iter()
        .filter_map(|c| {
            let f = &c["function"];
            let name = f["name"].as_str()?;
            let args = match &f["arguments"] {
                serde_json::Value::String(s) => serde_json::from_str(s).unwrap_or(serde_json::Value::String(s.clone())),
                serde_json::Value::Null => serde_json::json!({}),
                other => other.clone(),
            };
            let args = if args.is_object() { args } else { serde_json::json!({"_arguments_not_json": args}) };
            Some(format!("<tool_call>{}</tool_call>", serde_json::json!({"name": name, "arguments": args})))
        })
        .collect()
}

/// `finish_reason` as HERCULES reads it. Some servers (oMLX among them) say "stop" when
/// an answer reaches `max_tokens`; the token count is trusted over the label, so a cut
/// answer is always reported as "length" and the continuation logic can act on it.
pub fn openai_done_reason(finish_reason: Option<&str>, completion_tokens: Option<u64>, max_tokens: i64) -> String {
    let fr = finish_reason.unwrap_or("stop");
    if fr == "length" {
        return "length".to_string();
    }
    if max_tokens > 0 {
        if let Some(used) = completion_tokens {
            if used >= max_tokens as u64 {
                return "length".to_string();
            }
        }
    }
    fr.to_string()
}

fn chat_openai(a: &ChatArgs) -> Result<ChatResult, AppError> {
    if a.stream {
        return Err(AppError::new(
            ErrCat::Usage,
            "provider.kind = openai supports non-streaming requests only",
        ));
    }
    let started = Instant::now();
    let deadline = started + a.timeout;
    let msgs: Vec<serde_json::Value> = if a.native {
        crate::native::encode_messages(&a.messages)
    } else {
        a.messages
            .iter()
            .map(|(r, c)| serde_json::json!({"role": r, "content": c}))
            .collect()
    };
    let mut body = serde_json::json!({"model": a.model, "messages": msgs, "stream": false});
    if a.native {
        if let Some(t) = a.tools.as_ref().filter(|t| !t.is_empty()) {
            body["tools"] = serde_json::Value::Array(t.clone());
        }
    }
    if let serde_json::Value::Object(extra) = openai_options(a.num_predict, a.greedy, a.thinking_off) {
        for (k, v) in extra {
            body[k] = v;
        }
    }
    let body = body.to_string();
    let mut headers: Vec<(&str, String)> = Vec::new();
    if let Some(k) = &a.api_key {
        headers.push(("Authorization", format!("Bearer {k}")));
    }
    let res = post_with_headers(&a.endpoint, OPENAI_CHAT_PATH, &body, deadline, None, &headers)?;

    if res.status != 200 {
        let snippet = String::from_utf8_lossy(&res.body);
        let mut snippet = snippet.chars().take(300).collect::<String>();
        if let Some(k) = &a.api_key {
            if !k.is_empty() {
                snippet = snippet.replace(k.as_str(), "***REDACTED***");
            }
        }
        let low = snippet.to_ascii_lowercase();
        if res.status == 404 || low.contains("not found") || low.contains("does not exist") {
            return Err(AppError::new(
                ErrCat::ModelUnknown,
                format!("http={} body={snippet}", res.status),
            ));
        }
        return Err(AppError::new(
            ErrCat::ProviderHttp,
            format!("http={} body={snippet}", res.status),
        ));
    }
    let v: serde_json::Value = serde_json::from_slice(&res.body)
        .map_err(|e| AppError::new(ErrCat::ResponseMalformed, format!("body not JSON: {e}")))?;
    let m = v["model"].as_str().unwrap_or("");
    if m.is_empty() {
        return Err(AppError::new(
            ErrCat::ResponseMalformed,
            "response missing model field",
        ));
    }
    if m != a.model {
        return Err(AppError::new(
            ErrCat::IdentityMismatch,
            format!("requested={} response_model={m}", a.model),
        ));
    }
    let Some(choice) = v["choices"].as_array().and_then(|c| c.first()) else {
        return Err(AppError::new(
            ErrCat::ResponseMalformed,
            "response has no choices",
        ));
    };
    let mut content = choice["message"]["content"].as_str().unwrap_or("").to_string();
    // Some servers (oMLX among them) parse a model's <tool_call> markup out of the text
    // into message.tool_calls. Put each call back as the native markup the harness
    // already converts, so a tool request is never silently lost.
    // Build 3.6: in native mode the calls are returned as they are, never written into the text.
    let native_calls = if a.native { crate::native::parse_tool_calls(&choice["message"]["tool_calls"]) } else { Vec::new() };
    let calls = if a.native { Vec::new() } else { server_tool_calls_as_markup(&choice["message"]["tool_calls"]) };
    let server_tool_calls = if a.native { native_calls.len() } else { calls.len() };
    for c in calls {
        if !content.is_empty() && !content.ends_with('\n') {
            content.push('\n');
        }
        content.push_str(&c);
        content.push('\n');
    }
    let thinking_present = ["reasoning_content", "reasoning"]
        .iter()
        .any(|k| choice["message"][*k].as_str().map(|s| !s.is_empty()).unwrap_or(false));
    let finish = match choice["finish_reason"].as_str() {
        Some("tool_calls") => Some("stop"),
        other => other,
    };
    let done_reason = openai_done_reason(finish, v["usage"]["completion_tokens"].as_u64(), a.num_predict);
    Ok(ChatResult {
        native_calls,
        server_tool_calls,
        model_actual: m.to_string(),
        content,
        thinking_present,
        done_reason,
        http_status: res.status,
        duration_ms: started.elapsed().as_millis(),
        chunk_count: 1,
        raw_lines: res.lines,
    })
}

fn chat_ollama(a: &ChatArgs) -> Result<ChatResult, AppError> {
    let started = Instant::now();
    let deadline = started + a.timeout;

    let msgs: Vec<serde_json::Value> = a
        .messages
        .iter()
        .map(|(r, c)| serde_json::json!({"role": r, "content": c}))
        .collect();
    let body = serde_json::json!({
        "model": a.model,
        "messages": msgs,
        "stream": a.stream,
        "options": chat_options(a.num_predict, a.greedy), "think": false
    })
    .to_string();

    let res = post(&a.endpoint, "/api/chat", &body, deadline, None)?;

    if res.status != 200 {
        let snippet = String::from_utf8_lossy(&res.body);
        let snippet = snippet.chars().take(300).collect::<String>();
        if snippet.contains("not found") {
            return Err(AppError::new(
                ErrCat::ModelUnknown,
                format!("http={} body={snippet}", res.status),
            ));
        }
        return Err(AppError::new(
            ErrCat::ProviderHttp,
            format!("http={} body={snippet}", res.status),
        ));
    }

    let mut model_actual = String::new();
    let mut content = String::new();
    let mut thinking_present = false;
    let mut done_reason = String::new();
    let mut done_seen = false;
    let chunk_count;

    if a.stream {
        chunk_count = res.lines.len();
        for line in &res.lines {
            let v: serde_json::Value = serde_json::from_str(line).map_err(|e| {
                AppError::new(
                    ErrCat::ResponseMalformed,
                    format!("stream line not JSON: {e}"),
                )
            })?;
            let m = v["model"].as_str().unwrap_or("");
            if m.is_empty() {
                return Err(AppError::new(
                    ErrCat::ResponseMalformed,
                    "stream chunk missing model field",
                ));
            }
            if model_actual.is_empty() {
                model_actual = m.to_string();
            }
            if m != a.model {
                return Err(AppError::new(
                    ErrCat::IdentityMismatch,
                    format!("requested={} chunk_model={m}", a.model),
                ));
            }
            if let Some(c) = v["message"]["content"].as_str() {
                content.push_str(c);
            }
            if v["message"]["thinking"]
                .as_str()
                .map(|s| !s.is_empty())
                .unwrap_or(false)
            {
                thinking_present = true;
            }
            if v["done"].as_bool() == Some(true) {
                done_seen = true;
                done_reason = v["done_reason"].as_str().unwrap_or("stop").to_string();
            }
        }
        if !done_seen {
            return Err(AppError::new(
                ErrCat::ResponseMalformed,
                "stream ended without done=true chunk",
            ));
        }
    } else {
        chunk_count = 1;
        let v: serde_json::Value = serde_json::from_slice(&res.body)
            .map_err(|e| AppError::new(ErrCat::ResponseMalformed, format!("body not JSON: {e}")))?;
        let m = v["model"].as_str().unwrap_or("");
        if m.is_empty() {
            return Err(AppError::new(
                ErrCat::ResponseMalformed,
                "response missing model field",
            ));
        }
        model_actual = m.to_string();
        if m != a.model {
            return Err(AppError::new(
                ErrCat::IdentityMismatch,
                format!("requested={} response_model={m}", a.model),
            ));
        }
        content = v["message"]["content"].as_str().unwrap_or("").to_string();
        thinking_present = v["message"]["thinking"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false);
        done_reason = v["done_reason"].as_str().unwrap_or("stop").to_string();
    }

    Ok(ChatResult {
        native_calls: Vec::new(),
        server_tool_calls: 0,
        model_actual,
        content,
        thinking_present,
        done_reason,
        http_status: res.status,
        duration_ms: started.elapsed().as_millis(),
        chunk_count,
        raw_lines: res.lines,
    })
}

#[cfg(test)]
mod build2_tests {
    use super::*;

    #[test]
    fn openai_cut_is_read_from_the_token_count() {
        // oMLX labels an answer cut at max_tokens "stop"; the count decides.
        assert_eq!(openai_done_reason(Some("stop"), Some(2048), 2048), "length");
        assert_eq!(openai_done_reason(Some("stop"), Some(2047), 2048), "stop");
        assert_eq!(openai_done_reason(Some("length"), Some(10), 2048), "length");
        assert_eq!(openai_done_reason(None, None, 2048), "stop");
        // No limit set: the label stands.
        assert_eq!(openai_done_reason(Some("stop"), Some(99999), 0), "stop");
        assert_eq!(openai_done_reason(Some("tool_calls"), Some(5), 2048), "tool_calls");
    }

    #[test]
    fn openai_options_send_only_what_is_set() {
        assert_eq!(openai_options(2048, false, true), serde_json::json!({"seed": 7, "max_tokens": 2048, "chat_template_kwargs": {"enable_thinking": false}}));
        assert_eq!(openai_options(0, true, false), serde_json::json!({"seed": 7, "temperature": 0}));
        // Ollama options are unchanged.
        assert_eq!(model_options("ollama", 2048, false, false), chat_options(2048, false));
        assert_eq!(chat_path("ollama"), "/api/chat");
        assert_eq!(chat_path("openai"), "/v1/chat/completions");
    }

    #[test]
    fn header_values_with_line_breaks_are_refused_before_connecting() {
        let d = Instant::now() + Duration::from_secs(1);
        // Port 9 on a TEST-NET address is never contacted: the check runs first.
        let e = post_with_headers("http://192.0.2.1:9", "/x", "{}", d, None, &[("Authorization", "Bearer a\r\nX-Evil: 1".to_string())]);
        assert!(matches!(e, Err(ref err) if err.cat == ErrCat::ConfigInvalidValue), "{:?}", e.err().map(|x| x.detail));
    }
}

#[cfg(test)]
mod build2_server_tool_calls {
    #[test]
    fn server_tool_calls_become_native_markup() {
        let calls = serde_json::json!([
            {"id": "c1", "type": "function", "function": {"name": "fs.read", "arguments": "{\"path\": \"/a\"}"}},
            {"id": "c2", "type": "function", "function": {"name": "cmd.run", "arguments": {"argv": ["ls"]}}},
            {"id": "c3", "type": "function", "function": {"name": "fs.read", "arguments": "{bad"}},
            {"id": "c4", "type": "function", "function": {}}
        ]);
        let m = super::server_tool_calls_as_markup(&calls);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0], r#"<tool_call>{"arguments":{"path":"/a"},"name":"fs.read"}</tool_call>"#);
        assert!(m[1].contains(r#""argv":["ls"]"#));
        assert!(m[2].contains(r#""_arguments_not_json":"{bad""#), "{}", m[2]);
        assert!(super::server_tool_calls_as_markup(&serde_json::Value::Null).is_empty());
        let r = crate::tools::native_tool_calls(&m[0]);
        assert_eq!(r.len(), 1, "{r:?}");
    }
}
