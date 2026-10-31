//! Gate 06 corrected authority broker.
//! Approval-required actions bind operator-controlled material to
//! session_id + request_id + capability + normalized args + expiry + one-use.

use serde_json::Value;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug)]
struct ApprovalGrant {
    approval_id: String,
    session_id: String,
    request_id: String,
    capability: String,
    normalized_args: Value,
    expires_unix_ms: u64,
}

#[derive(Clone, Debug)]
pub struct AuthorityContext {
    pub sandbox_root: Option<PathBuf>,
    /// Build 3.2: the spellings of the sandbox root an absolute path may start with (canonical, as given,
    /// and macOS /private aliases). Matched as text only: no filesystem lookup on a model-chosen path.
    pub sandbox_aliases: Vec<PathBuf>,
    /// Build 1: granted read-only roots (empty unless config v2 + --roots).
    pub roots: crate::roots::RootPolicy,
    /// Build 1: cmd.run policy (disabled unless config v2).
    pub cmd: crate::cmd::CmdPolicy,
    /// Gate 10: the run's proposal overlay, when it has write roots. fs.write / fs.replace land there only.
    pub proposal: Option<Arc<crate::proposal::Proposal>>,
    session_id: Option<String>,
    approvals: Vec<ApprovalGrant>,
    approval_state_dir: Option<PathBuf>,
    used_in_process: Arc<Mutex<HashSet<String>>>,
}

#[derive(Clone, Debug)]
pub struct AuthorityDecision {
    pub level: &'static str,
    pub allowed: bool,
    pub code: Option<String>,
    pub detail: String,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn valid_id(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn exact_keys(o: &serde_json::Map<String, Value>, keys: &[&str], what: &str) -> Result<(), String> {
    for k in keys {
        if !o.contains_key(*k) {
            return Err(format!("{what} missing field: {k}"));
        }
    }
    for k in o.keys() {
        if !keys.contains(&k.as_str()) {
            return Err(format!("{what} unexpected field: {k}"));
        }
    }
    Ok(())
}

impl AuthorityContext {
    pub fn new(
        root: Option<&str>,
        approval_file: Option<&str>,
        session_id: Option<&str>,
    ) -> Result<Self, String> {
        let sandbox_root = match root {
            None => None,
            Some(p) => {
                let c = fs::canonicalize(p)
                    .map_err(|e| format!("sandbox root canonicalize failed: {p}: {e}"))?;
                if !c.is_dir() {
                    return Err(format!("sandbox root is not a directory: {}", c.display()));
                }
                Some(c)
            }
        };

        if let Some(sid) = session_id {
            if !valid_id(sid, 96) {
                return Err(format!("invalid authority session_id: {sid}"));
            }
        }

        let mut approvals = Vec::new();
        let mut approval_state_dir = None;
        let mut session_owned = session_id.map(ToString::to_string);

        if let Some(path) = approval_file {
            let sid = session_id.ok_or_else(|| {
                "--approval-file requires an explicit --session-id for exact binding".to_string()
            })?;
            let canonical = fs::canonicalize(path)
                .map_err(|e| format!("approval file canonicalize failed: {path}: {e}"))?;
            if !canonical.is_file() {
                return Err(format!(
                    "approval file is not regular: {}",
                    canonical.display()
                ));
            }
            if let Some(root) = &sandbox_root {
                if canonical.starts_with(root) {
                    return Err("approval file must be outside sandbox".into());
                }
            }

            let raw = fs::read_to_string(&canonical)
                .map_err(|e| format!("approval file read failed: {e}"))?;
            let top: Value =
                serde_json::from_str(&raw).map_err(|e| format!("approval JSON malformed: {e}"))?;
            let obj = top
                .as_object()
                .ok_or_else(|| "approval document must be object".to_string())?;
            exact_keys(obj, &["schema", "approvals"], "approval document")?;
            if obj["schema"].as_str() != Some("hercules_gate06_approval_v1") {
                return Err("approval document schema mismatch".into());
            }
            let arr = obj["approvals"]
                .as_array()
                .ok_or_else(|| "approvals must be array".to_string())?;

            let mut ids = HashSet::new();
            for item in arr {
                let g = item
                    .as_object()
                    .ok_or_else(|| "approval grant must be object".to_string())?;
                exact_keys(
                    g,
                    &[
                        "approval_id",
                        "session_id",
                        "request_id",
                        "capability",
                        "normalized_args",
                        "expires_unix_ms",
                        "one_use",
                    ],
                    "approval grant",
                )?;
                let approval_id = g["approval_id"]
                    .as_str()
                    .ok_or_else(|| "approval_id must be string".to_string())?
                    .to_string();
                let grant_session = g["session_id"]
                    .as_str()
                    .ok_or_else(|| "session_id must be string".to_string())?
                    .to_string();
                let request_id = g["request_id"]
                    .as_str()
                    .ok_or_else(|| "request_id must be string".to_string())?
                    .to_string();
                let capability = g["capability"]
                    .as_str()
                    .ok_or_else(|| "capability must be string".to_string())?
                    .to_string();
                let normalized_args = g["normalized_args"].clone();
                let expires_unix_ms = g["expires_unix_ms"]
                    .as_u64()
                    .ok_or_else(|| "expires_unix_ms must be integer".to_string())?;
                if g["one_use"].as_bool() != Some(true) {
                    return Err("one_use must be true".into());
                }
                if !valid_id(&approval_id, 96)
                    || !valid_id(&grant_session, 96)
                    || !valid_id(&request_id, 64)
                {
                    return Err("approval identifier invalid".into());
                }
                if grant_session != sid {
                    return Err(format!(
                        "approval session_id {grant_session} does not match active {sid}"
                    ));
                }
                if !normalized_args.is_object() {
                    return Err("normalized_args must be object".into());
                }
                if !ids.insert(approval_id.clone()) {
                    return Err(format!("duplicate approval_id: {approval_id}"));
                }
                approvals.push(ApprovalGrant {
                    approval_id,
                    session_id: grant_session,
                    request_id,
                    capability,
                    normalized_args,
                    expires_unix_ms,
                });
            }

            let state_name = format!(
                "{}.used",
                canonical
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("approval")
            );
            approval_state_dir = Some(canonical.with_file_name(state_name));
            session_owned = Some(sid.to_string());
        }

        let sandbox_aliases = match (root, &sandbox_root) {
            (Some(given), Some(c)) => root_aliases(given, c),
            _ => Vec::new(),
        };
        Ok(Self {
            roots: crate::roots::RootPolicy::default(),
            cmd: crate::cmd::CmdPolicy::disabled(),
            proposal: None,
            sandbox_root,
            sandbox_aliases,
            session_id: session_owned,
            approvals,
            approval_state_dir,
            used_in_process: Arc::new(Mutex::new(HashSet::new())),
        })
    }

    pub fn summary_json(&self) -> Value {
        let mut ids: Vec<String> = self
            .approvals
            .iter()
            .map(|g| g.approval_id.clone())
            .collect();
        ids.sort();
        let mut v = serde_json::json!({
            "sandbox_root": self.sandbox_root.as_ref().map(|p| p.display().to_string()),
            "session_id": self.session_id,
            "approval_ids": ids,
            "approval_binding": "session_id+request_id+capability+normalized_args+expiry+one_use",
            "legacy_request_id_only_approval": false,
            "default": "deny",
            "levels": ["automatic", "sandbox-only", "approval-required", "prohibited"]
        });
        if crate::features::build1() {
            v["levels"] = serde_json::json!(["automatic", "sandbox-only", "root-read", "approval-required", "prohibited"]);
            v["read_roots"] = self.roots.summary_json();
            v["cmd"] = self.cmd.summary_json();
        }
        v
    }

    fn consume_matching_approval(
        &self,
        tool: &str,
        args: &Value,
        request_id: &str,
    ) -> Result<String, (String, String)> {
        let sid = self.session_id.as_deref().ok_or_else(|| {
            (
                "APPROVAL_REQUIRED".to_string(),
                "no session-bound approval context".to_string(),
            )
        })?;

        let candidates: Vec<&ApprovalGrant> = self
            .approvals
            .iter()
            .filter(|g| g.request_id == request_id)
            .collect();
        if candidates.is_empty() {
            return Err((
                "APPROVAL_REQUIRED".into(),
                format!("request_id {request_id} has no grant"),
            ));
        }

        let grant = candidates
            .iter()
            .copied()
            .find(|g| g.session_id == sid && g.capability == tool && g.normalized_args == *args)
            .ok_or_else(|| {
                (
                    "APPROVAL_MISMATCH".into(),
                    "session/capability/normalized_args mismatch".into(),
                )
            })?;

        if now_ms() > grant.expires_unix_ms {
            return Err((
                "APPROVAL_EXPIRED".into(),
                format!("approval_id {} expired", grant.approval_id),
            ));
        }

        {
            let used = self.used_in_process.lock().map_err(|_| {
                (
                    "APPROVAL_STATE_ERROR".into(),
                    "approval lock poisoned".into(),
                )
            })?;
            if used.contains(&grant.approval_id) {
                return Err((
                    "APPROVAL_REUSED".into(),
                    format!("approval_id {} already consumed", grant.approval_id),
                ));
            }
        }

        let state_dir = self.approval_state_dir.as_ref().ok_or_else(|| {
            (
                "APPROVAL_STATE_ERROR".into(),
                "approval state unavailable".into(),
            )
        })?;
        fs::create_dir_all(state_dir).map_err(|e| {
            (
                "APPROVAL_STATE_ERROR".into(),
                format!("approval state create failed: {e}"),
            )
        })?;
        let marker = state_dir.join(&grant.approval_id);
        let mut f = match OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&marker)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err((
                    "APPROVAL_REUSED".into(),
                    format!("approval_id {} already consumed", grant.approval_id),
                ))
            }
            Err(e) => {
                return Err((
                    "APPROVAL_STATE_ERROR".into(),
                    format!("consume marker failed: {e}"),
                ))
            }
        };
        writeln!(
            f,
            "{}",
            serde_json::json!({
                "approval_id": grant.approval_id,
                "session_id": sid,
                "request_id": request_id,
                "capability": tool,
                "normalized_args": args,
                "consumed_unix_ms": now_ms()
            })
        )
        .map_err(|e| {
            (
                "APPROVAL_STATE_ERROR".into(),
                format!("marker write failed: {e}"),
            )
        })?;
        f.sync_all().map_err(|e| {
            (
                "APPROVAL_STATE_ERROR".into(),
                format!("marker sync failed: {e}"),
            )
        })?;

        self.used_in_process
            .lock()
            .map_err(|_| {
                (
                    "APPROVAL_STATE_ERROR".into(),
                    "approval lock poisoned".into(),
                )
            })?
            .insert(grant.approval_id.clone());

        Ok(grant.approval_id.clone())
    }
}

fn deny(level: &'static str, code: &str, detail: impl Into<String>) -> AuthorityDecision {
    AuthorityDecision {
        level,
        allowed: false,
        code: Some(code.to_string()),
        detail: detail.into(),
    }
}

fn allow(level: &'static str, detail: impl Into<String>) -> AuthorityDecision {
    AuthorityDecision {
        level,
        allowed: true,
        code: None,
        detail: detail.into(),
    }
}

/// Build 3.2: the sandbox-relative form of a path the model gave, when it names a place inside the session
/// sandbox in another spelling. Returns None when nothing needs rewriting or the path is outside the sandbox
/// (then the caller's usual checks refuse it, exactly as before).
///   - an absolute path that starts with one of the root's spellings (sandbox_aliases) -> relative to the root;
///   - `.` components are dropped (`./a`, `a/./b`); `.` alone, or the root itself, is the sandbox root (`.`).
/// `..` is never rewritten, and the result is still checked by the usual canonicalize + starts_with(root) test,
/// so this cannot widen what a session can read: it only accepts other spellings of the same in-sandbox paths,
/// and the sandbox policy (not a granted root's policy) then applies, as for any relative path.
pub fn sandbox_relative_form(ctx: &AuthorityContext, raw: &str) -> Option<String> {
    ctx.sandbox_root.as_deref()?;
    let p = Path::new(raw);
    if raw.is_empty() || p.components().any(|c| matches!(c, Component::ParentDir | Component::Prefix(_))) {
        return None;
    }
    let lexical: PathBuf = p.components().filter(|c| !matches!(c, Component::CurDir)).collect();
    let rel: PathBuf = if p.is_absolute() {
        // Text only (review 2026-10-08): never canonicalize a model-chosen absolute path here, so an
        // automount, network or dead-mount path is not touched before the policy refuses it.
        ctx.sandbox_aliases.iter().find_map(|a| lexical.strip_prefix(a).ok())?.to_path_buf()
    } else if p.components().any(|c| matches!(c, Component::CurDir)) {
        lexical
    } else {
        return None;
    };
    let out = if rel.as_os_str().is_empty() { ".".to_string() } else { rel.to_str()?.to_string() };
    if out == raw { None } else { Some(out) }
}

/// The spellings of a sandbox root: canonical, as given (made absolute, "." dropped), and the macOS
/// /private aliases (/var, /tmp, /etc are symlinks into /private).
fn root_aliases(given: &str, canonical: &Path) -> Vec<PathBuf> {
    let mut out = vec![canonical.to_path_buf()];
    let g = Path::new(given);
    if g.is_absolute() && !g.components().any(|c| matches!(c, Component::ParentDir)) {
        out.push(g.components().filter(|c| !matches!(c, Component::CurDir)).collect());
    }
    for base in out.clone() {
        for top in ["var", "tmp", "etc"] {
            let private = Path::new("/private").join(top);
            let short = Path::new("/").join(top);
            if let Ok(r) = base.strip_prefix(&private) {
                out.push(short.join(r));
            } else if let Ok(r) = base.strip_prefix(&short) {
                out.push(private.join(r));
            }
        }
    }
    // Keep only spellings that really are this root on this machine (review 2026-10-08: on Linux a text-only
    // /private/tmp alias did not exist). This lookup runs once, at startup, on operator-chosen paths.
    let mut kept: Vec<PathBuf> = Vec::new();
    for a in out {
        if !kept.contains(&a) && fs::canonicalize(&a).map(|c| c == canonical).unwrap_or(false) {
            kept.push(a);
        }
    }
    if !kept.iter().any(|a| a == canonical) {
        kept.insert(0, canonical.to_path_buf());
    }
    kept
}

/// Build 3.2: rewrite the path argument of the fs.* tools to its sandbox-relative form (see above). Returns the
/// new args and, when something changed, (from, to) for the transcript.
pub fn relativize_tool_args(tool: &str, args: &Value, ctx: &AuthorityContext) -> (Value, Option<(String, String)>) {
    if !matches!(tool, "fs.read" | "fs.list" | "fs.stat" | "fs.write" | "fs.patch" | "fs.replace" | "fs.remove") {
        return (args.clone(), None);
    }
    let Some(raw) = args["path"].as_str() else { return (args.clone(), None) };
    match sandbox_relative_form(ctx, raw) {
        Some(rel) => {
            let mut a = args.clone();
            a["path"] = Value::String(rel.clone());
            (a, Some((raw.to_string(), rel)))
        }
        None => (args.clone(), None),
    }
}

fn relative_path(s: &str) -> Result<PathBuf, String> {
    if s.is_empty() {
        return Err("path is empty".into());
    }
    let p = Path::new(s);
    if p.is_absolute() {
        return Err("absolute paths prohibited (outside the session sandbox)".into());
    }
    if s == "." {
        return Ok(PathBuf::new()); // Build 3.2: "." is the sandbox root
    }
    for c in p.components() {
        match c {
            Component::Normal(_) => {}
            _ => return Err(format!("non-normal component prohibited: {c:?}")),
        }
    }
    Ok(p.to_path_buf())
}

fn root(ctx: &AuthorityContext) -> Result<&Path, String> {
    ctx.sandbox_root
        .as_deref()
        .ok_or_else(|| "sandbox root required".to_string())
}

fn preflight_existing(
    ctx: &AuthorityContext,
    rel: &str,
    file: bool,
    dir: bool,
) -> Result<(), String> {
    let root = root(ctx)?;
    let joined = root.join(relative_path(rel)?);
    let target = fs::canonicalize(&joined)
        .map_err(|e| format!("canonicalize failed {}: {e}", joined.display()))?;
    if !target.starts_with(root) {
        return Err(format!("sandbox escape: {}", target.display()));
    }
    if file && !target.is_file() {
        return Err("target is not regular file".into());
    }
    if dir && !target.is_dir() {
        return Err("target is not directory".into());
    }
    Ok(())
}

fn preflight_write(ctx: &AuthorityContext, rel: &str) -> Result<(), String> {
    let root = root(ctx)?;
    let joined = root.join(relative_path(rel)?);
    let parent = joined
        .parent()
        .ok_or_else(|| "write target has no parent".to_string())?;
    let parent_c = fs::canonicalize(parent)
        .map_err(|e| format!("parent canonicalize failed {}: {e}", parent.display()))?;
    if !parent_c.starts_with(root) {
        return Err(format!("sandbox parent escape: {}", parent_c.display()));
    }
    if joined.exists() || fs::symlink_metadata(&joined).is_ok() {
        let target = fs::canonicalize(&joined)
            .map_err(|e| format!("target canonicalize failed {}: {e}", joined.display()))?;
        if !target.starts_with(root) {
            return Err(format!("sandbox target escape: {}", target.display()));
        }
    }
    Ok(())
}

fn preflight_shell(ctx: &AuthorityContext, args: &Value) -> Result<(), String> {
    let _ = root(ctx)?;
    let program = args["program"]
        .as_str()
        .ok_or_else(|| "program missing".to_string())?;
    const ALLOWED: [&str; 4] = ["/bin/echo", "/usr/bin/printf", "/bin/pwd", "/bin/sleep"];
    if !ALLOWED.contains(&program) {
        return Err(format!("program not allowlisted: {program}"));
    }
    Ok(())
}

/// Build 1 decision for fs.read / fs.list / fs.stat on an absolute path inside granted roots.
fn decide_root_read(path: &str, ctx: &AuthorityContext) -> AuthorityDecision {
    // Gate 10: a file the model wrote in this run is read from its proposal, even one that exists only there
    // (only paths inside a write root and off the deny list ever reach the proposal).
    if ctx.proposal.as_ref().is_some_and(|p| p.has(path)) {
        return allow("proposal-read", "a file this run proposed; read from the proposal");
    }
    match ctx.roots.resolve(path) {
        Ok(r) => allow("root-read", format!("inside granted read-only root {}", r.root)),
        Err(e) => deny("root-read", e.code, e.detail),
    }
}

pub fn decide(
    tool: &str,
    args: &Value,
    request_id: &str,
    ctx: &AuthorityContext,
) -> AuthorityDecision {
    if tool.starts_with("test.") {
        return allow("automatic", "Gate 05 inert capability");
    }

    if crate::features::build1() {
        // Build 3: the answer-contract tools read only this session's answer and its staged approved
        // copies, and write nothing (answer.rs).
        if matches!(tool, "answer.submit" | "evidence.check") {
            return allow("session-local", "works only on this session's answer and its staged approved copies");
        }
        // Gate 10: in a run with write roots, fs.write / fs.replace go into the proposal overlay (nothing outside
        // it changes; the operator applies a reviewed changeset later), so they need no per-call approval.
        // Everywhere else config v2 stays read-only, as decided 2026-10-03; fs.patch is not part of the lane.
        if matches!(tool, "fs.write" | "fs.replace") {
            if let Some(p) = &ctx.proposal {
                let path = args["path"].as_str().unwrap_or("");
                return if p.is_write_target(path) {
                    allow("propose", "into the proposal for a write root; the root file is unchanged until the operator applies the changeset")
                } else {
                    deny("propose", "WRITE_ROOT_POLICY", format!("{path} is outside the write roots of this run (absolute path, existing parent directory)"))
                };
            }
        }
        if matches!(tool, "fs.write" | "fs.patch" | "fs.replace") {
            return deny("prohibited", "PROHIBITED_CAPABILITY", "write tools are not available under config v2 (read-only lane); a run with --write-roots offers fs.write and fs.replace");
        }
        let path = args["path"].as_str().unwrap_or("");
        if matches!(tool, "fs.read" | "fs.list" | "fs.stat")
            && Path::new(path).is_absolute()
            && !ctx.roots.is_empty()
        {
            return decide_root_read(path, ctx);
        }
        if tool == "cmd.run" {
            return match crate::cmd::authorize(args, ctx) {
                Ok(detail) => allow("root-read", detail),
                Err((code, detail)) => deny("root-read", &code, detail),
            };
        }
    }

    match tool {
        "fs.read" => {
            match preflight_existing(ctx, args["path"].as_str().unwrap_or(""), true, false) {
                Ok(()) => allow("sandbox-only", "read target inside sandbox"),
                Err(e) => deny("sandbox-only", "SANDBOX_POLICY", e),
            }
        }
        "fs.list" => {
            match preflight_existing(ctx, args["path"].as_str().unwrap_or(""), false, true) {
                Ok(()) => allow("sandbox-only", "list target inside sandbox"),
                Err(e) => deny("sandbox-only", "SANDBOX_POLICY", e),
            }
        }
        "fs.stat" => {
            match preflight_existing(ctx, args["path"].as_str().unwrap_or(""), false, false) {
                Ok(()) => allow("sandbox-only", "stat target inside sandbox"),
                Err(e) => deny("sandbox-only", "SANDBOX_POLICY", e),
            }
        }
        "fs.write" | "fs.patch" | "fs.replace" => {
            match preflight_write(ctx, args["path"].as_str().unwrap_or("")) {
                Ok(()) => allow("sandbox-only", "write/patch target inside sandbox"),
                Err(e) => deny("sandbox-only", "SANDBOX_POLICY", e),
            }
        }
        "shell.exec" => {
            if let Err(e) = preflight_shell(ctx, args) {
                return deny("approval-required", "SHELL_POLICY", e);
            }
            match ctx.consume_matching_approval(tool, args, request_id) {
                Ok(id) => allow(
                    "approval-required",
                    format!("one-use approval consumed: {id}"),
                ),
                Err((code, detail)) => deny("approval-required", &code, detail),
            }
        }
        "fs.remove" => deny(
            "prohibited",
            "PROHIBITED_CAPABILITY",
            "file removal prohibited",
        ),
        _ => deny(
            "prohibited",
            "AUTHORITY_UNKNOWN_TOOL",
            format!("no policy for {tool}"),
        ),
    }
}

#[cfg(test)]
mod b32_tests {
    use super::*;

    #[test]
    fn root_aliases_keep_only_real_spellings() {
        let d = std::env::temp_dir().join(format!("b32a-{}", std::process::id()));
        std::fs::create_dir_all(d.join("home")).unwrap();
        let c = fs::canonicalize(d.join("home")).unwrap();
        let a = root_aliases(d.join("home").to_str().unwrap(), &c);
        assert!(a.contains(&c));
        assert!(a.iter().all(|x| fs::canonicalize(x).unwrap() == c), "every alias is really this root: {a:?}");
        let link = d.join("link");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(d.join("home"), &link).unwrap();
        let a = root_aliases(link.to_str().unwrap(), &c);
        assert!(a.contains(&link), "the operator's symlinked spelling is kept");
        // A relative --sandbox-root spelling adds no alias of its own. (On macOS the canonical root under
        // /private/var still gets its real /var spelling, so the list need not be just the canonical path.)
        let a = root_aliases("./home", &c);
        assert!(a.contains(&c) && a.iter().all(|x| x.is_absolute() && fs::canonicalize(x).unwrap() == c),
                "a relative spelling is not an alias: {a:?}");
        if Path::new("/private/tmp").is_dir() {
            // macOS: /tmp -> /private/tmp
            let t = Path::new("/tmp").join(format!("b32m-{}", std::process::id()));
            std::fs::create_dir_all(&t).unwrap();
            let tc = fs::canonicalize(&t).unwrap();
            let a = root_aliases(t.to_str().unwrap(), &tc);
            assert!(a.contains(&t) && a.contains(&tc));
        } else {
            let a = root_aliases("/tmp/x-not-there", Path::new("/tmp/x-not-there"));
            assert!(!a.iter().any(|x| x.starts_with("/private")), "no made-up /private alias on Linux: {a:?}");
        }
    }
}
