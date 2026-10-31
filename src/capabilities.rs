//! Gate 06 corrected capability implementations.

use crate::authority::AuthorityContext;
use crate::gateway;
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct CapabilityOutcome {
    pub value: serde_json::Value,
    pub real_execution: bool,
    /// Build 1 receipt targets: what was read, from which root, and a digest of what was shown.
    pub targets: Vec<serde_json::Value>,
}

pub struct CapabilityError {
    pub code: String,
    pub detail: String,
    pub policy_rejection: bool,
    pub real_execution: bool,
}

fn policy(code: &str, detail: impl Into<String>) -> CapabilityError {
    CapabilityError {
        code: code.into(),
        detail: detail.into(),
        policy_rejection: true,
        real_execution: false,
    }
}

fn failure(code: &str, detail: impl Into<String>, real_execution: bool) -> CapabilityError {
    CapabilityError {
        code: code.into(),
        detail: detail.into(),
        policy_rejection: false,
        real_execution,
    }
}

fn root(ctx: &AuthorityContext) -> Result<&Path, CapabilityError> {
    ctx.sandbox_root
        .as_deref()
        .ok_or_else(|| policy("SANDBOX_ROOT_REQUIRED", "sandbox root not configured"))
}

fn relative_path(s: &str) -> Result<PathBuf, CapabilityError> {
    if s.is_empty() {
        return Err(policy("SANDBOX_POLICY", "path is empty"));
    }
    let p = Path::new(s);
    if p.is_absolute() {
        return Err(policy("SANDBOX_POLICY", "absolute path prohibited (outside the session sandbox)"));
    }
    if s == "." {
        return Ok(PathBuf::new()); // Build 3.2: "." is the sandbox root
    }
    for c in p.components() {
        match c {
            Component::Normal(_) => {}
            _ => {
                return Err(policy(
                    "SANDBOX_POLICY",
                    format!("bad path component: {c:?}"),
                ))
            }
        }
    }
    Ok(p.to_path_buf())
}

fn existing_path(ctx: &AuthorityContext, rel: &str) -> Result<PathBuf, CapabilityError> {
    let root = root(ctx)?;
    let joined = root.join(relative_path(rel)?);
    let target = std::fs::canonicalize(&joined)
        .map_err(|e| policy("SANDBOX_POLICY", format!("{}: {e}", joined.display())))?;
    if !target.starts_with(root) {
        return Err(policy("SANDBOX_ESCAPE", format!("{}", target.display())));
    }
    Ok(target)
}

fn read_path(ctx: &AuthorityContext, rel: &str) -> Result<PathBuf, CapabilityError> {
    let p = existing_path(ctx, rel)?;
    if !p.is_file() {
        return Err(policy("SANDBOX_POLICY", "read target not regular file"));
    }
    Ok(p)
}

fn write_path(ctx: &AuthorityContext, rel: &str) -> Result<PathBuf, CapabilityError> {
    let root = root(ctx)?;
    let joined = root.join(relative_path(rel)?);
    let parent = joined
        .parent()
        .ok_or_else(|| policy("SANDBOX_POLICY", "write target has no parent"))?;
    let parent_c = std::fs::canonicalize(parent)
        .map_err(|e| policy("SANDBOX_POLICY", format!("{}: {e}", parent.display())))?;
    if !parent_c.starts_with(root) {
        return Err(policy("SANDBOX_ESCAPE", format!("{}", parent_c.display())));
    }
    if joined.exists() || std::fs::symlink_metadata(&joined).is_ok() {
        let target = std::fs::canonicalize(&joined)
            .map_err(|e| policy("SANDBOX_POLICY", format!("{}: {e}", joined.display())))?;
        if !target.starts_with(root) {
            return Err(policy("SANDBOX_ESCAPE", format!("{}", target.display())));
        }
    }
    Ok(joined)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), CapabilityError> {
    let parent = path
        .parent()
        .ok_or_else(|| failure("FS_WRITE_FAILED", "no parent", false))?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = parent.join(format!(".hercules-tmp-{}-{nonce}", std::process::id()));
    let mut f = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| failure("FS_WRITE_FAILED", format!("{e}"), false))?;
    f.write_all(bytes)
        .map_err(|e| failure("FS_WRITE_FAILED", format!("{e}"), true))?;
    f.flush()
        .map_err(|e| failure("FS_WRITE_FAILED", format!("{e}"), true))?;
    f.sync_all()
        .map_err(|e| failure("FS_WRITE_FAILED", format!("{e}"), true))?;
    std::fs::rename(&tmp, path).map_err(|e| failure("FS_WRITE_FAILED", format!("{e}"), true))?;
    if let Ok(dirf) = std::fs::File::open(parent) {
        let _ = dirf.sync_all();
    }
    Ok(())
}

fn bounded_text(bytes: &[u8], max: usize) -> (String, bool, usize) {
    if bytes.len() <= max {
        (
            String::from_utf8_lossy(bytes).to_string(),
            false,
            bytes.len(),
        )
    } else {
        (
            String::from_utf8_lossy(&bytes[..max]).to_string(),
            true,
            bytes.len(),
        )
    }
}

fn fs_read(
    args: &serde_json::Value,
    ctx: &AuthorityContext,
) -> Result<CapabilityOutcome, CapabilityError> {
    let p = read_path(ctx, args["path"].as_str().unwrap_or(""))?;
    let b = std::fs::read(&p).map_err(|e| failure("FS_READ_FAILED", format!("{e}"), true))?;
    if b.len() > 65536 {
        return Err(failure("FS_READ_LIMIT", "file exceeds 65536 bytes", true));
    }
    let text = String::from_utf8_lossy(&b);
    let lines = if text.is_empty() {
        0
    } else {
        let nl = text.matches('\n').count();
        if text.ends_with('\n') { nl } else { nl + 1 }
    };
    Ok(CapabilityOutcome {
        value: serde_json::json!({"path":args["path"],"content":text,"bytes":b.len(),"lines":lines}),
        real_execution: true,
        targets: Vec::new(),
    })
}

fn fs_list(
    args: &serde_json::Value,
    ctx: &AuthorityContext,
) -> Result<CapabilityOutcome, CapabilityError> {
    let p = existing_path(ctx, args["path"].as_str().unwrap_or(""))?;
    if !p.is_dir() {
        return Err(policy("SANDBOX_POLICY", "list target not directory"));
    }
    let mut entries = Vec::new();
    for x in std::fs::read_dir(&p).map_err(|e| failure("FS_LIST_FAILED", format!("{e}"), true))? {
        entries.push(
            x.map_err(|e| failure("FS_LIST_FAILED", format!("{e}"), true))?
                .file_name()
                .to_string_lossy()
                .to_string(),
        );
        if entries.len() > 256 {
            break;
        }
    }
    entries.sort();
    let truncated = entries.len() > 256;
    entries.truncate(256);
    Ok(CapabilityOutcome {
        value: serde_json::json!({"path":args["path"],"entries":entries,"truncated":truncated}),
        real_execution: true,
        targets: Vec::new(),
    })
}

fn fs_stat(
    args: &serde_json::Value,
    ctx: &AuthorityContext,
) -> Result<CapabilityOutcome, CapabilityError> {
    let p = existing_path(ctx, args["path"].as_str().unwrap_or(""))?;
    let m = std::fs::metadata(&p).map_err(|e| failure("FS_STAT_FAILED", format!("{e}"), true))?;
    let kind = if m.is_file() {
        "file"
    } else if m.is_dir() {
        "directory"
    } else {
        "other"
    };
    Ok(CapabilityOutcome {
        value: serde_json::json!({"path":args["path"],"kind":kind,"bytes":m.len(),"readonly":m.permissions().readonly()}),
        real_execution: true,
        targets: Vec::new(),
    })
}

fn fs_write(
    args: &serde_json::Value,
    ctx: &AuthorityContext,
) -> Result<CapabilityOutcome, CapabilityError> {
    let p = write_path(ctx, args["path"].as_str().unwrap_or(""))?;
    let content = args["content"].as_str().unwrap_or("");
    atomic_write(&p, content.as_bytes())?;
    Ok(CapabilityOutcome {
        value: serde_json::json!({"path":args["path"],"bytes_written":content.len()}),
        real_execution: true,
        targets: Vec::new(),
    })
}

fn fs_replace(
    args: &serde_json::Value,
    ctx: &AuthorityContext,
) -> Result<CapabilityOutcome, CapabilityError> {
    let r = read_path(ctx, args["path"].as_str().unwrap_or(""))?;
    let w = write_path(ctx, args["path"].as_str().unwrap_or(""))?;
    let b = std::fs::read(&r).map_err(|e| failure("FS_REPLACE_FAILED", format!("{e}"), true))?;
    if b.len() > 65536 {
        return Err(failure("FS_REPLACE_LIMIT", "file too large", true));
    }
    let text =
        String::from_utf8(b).map_err(|_| failure("FS_REPLACE_UTF8", "target not UTF-8", true))?;
    let old = args["old"].as_str().unwrap_or("");
    let new = args["new"].as_str().unwrap_or("");
    if old.is_empty() {
        return Err(policy("FS_REPLACE_POLICY", "old must not be empty"));
    }
    let count = text.matches(old).count();
    if count != 1 {
        return Err(failure(
            "FS_REPLACE_MATCH_COUNT",
            format!("expected one match; found {count}"),
            true,
        ));
    }
    let out = text.replacen(old, new, 1);
    if out.len() > 65536 {
        return Err(failure("FS_REPLACE_LIMIT", "result too large", true));
    }
    atomic_write(&w, out.as_bytes())?;
    Ok(CapabilityOutcome {
        value: serde_json::json!({"path":args["path"],"replacements":1,"bytes_written":out.len()}),
        real_execution: true,
        targets: Vec::new(),
    })
}

fn kill_group(child: &mut Child) {
    let pgid = child.id() as i32;
    unsafe {
        let _ = libc::kill(-pgid, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn shell_exec(
    args: &serde_json::Value,
    ctx: &AuthorityContext,
) -> Result<CapabilityOutcome, CapabilityError> {
    let root = root(ctx)?;
    let program = args["program"]
        .as_str()
        .ok_or_else(|| policy("SHELL_POLICY", "program missing"))?;
    const ALLOWED: [&str; 4] = ["/bin/echo", "/usr/bin/printf", "/bin/pwd", "/bin/sleep"];
    if !ALLOWED.contains(&program) {
        return Err(policy(
            "SHELL_POLICY",
            format!("program not allowlisted: {program}"),
        ));
    }
    let argv: Vec<String> = args["args"]
        .as_array()
        .ok_or_else(|| policy("SHELL_POLICY", "args missing"))?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    let timeout_ms = args["timeout_ms"].as_u64().unwrap_or(1000);

    let mut cmd = Command::new(program);
    cmd.args(&argv)
        .current_dir(root)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd.process_group(0);

    let mut child = cmd
        .spawn()
        .map_err(|e| failure("SHELL_SPAWN_FAILED", format!("{e}"), false))?;
    let pgid = child.id();
    let start = Instant::now();

    loop {
        if gateway::CANCELLED.load(Ordering::SeqCst) {
            kill_group(&mut child);
            return Err(failure(
                "CAPABILITY_CANCELLED",
                format!("shell cancelled process_group={pgid}"),
                true,
            ));
        }

        match child.try_wait() {
            Ok(Some(status)) => {
                let mut out = Vec::new();
                let mut err = Vec::new();
                if let Some(mut s) = child.stdout.take() {
                    let _ = s.read_to_end(&mut out);
                }
                if let Some(mut s) = child.stderr.take() {
                    let _ = s.read_to_end(&mut err);
                }
                let (stdout, stdout_truncated, stdout_bytes) = bounded_text(&out, 8192);
                let (stderr, stderr_truncated, stderr_bytes) = bounded_text(&err, 8192);
                return Ok(CapabilityOutcome {
                    value: serde_json::json!({
                        "program":program,"args":argv,"cwd":root.display().to_string(),
                        "exit_code":status.code(),"success":status.success(),
                        "stdout":stdout,"stdout_bytes":stdout_bytes,"stdout_truncated":stdout_truncated,
                        "stderr":stderr,"stderr_bytes":stderr_bytes,"stderr_truncated":stderr_truncated,
                        "duration_ms":start.elapsed().as_millis() as u64,
                        "environment":"cleared","process_group":pgid
                    }),
                    real_execution: true,
                    targets: Vec::new(),
                });
            }
            Ok(None) => {}
            Err(e) => {
                kill_group(&mut child);
                return Err(failure(
                    "SHELL_WAIT_FAILED",
                    format!("process_group={pgid}: {e}"),
                    true,
                ));
            }
        }

        if start.elapsed() >= Duration::from_millis(timeout_ms) {
            kill_group(&mut child);
            return Err(failure(
                "CAPABILITY_TIMEOUT",
                format!("shell exceeded {timeout_ms} ms process_group={pgid}"),
                true,
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

impl From<crate::readers::ReadErr> for CapabilityError {
    fn from(e: crate::readers::ReadErr) -> Self {
        CapabilityError {
            code: e.code,
            detail: e.detail,
            policy_rejection: e.policy,
            real_execution: !e.policy,
        }
    }
}

/// Build 1 fs.read: roots or sandbox, optional line window, JSON-size-bounded content.
fn fs_read_v2(args: &serde_json::Value, ctx: &AuthorityContext) -> Result<CapabilityOutcome, CapabilityError> {
    use crate::readers;
    let raw = args["path"].as_str().unwrap_or("");
    let (target, bytes) = readers::read_bytes(ctx, raw)?;
    let text = String::from_utf8_lossy(&bytes);
    let start = args.get("start_line").and_then(serde_json::Value::as_u64).unwrap_or(1) as usize;
    let max = args.get("max_lines").and_then(serde_json::Value::as_u64).map(|v| v as usize);
    // Each shown line is rendered with a line-number prefix (tools::render_observation).
    let w = readers::window_lines(&text, start, max, readers::content_budget(), 9);
    let digest = crate::audit::sha256_text(&w.content);
    let mut t = target.json("file");
    t["shown_sha256"] = serde_json::json!(digest);
    t["shown_lines"] = serde_json::json!([w.start_line, w.end_line]);
    Ok(CapabilityOutcome {
        value: serde_json::json!({
            "path": raw, "root": target.root, "content": w.content, "bytes": bytes.len(),
            "lines": w.total_lines, "start_line": w.start_line, "end_line": w.end_line,
            "truncated": w.truncated, "next_start_line": w.next_start_line
        }),
        real_execution: true,
        targets: vec![t],
    })
}

fn fs_list_v2(args: &serde_json::Value, ctx: &AuthorityContext) -> Result<CapabilityOutcome, CapabilityError> {
    let raw = args["path"].as_str().unwrap_or("");
    let sort = args.get("sort").and_then(serde_json::Value::as_str).unwrap_or("name");
    let limit = args.get("limit").and_then(serde_json::Value::as_u64).unwrap_or(256) as usize;
    let l = crate::readers::list(ctx, raw, sort, limit, true)?;
    let entries: Vec<serde_json::Value> = l.entries.iter().map(|e| e.json()).collect();
    let digest = crate::audit::sha256_text(&serde_json::Value::Array(entries.clone()).to_string());
    let mut t = l.target.json("directory");
    t["shown_sha256"] = serde_json::json!(digest);
    Ok(CapabilityOutcome {
        value: serde_json::json!({
            "path": raw, "root": l.target.root, "entries": entries, "total": l.total,
            "truncated": l.truncated, "denied_omitted": l.denied_omitted, "sort": sort
        }),
        real_execution: true,
        targets: vec![t],
    })
}

fn fs_stat_v2(args: &serde_json::Value, ctx: &AuthorityContext) -> Result<CapabilityOutcome, CapabilityError> {
    let raw = args["path"].as_str().unwrap_or("");
    let (target, e) = crate::readers::stat(ctx, raw)?;
    let value = serde_json::json!({
        "path": raw, "root": target.root, "kind": e.kind, "bytes": e.size,
        "mode": e.mode, "owner": e.owner, "mtime": e.mtime
    });
    let mut t = target.json("stat");
    t["shown_sha256"] = serde_json::json!(crate::audit::sha256_text(&value.to_string()));
    Ok(CapabilityOutcome { value, real_execution: true, targets: vec![t] })
}

fn proposal_write(tool: &str, args: &serde_json::Value, ctx: &AuthorityContext) -> Result<CapabilityOutcome, CapabilityError> {
    let Some(p) = &ctx.proposal else {
        return Err(policy("PROHIBITED_CAPABILITY", "write tools need write roots (--write-roots)"));
    };
    let path = args["path"].as_str().unwrap_or("");
    let r = if tool == "fs.write" {
        p.write(&ctx.roots, path, args["content"].as_str().unwrap_or(""))
    } else {
        p.replace(&ctx.roots, path, args["old"].as_str().unwrap_or(""), args["new"].as_str().unwrap_or(""))
    };
    match r {
        Ok(value) => {
            let key = crate::proposal::Proposal::key_for(path).unwrap_or_default();
            let t = crate::proposal::Proposal::target_json(&value, &key);
            Ok(CapabilityOutcome { value, real_execution: true, targets: vec![t] })
        }
        Err(e) if e.policy => Err(policy(e.code, e.detail)),
        Err(e) => Err(failure(e.code, e.detail, true)),
    }
}

pub fn dispatch(
    tool: &str,
    args: &serde_json::Value,
    ctx: &AuthorityContext,
) -> Result<CapabilityOutcome, CapabilityError> {
    if crate::features::build1() {
        match tool {
            "fs.read" => return fs_read_v2(args, ctx),
            "fs.list" => return fs_list_v2(args, ctx),
            "fs.stat" => return fs_stat_v2(args, ctx),
            "cmd.run" => return crate::cmd::run(args, ctx),
            // Gate 10: the write lane. Writes only ever reach the proposal overlay.
            "fs.write" | "fs.replace" => return proposal_write(tool, args, ctx),
            "fs.patch" | "fs.remove" | "shell.exec" => return Err(policy("PROHIBITED_CAPABILITY", format!("{tool} is not available under config v2"))),
            _ => {}
        }
    }
    match tool {
        "fs.read" => fs_read(args, ctx),
        "fs.list" => fs_list(args, ctx),
        "fs.stat" => fs_stat(args, ctx),
        "fs.write" => fs_write(args, ctx),
        "fs.patch" | "fs.replace" => fs_replace(args, ctx),
        "shell.exec" => shell_exec(args, ctx),
        "fs.remove" => Err(policy(
            "PROHIBITED_CAPABILITY",
            "fs.remove must never dispatch",
        )),
        _ => Err(policy(
            "CAPABILITY_UNKNOWN",
            format!("no implementation for {tool}"),
        )),
    }
}
