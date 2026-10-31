//! Gate 09 native evidence/audit support.
//! Pure-Rust SHA-256, atomic evidence writes, sensitive-value redaction,
//! and machine-readable transcript reconstruction.

use serde_json::{json, Map, Value};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::sha256::{hex, sha256_inner};

pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex(&sha256_inner(bytes))
}

pub fn sha256_text(text: &str) -> String {
    sha256_bytes(text.as_bytes())
}

pub fn sha256_file(path: impl AsRef<Path>) -> Result<String, String> {
    let p = path.as_ref();
    let b = fs::read(p).map_err(|e| format!("sha256 read failed {}: {e}", p.display()))?;
    Ok(sha256_bytes(&b))
}

pub fn sha256_source_tree(root: &str) -> Result<String, String> {
    crate::sha256::source_tree_digest(Path::new(root))
}

fn sensitive_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    matches!(
        k.as_str(),
        "api_key"
            | "apikey"
            | "authorization"
            | "password"
            | "passwd"
            | "secret"
            | "token"
            | "private_key"
            | "credential"
            | "cookie"
    ) || k.ends_with("_secret")
        || k.ends_with("_token")
        || k.ends_with("_password")
        || k.ends_with("_api_key")
        || k.ends_with("_credential")
}

fn sensitive_string(s: &str) -> bool {
    let x = s.to_ascii_lowercase();
    x.contains("bearer ")
        || x.contains("-----begin private key-----")
        || x.contains("hercules_secret_")
}

pub fn redact_value(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, val) in m {
                if sensitive_key(k) {
                    out.insert(
                        k.clone(),
                        json!({
                            "protected_field_present": true,
                            "redacted": true,
                            "value": "[REDACTED]"
                        }),
                    );
                } else {
                    out.insert(k.clone(), redact_value(val));
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(redact_value).collect()),
        Value::String(s) if sensitive_string(s) => json!({
            "protected_string_present": true,
            "redacted": true,
            "value": "[REDACTED]"
        }),
        _ => v.clone(),
    }
}

/// A new temporary file next to `path`, for an atomic replace. The name carries 64 random bits, the file is
/// created exclusively (`O_EXCL`), and a symlink is never followed, so nothing that already sits in the
/// directory (a planted file or symlink) can be opened or truncated through it.
pub fn create_temp_beside(path: &Path) -> Result<(fs::File, std::path::PathBuf), String> {
    use std::os::unix::fs::OpenOptionsExt;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let name = path
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| format!("invalid path {}", path.display()))?;
    let mut last_err = String::new();
    for _ in 0..8 {
        let tmp = parent.join(format!(".{name}.tmp-{}-{:016x}", std::process::id(), random_u64()?));
        // 0600: evidence, manifests, final answers and checkpoints are private to the operator.
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)
        {
            Ok(f) => return Ok((f, tmp)),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => last_err = e.to_string(),
            Err(e) => return Err(format!("temp open failed {}: {e}", tmp.display())),
        }
    }
    Err(format!("temp open failed next to {}: {last_err}", path.display()))
}

pub(crate) fn random_u64() -> Result<u64, String> {
    use std::io::Read;
    let mut b = [0u8; 8];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("/dev/urandom: {e}"))?;
    Ok(u64::from_le_bytes(b))
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let (mut f, tmp) = create_temp_beside(path).map_err(|e| format!("evidence {e}"))?;
    if let Err(e) = f.write_all(bytes).and_then(|_| f.flush()).and_then(|_| f.sync_all()) {
        let _ = fs::remove_file(&tmp);
        return Err(format!("evidence write failed {}: {e}", tmp.display()));
    }
    fs::rename(&tmp, path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        format!(
            "evidence atomic rename failed {} -> {}: {e}",
            tmp.display(),
            path.display()
        )
    })?;
    if let Ok(dirf) = fs::File::open(parent) {
        let _ = dirf.sync_all();
    }
    Ok(())
}

pub fn write_json_atomic(path: &str, v: &Value) -> Result<(), String> {
    let clean = redact_value(v);
    let mut bytes =
        serde_json::to_vec_pretty(&clean).map_err(|e| format!("evidence serialize failed: {e}"))?;
    bytes.push(b'\n');
    atomic_write(Path::new(path), &bytes)
}

pub fn write_text_atomic(path: &str, text: &str) -> Result<(), String> {
    atomic_write(Path::new(path), text.as_bytes())
}

pub fn summarize_transcript(path: &str) -> Result<Value, String> {
    let raw =
        fs::read_to_string(path).map_err(|e| format!("transcript read failed {path}: {e}"))?;

    let mut events = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line)
            .map_err(|e| format!("transcript line {} malformed: {e}", idx + 1))?;
        events.push(v);
    }

    let mut expected = 1u64;
    let mut sequence_ok = true;
    let mut first_ts: Option<u64> = None;
    let mut last_ts: Option<u64> = None;
    let mut sid: Option<String> = None;
    let mut session_id_consistent = true;
    let mut model_actual = Value::Null;
    let mut tool_requests = Vec::new();
    let mut authority_decisions = Vec::new();
    let mut tool_results = Vec::new();
    let mut errors = Vec::new();
    let mut retries = Vec::new();
    let mut recovery_events = Vec::new();
    let mut router_decisions = Vec::new();
    let mut escalation_events = Vec::new();
    let mut final_answer = Value::Null;

    for v in &events {
        let seq = v.get("seq").and_then(Value::as_u64).unwrap_or(0);
        if seq != expected {
            sequence_ok = false;
        }
        expected = seq.saturating_add(1);

        if let Some(ts) = v.get("ts_ms").and_then(Value::as_u64) {
            first_ts.get_or_insert(ts);
            last_ts = Some(ts);
        }

        match v.get("session_id").and_then(Value::as_str) {
            Some(s) => {
                if let Some(existing) = &sid {
                    if existing != s {
                        session_id_consistent = false;
                    }
                } else {
                    sid = Some(s.to_string());
                }
            }
            None => session_id_consistent = false,
        }

        let event = v.get("event").and_then(Value::as_str).unwrap_or("");
        let data = v.get("data").cloned().unwrap_or(Value::Null);

        match event {
            "turn.model_response" => {
                if let Some(m) = data.get("model_actual") {
                    model_actual = m.clone();
                }
            }
            "turn.tool_request" => tool_requests.push(data.clone()),
            "turn.authority_decision" => authority_decisions.push(data.clone()),
            "turn.tool_result" => tool_results.push(data.clone()),
            "session_resume" => recovery_events.push(data.clone()),
            "router.decision" => router_decisions.push(data.clone()),
            "router.escalation" => escalation_events.push(data.clone()),
            "final_answer" => final_answer = data.get("content").cloned().unwrap_or(Value::Null),
            _ => {}
        }

        if event.contains("retry") {
            retries.push(json!({"event": event, "data": data.clone()}));
        }
        if event.contains("error") {
            errors.push(json!({"event": event, "data": data.clone()}));
        }
        if event == "session_stop" {
            if let Some(stop) = data.get("stop_reason").and_then(Value::as_str) {
                if stop.starts_with("ERROR:") || stop == "CONTRACT_FAIL" {
                    errors.push(json!({"event":"session_stop","stop_reason":stop}));
                }
            }
        }
    }

    let start = first_ts.unwrap_or(0);
    let end = last_ts.unwrap_or(start);
    Ok(json!({
        "event_count": events.len(),
        "sequence_ok": sequence_ok,
        "session_id_consistent": session_id_consistent,
        "session_id": sid,
        "time_basis": "unix_epoch_ms_utc",
        "start_time": start,
        "end_time": end,
        "elapsed": end.saturating_sub(start),
        "model_actual": model_actual,
        "tool_requests": tool_requests,
        "authority_decisions": authority_decisions,
        "tool_results": tool_results,
        "errors": errors,
        "retries": retries,
        "recovery_events": recovery_events,
        "router_decisions": router_decisions,
        "escalation_events": escalation_events,
        "final_answer": final_answer
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_vectors() {
        assert_eq!(
            sha256_text(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_text("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn atomic_write_never_follows_a_planted_symlink() {
        let d = std::env::temp_dir().join(format!("hercules-audit-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        let victim = d.join("victim.txt");
        fs::write(&victim, "keep me").unwrap();
        // The old predictable temp name, and the target itself, both planted as symlinks to the victim.
        let target = d.join("evidence.json");
        std::os::unix::fs::symlink(&victim, d.join(format!(".evidence.json.tmp-{}", std::process::id()))).unwrap();
        std::os::unix::fs::symlink(&victim, &target).unwrap();
        write_text_atomic(target.to_str().unwrap(), "new evidence").unwrap();
        assert_eq!(fs::read_to_string(&victim).unwrap(), "keep me");
        assert!(!fs::symlink_metadata(&target).unwrap().file_type().is_symlink());
        assert_eq!(fs::read_to_string(&target).unwrap(), "new evidence");
        // Temp names are unpredictable and opened exclusively.
        let (_, a) = create_temp_beside(&target).unwrap();
        let (_, b) = create_temp_beside(&target).unwrap();
        assert_ne!(a, b);
        fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn redaction_marks_protected_field() {
        let v = json!({"api_key":"HERCULES_SECRET_EXAMPLE","safe":"ok"});
        let r = redact_value(&v);
        assert_eq!(r["safe"], "ok");
        assert_eq!(r["api_key"]["redacted"], true);
        assert_eq!(r["api_key"]["protected_field_present"], true);
    }
}
