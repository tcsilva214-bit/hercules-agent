//! Shared deterministic NDJSON transcript writer.
//! Gate 09 adds session-bound envelopes, monotonic sequence continuity,
//! sensitive-value redaction, and observable write-failure state.

use crate::audit;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Signed runs (config v2): the `prev_sha256` of the first event.
pub const CHAIN_GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub struct TranscriptWriter {
    f: std::fs::File,
    seq: u64,
    session_id: String,
    write_error: Option<String>,
    /// Signed runs (config v2 only): SHA-256 of the previous line as written, without its newline.
    /// v1 transcripts carry no chain and stay byte for byte as before.
    prev: Option<String>,
}

/// Open a transcript path safely: never through a symlink (`O_NOFOLLOW`), created 0600, and an existing file
/// must be a regular file owned by this user with a single link, so a link or hard link planted in a shared
/// output directory cannot redirect the write or the truncation to another file. Nothing is truncated or read
/// until those checks pass.
fn open_private(path: &str) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| std::io::Error::new(e.kind(), format!("transcript {path}: {e} (a symlink is refused)")))?;
    let m = f.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let me = unsafe { libc::geteuid() };
    if !m.is_file() || m.uid() != me || m.nlink() != 1 {
        return Err(std::io::Error::other(format!(
            "transcript {path}: must be a regular file owned by this user with one link (is_file={} uid={} links={})",
            m.is_file(), m.uid(), m.nlink()
        )));
    }
    Ok(f)
}

impl TranscriptWriter {
    /// Transcripts are created 0600: they hold file contents and model output.
    pub fn new(path: &str, session_id: &str) -> std::io::Result<Self> {
        let f = open_private(path)?;
        f.set_len(0)?;
        Ok(TranscriptWriter {
            f,
            seq: 0,
            session_id: session_id.to_string(),
            write_error: None,
            prev: crate::features::build1().then(|| CHAIN_GENESIS.to_string()),
        })
    }

    /// Continue a transcript after a crash. A last line without its newline is a torn write: it is moved to
    /// `<transcript>.torn-<hex>` (never glued to the next event), the file is cut back to the last whole line,
    /// and the first new event records the bytes removed and their SHA-256, so the signed chain says so.
    pub fn resume(path: &str, session_id: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt;
        let mut seq = 0u64;
        let mut last_line: Option<Vec<u8>> = None;
        let mut torn: Option<(usize, String, String)> = None;
        let mut f = open_private(path)?;
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut f, &mut bytes)?;
        {
            let keep = bytes.iter().rposition(|b| *b == b'\n').map(|i| i + 1).unwrap_or(0);
            if keep < bytes.len() {
                let tail = bytes.split_off(keep);
                let saved = format!("{path}.torn-{:016x}", audit::random_u64().map_err(std::io::Error::other)?);
                let mut t = OpenOptions::new().write(true).create_new(true).mode(0o600).custom_flags(libc::O_NOFOLLOW).open(&saved)?;
                t.write_all(&tail)?;
                t.sync_all()?;
                f.set_len(keep as u64)?;
                f.sync_all()?;
                torn = Some((tail.len(), audit::sha256_bytes(&tail), saved));
            }
            for line in bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()) {
                if let Ok(v) = serde_json::from_slice::<serde_json::Value>(line) {
                    if let Some(n) = v.get("seq").and_then(serde_json::Value::as_u64) {
                        seq = seq.max(n);
                    }
                }
                last_line = Some(line.to_vec());
            }
        }
        // The chain continues from the last line on disk, exactly as written.
        let prev = crate::features::build1().then(|| match &last_line {
            Some(l) => audit::sha256_bytes(l),
            None => CHAIN_GENESIS.to_string(),
        });
        let mut w = TranscriptWriter {
            f,
            seq,
            session_id: session_id.to_string(),
            write_error: None,
            prev,
        };
        if let Some((bytes, sha256, saved_to)) = torn {
            w.emit("transcript_torn_tail_removed", None, serde_json::json!({"bytes": bytes, "sha256": sha256, "saved_to": saved_to}));
        }
        Ok(w)
    }

    pub fn emit(&mut self, event: &str, turn: Option<u64>, data: serde_json::Value) {
        self.seq = self.seq.saturating_add(1);
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        if self.write_error.is_some() {
            return;
        }

        let clean = audit::redact_value(&data);
        let mut o = serde_json::json!({
            "schema": "hercules_native_audit_event_v1",
            "seq": self.seq,
            "ts_ms": ts,
            "time_basis": "unix_epoch_ms_utc",
            "session_id": self.session_id,
            "event": event,
            "data": clean
        });
        if let Some(t) = turn {
            o["turn"] = serde_json::json!(t);
        }
        if let Some(prev) = &self.prev {
            o["prev_sha256"] = serde_json::json!(prev);
        }

        // The line is hashed exactly as written (after redaction), so the chain covers the bytes on disk.
        let line = o.to_string();
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        match self.f.write_all(&bytes).and_then(|_| self.f.flush()) {
            Ok(()) => {
                if self.prev.is_some() {
                    self.prev = Some(audit::sha256_bytes(line.as_bytes()));
                }
            }
            Err(e) => {
                self.write_error = Some(format!(
                    "transcript write/flush failed session_id={} seq={} event={}: {e}",
                    self.session_id, self.seq, event
                ));
            }
        }
    }


    pub fn finish(&mut self) -> Result<(), String> {
        if let Some(e) = &self.write_error {
            return Err(e.clone());
        }
        self.f
            .flush()
            .map_err(|e| format!("transcript final flush failed: {e}"))?;
        self.f
            .sync_all()
            .map_err(|e| format!("transcript final sync failed: {e}"))?;
        Ok(())
    }

    pub fn write_error(&self) -> Option<&str> {
        self.write_error.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_planted_link_is_never_written_through() {
        let d = std::env::temp_dir().join(format!("hercules-transcript-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let victim = d.join("victim.txt");
        std::fs::write(&victim, "keep me").unwrap();
        let sym = d.join("sym.ndjson").display().to_string();
        std::os::unix::fs::symlink(&victim, &sym).unwrap();
        assert!(TranscriptWriter::new(&sym, "s").is_err());
        assert!(TranscriptWriter::resume(&sym, "s").is_err());
        let hard = d.join("hard.ndjson").display().to_string();
        std::fs::hard_link(&victim, &hard).unwrap();
        assert!(TranscriptWriter::new(&hard, "s").is_err());
        assert!(TranscriptWriter::resume(&hard, "s").is_err());
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "keep me");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn resume_after_a_torn_write_keeps_the_chain_intact_and_records_it() {
        crate::features::set_build1(true);
        let d = std::env::temp_dir().join(format!("hercules-transcript-torn-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("t.ndjson").display().to_string();
        let mut w = TranscriptWriter::new(&p, "s").unwrap();
        w.emit("a", None, serde_json::json!({}));
        w.emit("b", None, serde_json::json!({}));
        drop(w);
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        // A crash in the middle of the third write.
        let mut f = OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"seq\":3,\"event\":\"c\",\"prev_sha").unwrap();
        drop(f);
        let mut w = TranscriptWriter::resume(&p, "s").unwrap();
        w.emit("d", None, serde_json::json!({}));
        drop(w);
        let bytes = std::fs::read(&p).unwrap();
        let c = crate::attest::check_chain(&bytes);
        assert!(c.first_break.is_none(), "{:?}", c.first_break);
        assert_eq!(c.events, 4);
        let lines: Vec<serde_json::Value> = bytes.split(|b| *b == b'\n').filter(|l| !l.is_empty()).map(|l| serde_json::from_slice(l).unwrap()).collect();
        assert_eq!(lines[2]["event"], "transcript_torn_tail_removed");
        assert_eq!(lines[2]["data"]["sha256"], audit::sha256_bytes(b"{\"seq\":3,\"event\":\"c\",\"prev_sha"));
        let saved = lines[2]["data"]["saved_to"].as_str().unwrap().to_string();
        assert_eq!(std::fs::read(&saved).unwrap(), b"{\"seq\":3,\"event\":\"c\",\"prev_sha");
        std::fs::remove_dir_all(&d).unwrap();
    }
}
