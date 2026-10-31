//! Signed runs (config v2): keys, the run statement, the DSSE envelope and `attest verify`.
//!
//! Every transcript event carries `prev_sha256`, the SHA-256 of the previous line as written (transcript.rs).
//! At run end one short statement binds the chain head to everything else the run produced; it is signed
//! with Ed25519 inside a DSSE v1 envelope. The signature is checked with a public key and the rest by
//! re-deriving, so a verifier needs no network and no account.
//!
//! Cryptography comes from `ed25519-dalek` only. What is written here is encoding: base64, the fixed
//! RFC 8410 DER prefixes of an Ed25519 PKCS#8 private key and SubjectPublicKeyInfo public key (so the
//! key files are ordinary PEM that other tools read), and DSSE's pre-authentication encoding.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

pub const PAYLOAD_TYPE: &str = "application/vnd.hercules.run-statement.v1+json";
/// Gate 10: signed records of `change apply` and `change rollback`.
pub const CHANGE_PAYLOAD_TYPE: &str = "application/vnd.hercules.change-record.v1+json";
pub const STATEMENT_SCHEMA: &str = "hercules_run_statement_v1";
pub const KEY_FILE_NAME: &str = "signing.key";
pub const PUB_FILE_NAME: &str = "signing.pub";

/// RFC 8410: PKCS#8 v1 PrivateKeyInfo for Ed25519, followed by the 32-byte seed.
const PKCS8_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];
/// RFC 8410: SubjectPublicKeyInfo for Ed25519, followed by the 32-byte public key.
const SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
const KEY_FILE_MAX_BYTES: u64 = 4096;

// ---------------------------------------------------------------------------------------------- base64

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard base64 with padding (RFC 4648 section 4).
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}

/// Strict decoding of standard or URL-safe base64 (DSSE allows either). Padding is optional, but if
/// present it must be correct; unused low bits must be zero. Whitespace is not accepted.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    let s = s.as_bytes();
    let body_len = s.iter().rposition(|c| *c != b'=').map(|i| i + 1).unwrap_or(0);
    let pad = s.len() - body_len;
    if pad > 2 || (pad > 0 && !s.len().is_multiple_of(4)) || body_len % 4 == 1 {
        return Err("base64: bad length or padding".into());
    }
    let val = |c: u8| -> Result<u32, String> {
        Ok(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return Err(format!("base64: invalid character {:?}", c as char)),
        } as u32)
    };
    let body = &s[..body_len];
    let mut out = Vec::with_capacity(body_len * 3 / 4);
    for chunk in body.chunks(4) {
        let mut n = 0u32;
        for (i, c) in chunk.iter().enumerate() {
            n |= val(*c)? << (18 - 6 * i);
        }
        match chunk.len() {
            4 => out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8, n as u8]),
            3 => {
                if n & 0xff != 0 {
                    return Err("base64: non-zero trailing bits".into());
                }
                out.extend_from_slice(&[(n >> 16) as u8, (n >> 8) as u8]);
            }
            2 => {
                if n & 0xffff != 0 {
                    return Err("base64: non-zero trailing bits".into());
                }
                out.push((n >> 16) as u8);
            }
            _ => return Err("base64: bad length".into()),
        }
    }
    Ok(out)
}

// ------------------------------------------------------------------------------------------------- PEM

fn pem(label: &str, der: &[u8]) -> String {
    let b = b64_encode(der);
    let mut s = format!("-----BEGIN {label}-----\n");
    for line in b.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap_or(""));
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

fn unpem(text: &str, label: &str) -> Result<Vec<u8>, String> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let lines: Vec<&str> = text.lines().map(str::trim).filter(|l| !l.is_empty()).collect();
    if lines.len() < 3 || lines[0] != begin || lines[lines.len() - 1] != end {
        return Err(format!("not a single PEM block labelled {label}"));
    }
    b64_decode(&lines[1..lines.len() - 1].concat())
}

pub fn private_key_pem(seed: &[u8; 32]) -> String {
    let mut der = Vec::with_capacity(48);
    der.extend_from_slice(&PKCS8_PREFIX);
    der.extend_from_slice(seed);
    let s = pem("PRIVATE KEY", &der);
    wipe(&mut der);
    s
}

pub fn public_key_pem(pk: &VerifyingKey) -> String {
    let mut der = Vec::with_capacity(44);
    der.extend_from_slice(&SPKI_PREFIX);
    der.extend_from_slice(pk.as_bytes());
    pem("PUBLIC KEY", &der)
}

fn parse_private_key(text: &str) -> Result<SigningKey, String> {
    let mut der = unpem(text, "PRIVATE KEY")?;
    let ok = der.len() == 48 && der[..16] == PKCS8_PREFIX;
    let out = if ok {
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&der[16..]);
        let k = SigningKey::from_bytes(&seed);
        wipe(&mut seed);
        Ok(k)
    } else {
        Err("not an Ed25519 PKCS#8 private key (RFC 8410)".to_string())
    };
    wipe(&mut der);
    out
}

pub fn parse_public_key(text: &str) -> Result<VerifyingKey, String> {
    let der = unpem(text, "PUBLIC KEY")?;
    if der.len() != 44 || der[..12] != SPKI_PREFIX {
        return Err("not an Ed25519 SubjectPublicKeyInfo public key (RFC 8410)".into());
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&der[12..]);
    VerifyingKey::from_bytes(&pk).map_err(|e| format!("invalid Ed25519 public key: {e}"))
}

/// keyid = SHA-256 of the raw 32-byte public key, hex.
pub fn keyid(pk: &VerifyingKey) -> String {
    crate::audit::sha256_bytes(pk.as_bytes())
}

fn wipe(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        // Volatile so the compiler cannot drop the store of a value never read again.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

// ------------------------------------------------------------------------------------------- key files

/// `keygen --out <dir>`: writes signing.key (0600) and signing.pub (0644) into an existing directory.
/// Refuses to overwrite either. Returns the keyid.
pub fn keygen(dir: &str) -> Result<String, String> {
    let d = std::path::Path::new(dir);
    if !d.is_absolute() {
        return Err("--out must be an absolute path".into());
    }
    if !d.is_dir() {
        return Err(format!("--out {dir} is not an existing directory"));
    }
    let key_path = d.join(KEY_FILE_NAME);
    let pub_path = d.join(PUB_FILE_NAME);
    for p in [&key_path, &pub_path] {
        if std::fs::symlink_metadata(p).is_ok() {
            return Err(format!("{} exists; keygen never overwrites a key", p.display()));
        }
    }
    let mut seed = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut seed))
        .map_err(|e| format!("reading /dev/urandom: {e}"))?;
    let sk = SigningKey::from_bytes(&seed);
    let mut key_pem = private_key_pem(&seed);
    wipe(&mut seed);
    let pk = sk.verifying_key();
    let write_new = |p: &std::path::Path, mode: u32, body: &str| -> Result<(), String> {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .custom_flags(libc::O_NOFOLLOW)
            .open(p)
            .map_err(|e| format!("create {}: {e}", p.display()))?;
        f.write_all(body.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("write {}: {e}", p.display()))
    };
    let r = write_new(&key_path, 0o600, &key_pem);
    // SAFETY: wiping the String's bytes in place; it is dropped right after and never read again.
    wipe(unsafe { key_pem.as_bytes_mut() });
    r?;
    write_new(&pub_path, 0o644, &public_key_pem(&pk))?;
    Ok(keyid(&pk))
}

/// Read `sign.key_file`: an absolute path, no symlink, a regular file that neither the group nor other
/// users can read or write (a signing key is stricter than `provider.api_key_file`, which allows 0640:
/// on macOS every local account shares the `staff` group).
pub fn read_signing_key(path: &str) -> Result<SigningKey, String> {
    if !std::path::Path::new(path).is_absolute() {
        return Err("path must be absolute".into());
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| format!("cannot open: {e}"))?;
    let md = f.metadata().map_err(|e| format!("stat: {e}"))?;
    if !md.file_type().is_file() {
        return Err("is not a regular file".into());
    }
    if md.mode() & 0o077 != 0 {
        return Err(format!("mode {:o} lets other users read or change it; use chmod 600", md.mode() & 0o777));
    }
    if md.len() > KEY_FILE_MAX_BYTES {
        return Err("is too large to be a key".into());
    }
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| format!("read: {e}"))?;
    let r = match std::str::from_utf8(&buf) {
        Ok(text) => parse_private_key(text),
        Err(_) => Err("is not PEM text".into()),
    };
    wipe(&mut buf);
    r
}

pub fn read_public_key(path: &str) -> Result<VerifyingKey, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("--pubkey {path}: {e}"))?;
    parse_public_key(&text).map_err(|e| format!("--pubkey {path}: {e}"))
}

// ------------------------------------------------------------------------------------------------ DSSE

/// DSSE v1 pre-authentication encoding: "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body.
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Sign `statement` (its exact serialized bytes) and return the DSSE envelope as JSON text.
pub fn sign_envelope(sk: &SigningKey, statement: &Value) -> String {
    sign_typed(sk, PAYLOAD_TYPE, statement)
}

/// The same envelope for another payload type (Gate 10's change records).
pub fn sign_typed(sk: &SigningKey, payload_type: &str, statement: &Value) -> String {
    let payload = statement.to_string().into_bytes();
    let sig: Signature = sk.sign(&pae(payload_type, &payload));
    let env = json!({
        "payloadType": payload_type,
        "payload": b64_encode(&payload),
        "signatures": [{"keyid": keyid(&sk.verifying_key()), "sig": b64_encode(&sig.to_bytes())}]
    });
    format!("{env}\n")
}

/// Check an envelope against a public key. Returns the statement bytes when exactly one signature
/// (by this key's keyid) verifies; any other signatures are ignored.
pub fn open_envelope(envelope_text: &str, pk: &VerifyingKey) -> Result<Vec<u8>, String> {
    open_typed(envelope_text, pk, PAYLOAD_TYPE)
}

pub fn open_typed(envelope_text: &str, pk: &VerifyingKey, payload_type: &str) -> Result<Vec<u8>, String> {
    let env: Value = serde_json::from_str(envelope_text).map_err(|e| format!("attestation is not JSON: {e}"))?;
    if env["payloadType"].as_str() != Some(payload_type) {
        return Err(format!("payloadType is {}, expected {payload_type}", env["payloadType"]));
    }
    let payload = b64_decode(env["payload"].as_str().ok_or("payload missing")?).map_err(|e| format!("payload {e}"))?;
    let sigs = env["signatures"].as_array().ok_or("signatures missing")?;
    let want = keyid(pk);
    let mine: Vec<&Value> = sigs.iter().filter(|s| s["keyid"].as_str() == Some(want.as_str())).collect();
    if mine.is_empty() {
        return Err(format!("no signature with keyid {want} (the public key given)"));
    }
    let message = pae(payload_type, &payload);
    for s in mine {
        let Some(raw) = s["sig"].as_str() else { continue };
        let Ok(bytes) = b64_decode(raw) else { continue };
        let Ok(arr) = <[u8; 64]>::try_from(bytes.as_slice()) else { continue };
        let sig = Signature::from_bytes(&arr);
        if pk.verify_strict(&message, &sig).is_ok() {
            return Ok(payload);
        }
    }
    Err("signature does not verify".into())
}

// ------------------------------------------------------------------------------------------- the chain

pub struct ChainCheck {
    /// Number of non-empty lines.
    pub events: u64,
    /// SHA-256 of the last line (the head), if any.
    pub head: Option<String>,
    /// The `seq` of the last event whose link holds before the first break (or of the last event).
    pub intact_through_seq: u64,
    /// The first broken link, as (line number from 1, reason).
    pub first_break: Option<(u64, String)>,
}

/// Walk the transcript's `prev_sha256` links over the exact line bytes. Every line must be a JSON event whose
/// `prev_sha256` is the SHA-256 of the line before (64 zeros for the first), and the file must end with a
/// newline (the writer writes each line and its newline together, so a missing one means a torn write).
pub fn check_chain(bytes: &[u8]) -> ChainCheck {
    let mut prev = crate::transcript::CHAIN_GENESIS.to_string();
    let mut out = ChainCheck { events: 0, head: None, intact_through_seq: 0, first_break: None };
    if bytes.is_empty() {
        return out;
    }
    let body = bytes.strip_suffix(b"\n").unwrap_or(bytes);
    for (i, line) in body.split(|b| *b == b'\n').enumerate() {
        let n = i as u64 + 1;
        out.events = n;
        if out.first_break.is_none() {
            let link = serde_json::from_slice::<Value>(line).ok().and_then(|v| {
                let p = v.get("prev_sha256")?.as_str()?.to_string();
                Some((p, v.get("seq").and_then(Value::as_u64)))
            });
            match link {
                // Sequence continuity: line n carries seq n (the writer numbers events from 1 and resume continues).
                Some((p, Some(seq))) if p == prev && seq == n => out.intact_through_seq = seq,
                Some((p, seq)) if p == prev => {
                    out.first_break = Some((n, match seq {
                        Some(s) => format!("seq is {s}, expected {n}"),
                        None => "event has no seq".into(),
                    }))
                }
                Some(_) => out.first_break = Some((n, "prev_sha256 does not match the line before".into())),
                None => out.first_break = Some((n, "line is not a chained JSON event".into())),
            }
        }
        prev = crate::audit::sha256_bytes(line);
    }
    if out.first_break.is_none() && !bytes.ends_with(b"\n") {
        out.first_break = Some((out.events, "the last line has no newline (a torn write)".into()));
    }
    out.head = Some(prev);
    out
}

// --------------------------------------------------------------------------------------- the statement

/// RFC 3339 UTC from Unix milliseconds ("2026-10-30T05:47:38.457Z").
pub fn rfc3339_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{:03}Z", rem / 3600, rem % 3600 / 60, rem % 60, ms % 1000)
}

pub struct TranscriptFacts {
    pub sha256: String,
    pub events: u64,
    pub head: Option<String>,
}

pub fn transcript_facts(path: &str) -> Result<TranscriptFacts, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("transcript read failed {path}: {e}"))?;
    let c = check_chain(&bytes);
    Ok(TranscriptFacts { sha256: crate::audit::sha256_bytes(&bytes), events: c.events, head: c.head })
}

pub fn file_sha256(path: Option<&str>) -> Value {
    match path.map(crate::audit::sha256_file) {
        Some(Ok(h)) => json!(h),
        _ => Value::Null,
    }
}

// ------------------------------------------------------------------------------------------------ verify

pub struct VerifyArgs<'a> {
    pub attestation: &'a str,
    pub pubkey: &'a str,
    pub transcript: &'a str,
    pub final_path: &'a str,
    pub report: &'a str,
    pub manifest: &'a str,
    /// Gate 10: the run's proposal folder, when its statement names a changeset.
    pub proposal: Option<&'a str>,
}

/// `attest verify`: the one line to print and the exit code (0 only for MATCH).
pub fn verify(a: &VerifyArgs) -> (String, i32) {
    if std::fs::symlink_metadata(a.attestation).is_err() {
        // No attestation: verify_with reports INCOMPLETE before any key is used.
        return verify_with(a, &SigningKey::from_bytes(&[1u8; 32]).verifying_key());
    }
    match read_public_key(a.pubkey) {
        Ok(pk) => verify_with(a, &pk),
        Err(e) => (format!("ATTEST_VERIFY ERROR {e}"), 2),
    }
}

pub fn verify_with(a: &VerifyArgs, pk: &VerifyingKey) -> (String, i32) {
    let tbytes = match std::fs::read(a.transcript) {
        Ok(b) => b,
        Err(e) => return (format!("ATTEST_VERIFY ERROR transcript unreadable: {e}"), 2),
    };
    let chain = check_chain(&tbytes);
    // No attestation on disk: the run never closed (a crash). Report the chain, never a pass.
    if std::fs::symlink_metadata(a.attestation).is_err() {
        return match &chain.first_break {
            None => (
                format!("ATTEST_VERIFY INCOMPLETE unsigned chain_intact_through_seq={} events={}", chain.intact_through_seq, chain.events),
                1,
            ),
            Some((line, why)) => (
                format!("ATTEST_VERIFY INCOMPLETE unsigned chain_broken_at_line={line} ({why}) chain_intact_through_seq={}", chain.intact_through_seq),
                1,
            ),
        };
    }
    let pk = *pk;
    let env_text = match std::fs::read_to_string(a.attestation) {
        Ok(t) => t,
        Err(e) => return (format!("ATTEST_VERIFY ERROR attestation unreadable: {e}"), 2),
    };
    // 1. The signature.
    let payload = match open_envelope(&env_text, &pk) {
        Ok(p) => p,
        Err(e) => return (format!("ATTEST_VERIFY MISMATCH fields=signature ({e})"), 1),
    };
    let st: Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(e) => return (format!("ATTEST_VERIFY MISMATCH fields=statement (signed payload is not JSON: {e})"), 1),
    };
    if st["schema"].as_str() != Some(STATEMENT_SCHEMA) {
        return (format!("ATTEST_VERIFY MISMATCH fields=statement (schema {})", st["schema"]), 1);
    }
    let mut diffs: Vec<String> = Vec::new();
    // 2. The transcript's digest, event count and head.
    let t = &st["transcript"];
    if t["sha256"].as_str() != Some(crate::audit::sha256_bytes(&tbytes).as_str()) {
        diffs.push("transcript.sha256".into());
    }
    if t["events"].as_u64() != Some(chain.events) {
        diffs.push("transcript.events".into());
    }
    // Every bound digest must be a real SHA-256 in the statement and match a readable file: a null or
    // malformed digest never matches, and neither does a missing file.
    let hex64 = |v: &Value| v.as_str().filter(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())).map(str::to_string);
    if !matches!((hex64(&t["head"]), chain.head.as_deref()), (Some(a), Some(b)) if a == b) {
        diffs.push("transcript.head".into());
    }
    // 3. Every link.
    if chain.first_break.is_some() {
        diffs.push("transcript.chain".into());
    }
    // 4. The final answer, the report and the manifest (always required: the statement binds all three).
    let digest_of = |p: &str| crate::audit::sha256_file(p).ok();
    for (field, path) in [("final_content_sha256", a.final_path), ("evidence_report_sha256", a.report), ("manifest_sha256", a.manifest)] {
        if !matches!((hex64(&st[field]), digest_of(path)), (Some(want), Some(got)) if want == got) {
            diffs.push(field.into());
        }
    }
    // Gate 10: the changeset the statement names, and every proposed file in it.
    match (st["changeset_sha256"].as_str(), a.proposal) {
        (None, None) => {}
        (Some(_), None) => diffs.push("changeset(pass --proposal <folder>)".into()),
        (None, Some(_)) => diffs.push("changeset(this run proposed nothing)".into()),
        (Some(want), Some(dir)) => {
            let probs = crate::proposal::check_folder(std::path::Path::new(dir), want);
            if !probs.is_empty() {
                diffs.push(format!("changeset({})", probs.join(",")));
            }
        }
    }
    // 5. The report re-derives from the transcript and the final answer.
    let report: Option<Value> = std::fs::read_to_string(a.report).ok().and_then(|s| serde_json::from_str(&s).ok());
    let final_text = std::fs::read_to_string(a.final_path).ok();
    match (report, final_text) {
        (Some(r), Some(f)) => match crate::evidence::verify(&r, a.transcript, &f) {
            Ok(d) if d.is_empty() => {}
            Ok(d) => diffs.push(format!("evidence({})", d.join(","))),
            Err(e) => diffs.push(format!("evidence({e})")),
        },
        _ => diffs.push("evidence(report or final unreadable)".into()),
    }
    if diffs.is_empty() {
        (
            format!(
                "ATTEST_VERIFY MATCH kind={} keyid={} events={} stop_reason={}",
                st["kind"].as_str().unwrap_or("?"),
                keyid(&pk),
                chain.events,
                st["stop_reason"].as_str().unwrap_or("?")
            ),
            0,
        )
    } else {
        (format!("ATTEST_VERIFY MISMATCH fields={}", diffs.join(",")), 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "hercules-attest-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn base64_rfc4648_vectors() {
        for (plain, enc) in [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")] {
            assert_eq!(b64_encode(plain.as_bytes()), enc);
            assert_eq!(b64_decode(enc).unwrap(), plain.as_bytes());
        }
        assert_eq!(b64_decode("Zm9vYmE").unwrap(), b"fooba"); // unpadded
        assert_eq!(b64_decode("-_8=").unwrap(), [0xfb, 0xff]); // URL-safe alphabet
        for bad in ["Zg=", "Z", "Zh==", "Zm9=", "Zm 9v", "Zm9v====", "*m9v"] {
            assert!(b64_decode(bad).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn dsse_pae_spec_vector() {
        // DSSE protocol.md example.
        assert_eq!(pae("http://example.com/HelloWorld", b"hello world"), b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec());
        assert_eq!(pae("", b""), b"DSSEv1 0  0 ".to_vec());
    }

    /// The seed 0x01..0x20 is a public test value, never a real key. OpenSSL 3.0 read the RFC 8410 PKCS#8
    /// encoding of it (`openssl pkey -pubout`) and gave this public key; the PEM code must agree byte for byte.
    const TEST_SEED: [u8; 32] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32];
    const OPENSSL_PK: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAebVWLo/mVPlAeLES6KmLp5AfhTrmlb7X4OORC60ElmQ=\n-----END PUBLIC KEY-----\n";

    fn test_key() -> SigningKey {
        SigningKey::from_bytes(&TEST_SEED)
    }

    #[test]
    fn pem_matches_openssl() {
        let sk = test_key();
        assert_eq!(public_key_pem(&sk.verifying_key()), OPENSSL_PK);
        assert_eq!(parse_public_key(OPENSSL_PK).unwrap(), sk.verifying_key());
        // OpenSSL's Ed25519 PKCS#8 files all begin with these characters (the fixed RFC 8410 prefix).
        let sk_pem = private_key_pem(&TEST_SEED);
        assert!(sk_pem.starts_with("-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEI"), "{sk_pem}");
        assert_eq!(parse_private_key(&sk_pem).unwrap().to_bytes(), TEST_SEED);
        assert!(parse_public_key(&sk_pem).is_err());
        assert!(parse_private_key(OPENSSL_PK).is_err());
    }

    #[test]
    fn sign_open_and_tamper() {
        let sk = test_key();
        let pk = sk.verifying_key();
        let st = json!({"schema": STATEMENT_SCHEMA, "kind": "mission", "x": 1});
        let env = sign_envelope(&sk, &st);
        assert_eq!(open_envelope(&env, &pk).unwrap(), st.to_string().into_bytes());
        let v: Value = serde_json::from_str(&env).unwrap();
        // Changed payload.
        let mut e2 = v.clone();
        e2["payload"] = json!(b64_encode(br#"{"schema":"hercules_run_statement_v1","kind":"mission","x":2}"#));
        assert!(open_envelope(&e2.to_string(), &pk).unwrap_err().contains("does not verify"));
        // Corrupted signature.
        let mut e3 = v.clone();
        let mut sig = b64_decode(v["signatures"][0]["sig"].as_str().unwrap()).unwrap();
        sig[10] ^= 1;
        e3["signatures"][0]["sig"] = json!(b64_encode(&sig));
        assert!(open_envelope(&e3.to_string(), &pk).is_err());
        // Wrong payloadType (the signature binds it too).
        let mut e4 = v.clone();
        e4["payloadType"] = json!("application/json");
        assert!(open_envelope(&e4.to_string(), &pk).unwrap_err().contains("payloadType"));
        // Wrong key.
        let other = SigningKey::from_bytes(&[7u8; 32]).verifying_key();
        assert!(open_envelope(&env, &other).unwrap_err().contains("keyid"));
        // A signature by another key placed under this keyid.
        let mut e5 = v.clone();
        let forged = SigningKey::from_bytes(&[9u8; 32]).sign(&pae(PAYLOAD_TYPE, st.to_string().as_bytes()));
        e5["signatures"][0]["sig"] = json!(b64_encode(&forged.to_bytes()));
        assert!(open_envelope(&e5.to_string(), &pk).is_err());
    }

    fn chained(n: usize) -> Vec<u8> {
        let mut prev = crate::transcript::CHAIN_GENESIS.to_string();
        let mut out = Vec::new();
        for i in 1..=n {
            let line = json!({"seq": i, "event": "e", "prev_sha256": prev}).to_string();
            prev = crate::audit::sha256_bytes(line.as_bytes());
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        out
    }

    fn lines(b: &[u8]) -> Vec<Vec<u8>> {
        b.strip_suffix(b"\n").unwrap().split(|c| *c == b'\n').map(<[u8]>::to_vec).collect()
    }

    fn join(l: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for x in l {
            out.extend_from_slice(x);
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn chain_intact_and_every_tamper_case() {
        let good = chained(5);
        let c = check_chain(&good);
        assert!(c.first_break.is_none());
        assert_eq!((c.events, c.intact_through_seq), (5, 5));
        assert_eq!(c.head.unwrap(), crate::audit::sha256_bytes(&lines(&good)[4]));
        let base = lines(&good);
        // Edited line (one byte), deleted line, inserted line, reordered lines.
        let mut edited = base.clone();
        edited[2] = String::from_utf8(edited[2].clone()).unwrap().replace("\"e\"", "\"f\"").into_bytes();
        let mut deleted = base.clone();
        deleted.remove(2);
        let mut inserted = base.clone();
        inserted.insert(2, base[1].clone());
        let mut reordered = base.clone();
        reordered.swap(1, 2);
        for (name, t) in [("edited", edited), ("deleted", deleted), ("inserted", inserted), ("reordered", reordered)] {
            let c = check_chain(&join(&t));
            assert!(c.first_break.is_some(), "{name} not caught");
        }
        // The edited line itself still links; the break shows at the next line (line 4).
        let mut edited = base.clone();
        edited[2].push(b' ');
        assert_eq!(check_chain(&join(&edited)).first_break.unwrap().0, 4);
        // Truncation keeps a valid prefix chain: only the signed head and count catch it.
        let c = check_chain(&join(&base[..3]));
        assert!(c.first_break.is_none());
        assert_eq!(c.events, 3);
        // A torn last line (a crash mid-write): the first four events still verify.
        let mut torn = good.clone();
        torn.pop();
        torn.truncate(torn.len() - 5);
        let c = check_chain(&torn);
        assert_eq!(c.first_break.unwrap().0, 5);
        assert_eq!(c.intact_through_seq, 4);
        // A complete last line without its newline.
        let mut no_nl = good.clone();
        no_nl.pop();
        assert!(check_chain(&no_nl).first_break.unwrap().1.contains("torn"));
        // A blank line inside the file.
        let mut blank = join(&base[..2]);
        blank.push(b'\n');
        blank.extend_from_slice(&join(&base[2..]));
        assert_eq!(check_chain(&blank).first_break.unwrap().0, 3);
        // Empty transcript.
        assert_eq!(check_chain(b"").events, 0);
    }

    /// A chain whose links are all correct but whose `seq` values are the given ones.
    fn chained_seqs(seqs: &[Option<u64>]) -> Vec<u8> {
        let mut prev = crate::transcript::CHAIN_GENESIS.to_string();
        let mut out = Vec::new();
        for s in seqs {
            let mut v = json!({"event": "e", "prev_sha256": prev});
            if let Some(s) = s {
                v["seq"] = json!(s);
            }
            let line = v.to_string();
            prev = crate::audit::sha256_bytes(line.as_bytes());
            out.extend_from_slice(line.as_bytes());
            out.push(b'\n');
        }
        out
    }

    #[test]
    fn chain_requires_sequence_continuity() {
        let ok = check_chain(&chained_seqs(&[Some(1), Some(2), Some(3)]));
        assert!(ok.first_break.is_none());
        assert_eq!(ok.intact_through_seq, 3);
        // Links intact, numbering wrong: a gap, a duplicate, a missing seq, a start other than 1.
        for (seqs, at, why) in [
            (vec![Some(1), Some(2), Some(4)], 3, "seq is 4, expected 3"),
            (vec![Some(1), Some(2), Some(2)], 3, "seq is 2, expected 3"),
            (vec![Some(1), None, Some(3)], 2, "event has no seq"),
            (vec![Some(0), Some(1)], 1, "seq is 0, expected 1"),
            (vec![Some(2), Some(3)], 1, "seq is 2, expected 1"),
        ] {
            let c = check_chain(&chained_seqs(&seqs));
            assert_eq!(c.first_break, Some((at, why.to_string())), "{seqs:?}");
            assert_eq!(c.intact_through_seq, at - 1, "{seqs:?}");
        }
    }

    #[test]
    fn a_null_or_malformed_bound_digest_never_matches() {
        let d = std::env::temp_dir().join(format!("hercules-attest-null-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let w = |n: &str, b: &[u8]| {
            let p = d.join(n);
            std::fs::write(&p, b).unwrap();
            p.display().to_string()
        };
        let chain = chained(2);
        let (t, f, r) = (w("t.ndjson", &chain), w("final.txt", b"answer"), w("report.json", b"{}"));
        let manifest = w("manifest.json", b"{}");
        let sk = SigningKey::from_bytes(&[5u8; 32]);
        let head = crate::audit::sha256_bytes(&lines(&chain)[1]);
        let statement = |m: Value| json!({"schema": STATEMENT_SCHEMA, "kind": "mission",
            "transcript": {"sha256": crate::audit::sha256_bytes(&chain), "events": 2, "head": head},
            "final_content_sha256": crate::audit::sha256_bytes(b"answer"), "evidence_report_sha256": crate::audit::sha256_bytes(b"{}"),
            "manifest_sha256": m});
        let run = |m: Value, manifest_path: &str| {
            let a = w("a.json", sign_envelope(&sk, &statement(m)).as_bytes());
            verify_with(&VerifyArgs { attestation: &a, pubkey: "", transcript: &t, final_path: &f, report: &r, manifest: manifest_path, proposal: None }, &sk.verifying_key()).0
        };
        let missing = d.join("no-such-manifest.json").display().to_string();
        assert!(run(Value::Null, &missing).contains("manifest_sha256"), "null digest + missing file must not match");
        assert!(run(json!("not-hex"), &manifest).contains("manifest_sha256"));
        assert!(!run(json!(crate::audit::sha256_bytes(b"{}")), &manifest).contains("manifest_sha256"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn rfc3339() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(rfc3339_ms(951_782_400_000), "2000-02-29T00:00:00.000Z");
        assert_eq!(rfc3339_ms(1_793_339_923_127), "2026-10-30T05:58:43.127Z");
    }

    #[test]
    fn keygen_writes_once_and_key_file_rules() {
        let d = tmpdir("keygen");
        let ds = d.display().to_string();
        let kid = keygen(&ds).unwrap();
        assert!(keygen(&ds).unwrap_err().contains("never overwrites"));
        let kp = d.join(KEY_FILE_NAME).display().to_string();
        let pp = d.join(PUB_FILE_NAME).display().to_string();
        let sk = read_signing_key(&kp).unwrap();
        assert_eq!(keyid(&read_public_key(&pp).unwrap()), kid);
        assert_eq!(keyid(&sk.verifying_key()), kid);
        let mode = |p: &str| std::fs::metadata(p).unwrap().mode() & 0o777;
        assert_eq!(mode(&kp), 0o600);
        use std::os::unix::fs::PermissionsExt;
        for bad in [0o640, 0o604, 0o660] {
            std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(bad)).unwrap();
            assert!(read_signing_key(&kp).unwrap_err().contains("chmod 600"), "{bad:o}");
        }
        std::fs::set_permissions(&kp, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = d.join("link.key");
        std::os::unix::fs::symlink(&kp, &link).unwrap();
        assert!(read_signing_key(&link.display().to_string()).is_err());
        assert!(read_signing_key("relative/signing.key").is_err());
        assert!(read_signing_key(&d.display().to_string()).is_err());
        assert!(keygen("relative").is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
