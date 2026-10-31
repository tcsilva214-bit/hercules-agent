//! Gate 10: `change apply`, `change rollback`, `change recover`, `change verify`. Operator-run only; the model
//! never reaches this.
//!
//! Apply takes a proposal folder written by a signed run, checks that run (`attest verify` with the changeset),
//! takes the operator's typed changeset digest as the approval, and refuses if any target drifted from its base
//! (content or permissions). Rollback restores the backup only if every file still has the content and
//! permissions apply left. Both are transactions:
//!
//! 0. The command takes an exclusive lock on the proposal folder (`flock`, released by the kernel if the process
//!    dies), so no two `change` commands ever run on one proposal at the same time.
//! 1. Everything is validated before the first change: the run, the roots, the deny list, every target's current
//!    content and mode, and every proposed file or backup the transaction will write (read and hash-checked).
//! 2. A journal (`journal.json`) naming each file's from/to content and mode is signed with the operator's key,
//!    written, and its directory synced before the first change.
//! 3. Each file is checked again immediately before it is replaced, then replaced atomically, through directory
//!    handles that never follow a link (anchored.rs).
//! 4. Every file is read back, and the signed record is written; the journal is removed last (synced).
//!
//! A failure at any step after the journal (writing, the read-back, signing the record) puts back exactly what
//! this process wrote. If the process dies instead (a crash, a kill, power loss), the journal stays, every `change`
//! command refuses, and `change recover` puts every file back. Recover trusts only a journal signed by the
//! operator's key for this proposal's changeset, takes file names only from that changeset, derives where the
//! saved copies are itself, applies the deny list, and checks every copy before it changes anything. Each single
//! file is replaced atomically; the set of files is all-or-none through this journal and recovery, not by the
//! filesystem.

use crate::anchored::{Dir, State};
use crate::attest;
use crate::proposal::atomic_write;
use crate::roots::{Root, RootPolicy};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub const RECORD_SCHEMA: &str = "hercules_change_record_v1";
pub const JOURNAL_SCHEMA: &str = "hercules_change_journal_v1";
pub const JOURNAL_PAYLOAD_TYPE: &str = "application/vnd.hercules.change-journal.v1+json";
const JOURNAL: &str = "journal.json";
const LOCK: &str = ".change.lock";

fn sha(b: &[u8]) -> String {
    crate::audit::sha256_bytes(b)
}

fn now_rfc3339() -> String {
    let ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    attest::rfc3339_ms(ms)
}

fn parse_mode(v: &Value) -> Option<u32> {
    v.as_str().and_then(|m| u32::from_str_radix(m, 8).ok()).map(|m| m & 0o777)
}

fn mode_str(m: u32) -> String {
    format!("{:o}", m & 0o777)
}

struct File {
    root: String,
    rel: String,
    path: PathBuf,
    change: String,
    base: Option<String>,
    new: String,
    mode: u32,
}

fn load_changeset(dir: &Path) -> Result<(Value, String, Vec<File>), String> {
    let text = std::fs::read(dir.join("changeset.json")).map_err(|e| format!("changeset.json: {e}"))?;
    let cs: Value = serde_json::from_slice(&text).map_err(|e| format!("changeset.json: {e}"))?;
    if cs["schema"].as_str() != Some(crate::proposal::CHANGESET_SCHEMA) {
        return Err("changeset.json: unknown schema".into());
    }
    let mut files = Vec::new();
    for f in cs["files"].as_array().cloned().unwrap_or_default() {
        files.push(File {
            root: f["root"].as_str().unwrap_or("").into(),
            rel: f["rel"].as_str().unwrap_or("").into(),
            path: PathBuf::from(f["path"].as_str().unwrap_or("")),
            change: f["change"].as_str().unwrap_or("").into(),
            base: f["base_sha256"].as_str().map(str::to_string),
            new: f["new_sha256"].as_str().unwrap_or("").into(),
            mode: parse_mode(&f["mode"]).unwrap_or(0o644),
        });
    }
    Ok((cs, sha(&text), files))
}

/// The run that wrote the proposal must verify, changeset included.
fn verify_run(dir: &Path, pk: &VerifyingKey) -> Result<Value, String> {
    let run: Value = std::fs::read_to_string(dir.join("run.json"))
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .ok_or("run.json missing: this folder was not closed by a run")?;
    let s = |k: &str| run[k].as_str().unwrap_or("").to_string();
    let (a, t, f, r, m) = (s("attestation"), s("transcript"), s("final"), s("report"), s("manifest"));
    let dir_s = dir.display().to_string();
    let (line, code) = attest::verify_with(
        &attest::VerifyArgs { attestation: &a, pubkey: "", transcript: &t, final_path: &f, report: &r, manifest: &m, proposal: Some(&dir_s) },
        pk,
    );
    if code != 0 {
        return Err(format!("the proposal's run does not verify: {line}"));
    }
    // run.json is not signed: the run named in signed records is the signed statement's, and run.json must agree.
    let st: Value = std::fs::read_to_string(&a)
        .map_err(|e| e.to_string())
        .and_then(|t| attest::open_envelope(&t, pk))
        .and_then(|p| serde_json::from_slice(&p).map_err(|e| e.to_string()))
        .map_err(|e| format!("the proposal's run attestation: {e}"))?;
    if run["run_id"] != st["run_id"] || run["session_id"] != st["session_id"] {
        return Err(format!("run.json names run {} but the signed run is {}; nothing done", run["run_id"], st["run_id"]));
    }
    let digest = std::fs::read(dir.join("changeset.json")).map(|b| sha(&b)).unwrap_or_default();
    if st["changeset_sha256"].as_str() != Some(digest.as_str()) {
        return Err("the signed run names another changeset; nothing done".into());
    }
    Ok(st)
}

/// The write root a file belongs to, checked: its path must be exactly the root's path plus the relative path.
fn root_for<'a>(write_roots: &'a [Root], root: &str, rel: &str, path: &Path) -> Result<&'a Root, String> {
    let r = write_roots
        .iter()
        .find(|w| w.name == root)
        .ok_or_else(|| format!("{}: root {root} is not a write root in this config", path.display()))?;
    crate::anchored::split_rel(rel).map_err(|e| format!("{}: {e}", path.display()))?;
    if r.path.join(rel) != path {
        return Err(format!("{}: path does not match its root and relative path", path.display()));
    }
    Ok(r)
}

/// The changeset's roots must be the config's `write:` roots, path for path, and every file inside its root.
fn check_roots(cs: &Value, files: &[File], write_roots: &[Root]) -> Result<(), String> {
    for r in cs["write_roots"].as_array().cloned().unwrap_or_default() {
        let (n, p) = (r["name"].as_str().unwrap_or(""), r["path"].as_str().unwrap_or(""));
        if !write_roots.iter().any(|w| w.name == n && w.path == Path::new(p)) {
            return Err(format!("root {n} ({p}) is not a write root in this config"));
        }
    }
    for f in files {
        root_for(write_roots, &f.root, &f.rel, &f.path)?;
    }
    Ok(())
}

/// A file's identity for drift checks: None when absent, else (content SHA-256, permission bits).
type Sig = Option<(String, u32)>;

fn sig(s: &State) -> Sig {
    match s {
        State::Absent => None,
        State::File { bytes, mode } => Some((sha(bytes), *mode)),
    }
}

/// Write a file atomically and make sure its directory entry is on disk (the error is reported, not dropped).
fn durable_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write(path, bytes, 0o600).map_err(|e| format!("{}: {e}", path.display()))?;
    sync_dir(path.parent().unwrap_or(Path::new(".")))
}

fn sync_dir(dir: &Path) -> Result<(), String> {
    std::fs::File::open(dir).and_then(|d| d.sync_all()).map_err(|e| format!("sync {}: {e}", dir.display()))
}

fn sign_record(dir: &Path, name: &str, sk: &SigningKey, record: &Value) -> Result<(), String> {
    durable_write(&dir.join(format!("{name}.json")), format!("{}\n", serde_json::to_string_pretty(record).unwrap_or_default()).as_bytes())?;
    durable_write(&dir.join(format!("{name}.attestation.json")), attest::sign_typed(sk, attest::CHANGE_PAYLOAD_TYPE, record).as_bytes())
}

fn remove_record(dir: &Path, name: &str) {
    let _ = std::fs::remove_file(dir.join(format!("{name}.attestation.json")));
    let _ = std::fs::remove_file(dir.join(format!("{name}.json")));
}

/// Read a signed change record by the signature, never by the plain copy.
fn signed_record(dir: &Path, name: &str, pk: &VerifyingKey) -> Result<Option<Value>, String> {
    let p = dir.join(format!("{name}.attestation.json"));
    if std::fs::symlink_metadata(&p).is_err() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&p).map_err(|e| format!("{name}: {e}"))?;
    let payload = attest::open_typed(&text, pk, attest::CHANGE_PAYLOAD_TYPE).map_err(|e| format!("{name}: {e}"))?;
    serde_json::from_slice(&payload).map(Some).map_err(|e| format!("{name}: {e}"))
}

/// The exclusive lock on a proposal folder, held for the whole of apply, rollback or recover. The kernel releases
/// it when the process ends, however it ends.
struct Lock(#[allow(dead_code)] std::fs::File);

fn lock(dir: &Path) -> Result<Lock, String> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(LOCK))
        .map_err(|e| format!("{LOCK}: {e}"))?;
    // SAFETY: a valid descriptor owned by `f`.
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let e = std::io::Error::last_os_error();
        return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
            "another change command is running on this proposal; nothing done".into()
        } else {
            format!("{LOCK}: {e}")
        });
    }
    Ok(Lock(f))
}

/// Locks for changing files in write roots, hierarchical so that they hold across configurations: an exclusive
/// flock on each write root, and a shared flock on every folder above it. A change in `/ws` (exclusive on `/ws`)
/// and one in `/ws/project` (shared on `/ws`, exclusive on `/ws/project`) therefore always conflict, whichever
/// configs name those roots; changes in unrelated roots only share locks and never conflict. Non-blocking: a
/// conflict is refused, never waited on, so there is no deadlock. The kernel releases every lock however the
/// process ends.
#[derive(Debug)]
struct RootLocks(#[allow(dead_code)] Vec<std::fs::File>);

fn flock_dir(path: &Path, op: libc::c_int) -> Result<std::fs::File, std::io::Error> {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    // SAFETY: a valid descriptor owned by `f`.
    if unsafe { libc::flock(f.as_raw_fd(), op | libc::LOCK_NB) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(f)
}

fn lock_roots(roots: &[&Root]) -> Result<RootLocks, String> {
    let mut sorted: Vec<&Root> = roots.to_vec();
    sorted.sort_by(|a, b| a.path.cmp(&b.path));
    sorted.dedup_by(|a, b| a.path == b.path);
    let busy = |e: &std::io::Error| e.raw_os_error() == Some(libc::EWOULDBLOCK);
    let mut held = Vec::new();
    let mut shared: HashSet<PathBuf> = HashSet::new();
    for r in &sorted {
        for a in r.path.ancestors().skip(1) {
            if !shared.insert(a.to_path_buf()) {
                continue;
            }
            match flock_dir(a, libc::LOCK_SH) {
                Ok(f) => held.push(f),
                Err(e) if busy(&e) => {
                    return Err(format!(
                        "another change is being applied in {} (a folder that contains write root {}); nothing done",
                        a.display(),
                        r.name
                    ))
                }
                Err(e) => return Err(format!("{}: lock: {e}", a.display())),
            }
        }
    }
    for r in sorted {
        match flock_dir(&r.path, libc::LOCK_EX) {
            Ok(f) => held.push(f),
            Err(e) if busy(&e) => {
                return Err(format!(
                    "another change is being applied in write root {} ({}) or a folder inside it; nothing done",
                    r.name,
                    r.path.display()
                ))
            }
            Err(e) => return Err(format!("write root {} ({}): lock: {e}", r.name, r.path.display())),
        }
    }
    Ok(RootLocks(held))
}

/// Sync every directory in the tree under `top` (deepest first), then `top` and the folder that holds it. Run
/// once after the last file and folder in the tree is created, so every directory entry in it is on disk.
fn sync_tree(top: &Path) -> Result<(), String> {
    let mut dirs = vec![top.to_path_buf()];
    let mut i = 0;
    while i < dirs.len() {
        for e in std::fs::read_dir(&dirs[i]).map_err(|e| format!("{}: {e}", dirs[i].display()))? {
            let e = e.map_err(|e| e.to_string())?;
            if e.file_type().map_err(|e| e.to_string())?.is_dir() {
                dirs.push(e.path());
            }
        }
        i += 1;
    }
    for d in dirs.iter().rev() {
        sync_dir(d)?;
    }
    sync_dir(top.parent().unwrap_or(Path::new(".")))
}

fn journal_present(dir: &Path) -> bool {
    std::fs::symlink_metadata(dir.join(JOURNAL)).is_ok()
}

/// The journal, by its signature: it must be signed by this key, and name this proposal's changeset.
fn read_journal(dir: &Path, pk: &VerifyingKey, changeset_digest: &str) -> Result<Value, String> {
    let text = std::fs::read_to_string(dir.join(JOURNAL)).map_err(|e| format!("{JOURNAL}: {e}"))?;
    let payload = attest::open_typed(&text, pk, JOURNAL_PAYLOAD_TYPE).map_err(|e| format!("{JOURNAL}: not signed by this config's key ({e})"))?;
    let j: Value = serde_json::from_slice(&payload).map_err(|e| format!("{JOURNAL}: {e}"))?;
    if j["schema"].as_str() != Some(JOURNAL_SCHEMA) {
        return Err(format!("{JOURNAL}: unknown schema"));
    }
    if j["changeset_sha256"].as_str() != Some(changeset_digest) {
        return Err(format!("{JOURNAL}: signed for another changeset"));
    }
    Ok(j)
}

fn refuse_if_interrupted(dir: &Path) -> Result<(), String> {
    if journal_present(dir) {
        return Err(format!("an interrupted apply or rollback was found ({JOURNAL}); run `change recover` first"));
    }
    Ok(())
}

fn remove_journal(dir: &Path) -> Result<(), String> {
    std::fs::remove_file(dir.join(JOURNAL)).map_err(|e| format!("{JOURNAL}: {e}"))?;
    sync_dir(dir)
}

/// Where a transaction keeps the copy of a file's "from" content: apply backs up into `backup/`; for rollback,
/// the applied content is the proposal's own file in `files/`. Always derived, never read from the journal.
fn copy_path(dir: &Path, action: &str, root: &str, rel: &str) -> PathBuf {
    dir.join(if action == "apply" { "backup" } else { "files" }).join(root).join(rel)
}

/// One file in a transaction: move it from `from` to `to`. A `from` file can be put back from `from_copy`.
struct Step {
    root: String,
    rel: String,
    path: PathBuf,
    dir: Dir,
    name: String,
    from: Sig,
    from_copy: PathBuf,
    /// Content and mode after the step: None removes the file.
    to: Option<(Vec<u8>, u32)>,
}

impl Step {
    fn to_sig(&self) -> Sig {
        self.to.as_ref().map(|(b, m)| (sha(b), *m))
    }

    fn current(&self) -> Result<Sig, String> {
        self.dir.read(&self.name).map(|s| sig(&s)).map_err(|e| format!("{}: {e}", self.path.display()))
    }

    fn journal_entry(&self) -> Value {
        let to = self.to_sig();
        json!({
            "root": self.root, "rel": self.rel,
            "from_sha256": self.from.as_ref().map(|f| f.0.clone()), "from_mode": self.from.as_ref().map(|f| mode_str(f.1)),
            "to_sha256": to.as_ref().map(|t| t.0.clone()), "to_mode": to.as_ref().map(|t| mode_str(t.1)),
        })
    }

    /// Re-check the file is still exactly `from` (content and mode), then move it to `to`.
    fn commit(&self) -> Result<(), String> {
        if self.current()? != self.from {
            return Err(format!("{} changed while the transaction ran", self.path.display()));
        }
        match &self.to {
            Some((bytes, mode)) => self.dir.replace(&self.name, bytes, *mode),
            None => self.dir.remove(&self.name),
        }
        .map_err(|e| format!("writing {}: {e}", self.path.display()))
    }

    /// The bytes to put back, read from the copy and checked. Called before anything is changed.
    fn from_bytes(&self) -> Result<Option<Vec<u8>>, String> {
        let Some((want, _)) = &self.from else {
            return Ok(None);
        };
        let b = std::fs::read(&self.from_copy).map_err(|e| format!("the saved copy {}: {e}", self.from_copy.display()))?;
        if sha(&b) != *want {
            return Err(format!("the saved copy {} does not match", self.from_copy.display()));
        }
        Ok(Some(b))
    }

    /// Put `from` back (with the bytes checked beforehand).
    fn put_back(&self, bytes: Option<&[u8]>) -> Result<(), String> {
        match (&self.from, bytes) {
            (None, _) => self.dir.remove(&self.name),
            (Some((_, mode)), Some(b)) => self.dir.replace(&self.name, b, *mode),
            (Some(_), None) => Err("no saved copy".into()),
        }
        .map_err(|e| format!("restoring {}: {e}", self.path.display()))
    }
}

/// What a set of steps needs to be put back: per step, Ok(None) if it already holds `from`, Ok(Some(bytes)) if it
/// holds `to` and its copy checks out, Err for anything else. Nothing is changed.
fn plan_restore(steps: &[&Step]) -> Vec<Result<Option<Option<Vec<u8>>>, String>> {
    steps
        .iter()
        .map(|s| {
            let cur = s.current()?;
            if cur == s.from {
                Ok(None)
            } else if cur == s.to_sig() {
                s.from_bytes().map(Some)
            } else {
                Err(format!("{} holds neither the old nor the new content; left as it is", s.path.display()))
            }
        })
        .collect()
}

/// Restore the given steps: every copy is checked first; if any check fails nothing is changed.
fn restore_all(steps: &[&Step]) -> Result<(), String> {
    let plan = plan_restore(steps);
    let errors: Vec<String> = plan.iter().filter_map(|p| p.as_ref().err().cloned()).collect();
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    let mut errors = Vec::new();
    for (s, p) in steps.iter().zip(plan) {
        if let Ok(Some(bytes)) = p {
            if let Err(e) = s.put_back(bytes.as_deref()) {
                errors.push(e);
            }
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

/// Run a transaction: signed journal, `prepare` (e.g. write backups), commit each step, read every file back,
/// `finish` (sign the record), remove the journal. On any failure after the journal, put back what was written.
#[allow(clippy::too_many_arguments)]
fn transact(
    dir: &Path,
    sk: &SigningKey,
    action: &str,
    digest: &str,
    steps: &[Step],
    prepare: impl FnOnce() -> Result<(), String>,
    finish: impl FnOnce() -> Result<(), String>,
    on_restored: impl FnOnce(),
) -> Result<(), String> {
    let j = json!({
        "schema": JOURNAL_SCHEMA, "action": action, "changeset_sha256": digest, "started_at": now_rfc3339(),
        "files": steps.iter().map(Step::journal_entry).collect::<Vec<_>>(),
    });
    durable_write(&dir.join(JOURNAL), attest::sign_typed(sk, JOURNAL_PAYLOAD_TYPE, &j).as_bytes())
        .map_err(|e| format!("{JOURNAL}: {e}; nothing written"))?;
    // How many steps committed; a failure inside commit() leaves the failing step at index `committed`.
    let mut committed = 0usize;
    let failure = (|| -> Result<(), String> {
        prepare()?;
        for s in steps {
            s.commit()?;
            committed += 1;
        }
        for s in steps {
            if s.current()? != s.to_sig() {
                return Err(format!("{} does not have the expected content and mode after writing", s.path.display()));
            }
        }
        finish()
    })()
    .err();
    let Some(why) = failure else {
        return remove_journal(dir);
    };
    // Put back what this process wrote: every committed step, and the failing step only if it does hold the new
    // content (an atomic replace either happened or not). Steps never reached were not touched.
    let mut written: Vec<&Step> = steps[..committed].iter().collect();
    if let Some(s) = steps.get(committed) {
        if s.current().ok() == Some(s.to_sig()) {
            written.push(s);
        }
    }
    match restore_all(&written) {
        Ok(()) => {
            remove_record(dir, action);
            on_restored();
            remove_journal(dir)?;
            Err(format!("{why}; every file was put back, nothing is changed"))
        }
        Err(e) => Err(format!("{why}; RESTORE INCOMPLETE ({e}): {JOURNAL} is kept, run `change recover`")),
    }
}

fn record(action: &str, digest: &str, run_id: &Value, files: Vec<Value>) -> Value {
    json!({
        "schema": RECORD_SCHEMA, "action": action, "changeset_sha256": digest, "run_id": run_id,
        "files": files, "at": now_rfc3339(), "harness": {"name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION")}
    })
}

fn record_entry(s: &Step, change: Option<&str>) -> Value {
    let to = s.to_sig();
    let mut v = json!({
        "root": s.root, "rel": s.rel, "path": s.path.display().to_string(),
        "before_sha256": s.from.as_ref().map(|f| f.0.clone()), "before_mode": s.from.as_ref().map(|f| mode_str(f.1)),
        "after_sha256": to.as_ref().map(|t| t.0.clone()), "after_mode": to.as_ref().map(|t| mode_str(t.1)),
    });
    if let Some(c) = change {
        v["change"] = json!(c);
    }
    v
}

pub fn apply(dir: &Path, sk: &SigningKey, write_roots: &[Root], deny_extra: &[String], approve: &str) -> Result<String, String> {
    let pk = sk.verifying_key();
    let approve = approve.trim().to_ascii_lowercase();
    if approve.len() < 16 || !approve.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("--approve needs at least the first 16 hex characters of the changeset's SHA-256".into());
    }
    let _lock = lock(dir)?;
    refuse_if_interrupted(dir)?;
    if signed_record(dir, "apply", &pk)?.is_some() {
        return Err("this changeset was already applied (signed apply record exists)".into());
    }
    let backup = dir.join("backup");
    if backup.exists() {
        return Err("a backup folder from an earlier attempt exists; nothing written (move it aside to apply again)".into());
    }
    let (cs, digest, files) = load_changeset(dir)?;
    if !digest.starts_with(&approve) {
        return Err(format!("the approval {approve} does not match this changeset ({}…); review changeset.diff and approve the digest you reviewed", &digest[..16]));
    }
    let run = verify_run(dir, &pk)?;
    check_roots(&cs, &files, write_roots)?;
    let _roots = lock_roots(&files.iter().map(|f| root_for(write_roots, &f.root, &f.rel, &f.path)).collect::<Result<Vec<_>, _>>()?)?;
    let policy = RootPolicy::new(write_roots.to_vec(), deny_extra.to_vec());
    // Validate everything before the first change: drift (content and mode), every proposed file present and intact.
    let mut steps = Vec::new();
    let mut current = Vec::new();
    let mut drift = Vec::new();
    for f in &files {
        let root = root_for(write_roots, &f.root, &f.rel, &f.path)?;
        if let Some(why) = policy.deny_reason(&f.path, root) {
            return Err(format!("{}: {why}", f.path.display()));
        }
        let (d, name) = Dir::parent_of(&root.path, &f.rel).map_err(|e| format!("{}: {e}", f.path.display()))?;
        let cur = d.read(&name).map_err(|e| format!("{}: {e}", f.path.display()))?;
        match (&f.base, sig(&cur)) {
            (None, None) => {}
            (Some(b), Some((c, m))) if *b == c && m == f.mode => {}
            (Some(b), Some((c, m))) if *b == c => drift.push(format!("{} permissions changed since the proposal ({:o} -> {:o})", f.path.display(), f.mode, m)),
            (None, Some(_)) => drift.push(format!("{} now exists", f.path.display())),
            (Some(_), None) => drift.push(format!("{} was removed", f.path.display())),
            (Some(_), Some(_)) => drift.push(format!("{} changed since the proposal", f.path.display())),
        }
        let new = std::fs::read(dir.join("files").join(&f.root).join(&f.rel))
            .ok()
            .filter(|b| sha(b) == f.new)
            .ok_or_else(|| format!("proposal file for {} is missing or changed; nothing written", f.path.display()))?;
        steps.push(Step {
            root: f.root.clone(),
            rel: f.rel.clone(),
            path: f.path.clone(),
            dir: d,
            name,
            from: sig(&cur),
            from_copy: copy_path(dir, "apply", &f.root, &f.rel),
            to: Some((new, f.mode)),
        });
        current.push(cur);
    }
    if !drift.is_empty() {
        return Err(format!("drift, nothing written: {}", drift.join("; ")));
    }
    let out: Vec<Value> = files.iter().zip(&steps).map(|(f, s)| record_entry(s, Some(&f.change))).collect();
    // Every backup, and every directory entry leading to it, is on disk before the first file is replaced: the
    // files are synced as they are written, then the whole backup tree is synced once all of it exists.
    let backups = || -> Result<(), String> {
        std::fs::create_dir(&backup).map_err(|e| format!("backup: {e}"))?;
        for (s, cur) in steps.iter().zip(&current) {
            if let State::File { bytes, mode } = cur {
                let parent = s.from_copy.parent().unwrap_or(&backup);
                std::fs::create_dir_all(parent).map_err(|e| format!("backup: {e}"))?;
                atomic_write(&s.from_copy, bytes, *mode).map_err(|e| format!("backup {}: {e}", s.from_copy.display()))?;
            }
        }
        sync_tree(&backup)
    };
    let rec = record("apply", &digest, &run["run_id"], out);
    transact(dir, sk, "apply", &digest, &steps, backups, || sign_record(dir, "apply", sk, &rec), || {
        let _ = std::fs::rename(&backup, dir.join(format!("backup-failed-{}", std::process::id())));
    })?;
    Ok(format!("CHANGE_APPLY OK files={} changeset={}", files.len(), &digest[..16]))
}

pub fn rollback(dir: &Path, sk: &SigningKey, write_roots: &[Root], deny_extra: &[String]) -> Result<String, String> {
    let pk = sk.verifying_key();
    let _lock = lock(dir)?;
    refuse_if_interrupted(dir)?;
    let rec = signed_record(dir, "apply", &pk)?.ok_or("nothing to roll back: no signed apply record")?;
    if signed_record(dir, "rollback", &pk)?.is_some() {
        return Err("this changeset was already rolled back".into());
    }
    let digest = rec["changeset_sha256"].as_str().unwrap_or("").to_string();
    let rec_files = rec["files"].as_array().cloned().unwrap_or_default();
    let _roots = lock_roots(
        &rec_files
            .iter()
            .map(|f| root_for(write_roots, f["root"].as_str().unwrap_or(""), f["rel"].as_str().unwrap_or(""), Path::new(f["path"].as_str().unwrap_or(""))))
            .collect::<Result<Vec<_>, _>>()?,
    )?;
    // The current deny list applies to rollback as to apply and recover: a file that became deny-listed after
    // apply is not touched by any change command.
    let policy = RootPolicy::new(write_roots.to_vec(), deny_extra.to_vec());
    // Validate everything before the first change: every file still as apply left it (content and mode), every
    // backup present and intact, and every applied file's copy intact so an interrupted rollback can be undone.
    let mut steps = Vec::new();
    let mut moved = Vec::new();
    for f in rec_files {
        let (root, rel) = (f["root"].as_str().unwrap_or(""), f["rel"].as_str().unwrap_or(""));
        let path = PathBuf::from(f["path"].as_str().unwrap_or(""));
        let r = root_for(write_roots, root, rel, &path)?;
        if let Some(why) = policy.deny_reason(&path, r) {
            return Err(format!("{}: {why}; nothing restored", path.display()));
        }
        let (d, name) = Dir::parent_of(&r.path, rel).map_err(|e| format!("{}: {e}", path.display()))?;
        let after = (f["after_sha256"].as_str().unwrap_or("").to_string(), parse_mode(&f["after_mode"]).ok_or("apply record without after_mode")?);
        let cur = sig(&d.read(&name).map_err(|e| format!("{}: {e}", path.display()))?);
        if cur.as_ref() != Some(&after) {
            moved.push(path.display().to_string());
            continue;
        }
        let applied_copy = copy_path(dir, "rollback", root, rel);
        if std::fs::read(&applied_copy).map(|b| sha(&b)).ok().as_deref() != Some(after.0.as_str()) {
            return Err(format!("the proposal file for {} is missing or changed; nothing restored", path.display()));
        }
        let to = match f["before_sha256"].as_str() {
            None => None,
            Some(want) => {
                let b = copy_path(dir, "apply", root, rel);
                let bytes = std::fs::read(&b).map_err(|e| format!("backup {}: {e}; nothing restored", b.display()))?;
                if sha(&bytes) != want {
                    return Err(format!("backup of {} does not match the apply record; nothing restored", path.display()));
                }
                let m = parse_mode(&f["before_mode"]).unwrap_or_else(|| std::fs::metadata(&b).map(|m| m.mode() & 0o777).unwrap_or(0o644));
                Some((bytes, m))
            }
        };
        steps.push(Step { root: root.into(), rel: rel.into(), path, dir: d, name, from: Some(after), from_copy: applied_copy, to });
    }
    if !moved.is_empty() {
        return Err(format!("changed since apply, nothing restored: {}", moved.join("; ")));
    }
    let out: Vec<Value> = steps.iter().map(|s| record_entry(s, None)).collect();
    let rr = record("rollback", &digest, &rec["run_id"], out);
    transact(dir, sk, "rollback", &digest, &steps, || Ok(()), || sign_record(dir, "rollback", sk, &rr), || {})?;
    Ok(format!("CHANGE_ROLLBACK OK files={}", steps.len()))
}

/// `change recover`: finish undoing an apply or rollback that was interrupted (its signed journal is still there).
pub fn recover(dir: &Path, sk: &SigningKey, write_roots: &[Root], deny_extra: &[String]) -> Result<String, String> {
    let pk = sk.verifying_key();
    let _lock = lock(dir)?;
    if !journal_present(dir) {
        return Err("nothing to recover: no journal (no interrupted apply or rollback)".into());
    }
    let (cs, digest, files) = load_changeset(dir)?;
    let j = read_journal(dir, &pk, &digest)?;
    // The config's write roots must be the changeset's, path for path, before anything is planned.
    check_roots(&cs, &files, write_roots).map_err(|e| format!("{e}; nothing changed"))?;
    let action = j["action"].as_str().unwrap_or("").to_string();
    if action != "apply" && action != "rollback" {
        return Err(format!("{JOURNAL}: unknown action {action:?}"));
    }
    // The transaction finished (its signed record exists) and only the journal's removal was lost.
    if signed_record(dir, &action, &pk)?.is_some_and(|r| r["changeset_sha256"].as_str() == Some(digest.as_str())) {
        remove_journal(dir)?;
        return Ok(format!("CHANGE_RECOVER OK the {action} had completed (signed record present); journal removed"));
    }
    // Only files of this changeset, in this config's write roots, not deny-listed; copies at derived places.
    let in_changeset: std::collections::HashMap<(String, String), PathBuf> =
        files.iter().map(|f| ((f.root.clone(), f.rel.clone()), f.path.clone())).collect();
    let policy = RootPolicy::new(write_roots.to_vec(), deny_extra.to_vec());
    let mut steps = Vec::new();
    for f in j["files"].as_array().cloned().unwrap_or_default() {
        let (root, rel) = (f["root"].as_str().unwrap_or("").to_string(), f["rel"].as_str().unwrap_or("").to_string());
        // The target is the absolute path the signed changeset names, and the config must map the root there.
        let path = in_changeset
            .get(&(root.clone(), rel.clone()))
            .cloned()
            .ok_or_else(|| format!("{JOURNAL}: {root}/{rel} is not in this changeset; nothing changed"))?;
        let r = root_for(write_roots, &root, &rel, &path).map_err(|e| format!("{e}; nothing changed"))?;
        if let Some(why) = policy.deny_reason(&path, r) {
            return Err(format!("{}: {why}; nothing changed", path.display()));
        }
        let (d, name) = Dir::parent_of(&r.path, &rel).map_err(|e| format!("{}: {e}", path.display()))?;
        let from = match (f["from_sha256"].as_str(), parse_mode(&f["from_mode"])) {
            (Some(s), Some(m)) => Some((s.to_string(), m)),
            _ => None,
        };
        let to = match (f["to_sha256"].as_str(), parse_mode(&f["to_mode"])) {
            (Some(s), Some(m)) => Some((s.to_string(), m)),
            _ => None,
        };
        steps.push((Step { from_copy: copy_path(dir, &action, &root, &rel), root, rel, path, dir: d, name, from, to: None }, to));
    }
    let roots_touched: Vec<&Root> = steps.iter().filter_map(|(s, _)| write_roots.iter().find(|w| w.name == s.root)).collect();
    let _roots = lock_roots(&roots_touched)?;
    // Plan every file before changing any: unchanged, put back (copy checked now), or a conflict.
    let mut plan = Vec::new();
    let mut errors = Vec::new();
    for (s, to) in &steps {
        let r = s.current().and_then(|cur| {
            if cur == s.from {
                Ok(None)
            } else if cur == *to {
                s.from_bytes().map(Some)
            } else {
                Err(format!("{} holds neither the old nor the new content; left as it is", s.path.display()))
            }
        });
        match r {
            Ok(p) => plan.push(p),
            Err(e) => errors.push(e),
        }
    }
    if !errors.is_empty() {
        return Err(format!("{}; nothing changed, {JOURNAL} is kept", errors.join("; ")));
    }
    // Preflight cleanup before restoring any target. An unverified name or enumeration
    // failure must not trigger even a partial recovery; the journal is left for retry.
    // No signed transaction identity is encoded in the legacy `.hercules-apply-<pid>-<hex>`
    // temp names. Even a regular file with the correct pattern may belong to somebody else.
    // Never unlink by pattern. Enumerate each changeset folder and fail closed if any unverified
    // candidate is present, or if enumeration fails. In either case keep the signed journal and
    // do not sign successful recovery; after inspecting the candidates the operator can retry.
    let mut seen = HashSet::new();
    for (s, _) in &steps {
        let folder = (s.root.clone(), Path::new(&s.rel).parent().map(|p| p.to_path_buf()).unwrap_or_default());
        if seen.insert(folder) {
            let candidates = s.dir.unverified_temp_candidates()
                .map_err(|e| format!("{}: {e}; {JOURNAL} is kept, run `change recover` again", s.path.display()))?;
            if !candidates.is_empty() {
                return Err(format!("{}: {} unverified temp candidate(s) [{}]; none removed; {JOURNAL} is kept for inspection and retry",
                    s.path.display(), candidates.len(), candidates.join(", ")));
            }
        }
    }
    let mut out = Vec::new();
    for ((s, _), p) in steps.iter().zip(plan) {
        let what = match p {
            None => "unchanged",
            Some(bytes) => {
                s.put_back(bytes.as_deref()).map_err(|e| format!("{e}; {JOURNAL} is kept, run `change recover` again"))?;
                "put back"
            }
        };
        out.push(json!({"root": s.root, "rel": s.rel, "path": s.path.display().to_string(), "result": what,
                        "sha256": s.from.as_ref().map(|f| f.0.clone()), "mode": s.from.as_ref().map(|f| mode_str(f.1))}));
    }
    remove_record(dir, &action);
    if action == "apply" {
        let backup = dir.join("backup");
        if backup.exists() {
            let _ = std::fs::rename(&backup, dir.join(format!("backup-recovered-{}", std::process::id())));
        }
    }
    let rec = json!({
        "schema": RECORD_SCHEMA, "action": "recover", "interrupted": action, "changeset_sha256": digest,
        "files": out, "temp_files_removed": 0, "at": now_rfc3339(), "harness": {"name": env!("CARGO_PKG_NAME"), "version": env!("CARGO_PKG_VERSION")}
    });
    sign_record(dir, "recover", sk, &rec)?;
    remove_journal(dir)?;
    Ok(format!("CHANGE_RECOVER OK the interrupted {action} was undone, files={}", steps.len()))
}

/// `change verify`: the proposal's run (with its changeset), then the apply, rollback and recover records if present.
pub fn verify(dir: &Path, pk: &VerifyingKey) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut ok = true;
    match verify_run(dir, pk) {
        Ok(_) => lines.push("CHANGE_VERIFY run MATCH (signed run, changeset and proposed files)".to_string()),
        Err(e) => {
            ok = false;
            lines.push(format!("CHANGE_VERIFY run MISMATCH {e}"));
        }
    }
    let digest = std::fs::read(dir.join("changeset.json")).map(|b| sha(&b)).unwrap_or_default();
    if journal_present(dir) {
        ok = false;
        match read_journal(dir, pk, &digest) {
            Ok(j) => lines.push(format!("CHANGE_VERIFY INTERRUPTED {}: run `change recover`", j["action"].as_str().unwrap_or("?"))),
            Err(e) => lines.push(format!("CHANGE_VERIFY INTERRUPTED journal does not verify: {e}")),
        }
    }
    for name in ["apply", "rollback", "recover"] {
        match signed_record(dir, name, pk) {
            Ok(None) => {
                if name != "recover" {
                    lines.push(format!("CHANGE_VERIFY {name} none"));
                }
            }
            Ok(Some(r)) if r["changeset_sha256"].as_str() == Some(digest.as_str()) => {
                // The plain copy is for people to read; it must say what the signed record says.
                let plain: Option<Value> = std::fs::read_to_string(dir.join(format!("{name}.json"))).ok().and_then(|t| serde_json::from_str(&t).ok());
                if plain.as_ref() != Some(&r) {
                    ok = false;
                    lines.push(format!("CHANGE_VERIFY {name} MISMATCH the plain copy {name}.json is missing or differs from the signed record"));
                } else {
                    lines.push(format!("CHANGE_VERIFY {name} MATCH files={} at={}", r["files"].as_array().map(Vec::len).unwrap_or(0), r["at"].as_str().unwrap_or("?")))
                }
            }
            Ok(Some(_)) => {
                ok = false;
                lines.push(format!("CHANGE_VERIFY {name} MISMATCH signed for another changeset"));
            }
            Err(e) => {
                ok = false;
                lines.push(format!("CHANGE_VERIFY {name} MISMATCH {e}"));
            }
        }
    }
    (lines, ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u8) -> SigningKey {
        SigningKey::from_bytes(&[n; 32])
    }

    fn mode_of(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().mode() & 0o777
    }

    /// A root with a.txt ("old a") and sub/, and a proposal folder whose changeset lists a.txt, sub/b.txt and .env.
    fn setup(name: &str) -> (PathBuf, PathBuf, PathBuf, String) {
        let base = std::env::temp_dir().join(format!("hercules-apply-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let (root, prop) = (base.join("root"), base.join("prop"));
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(prop.join("backup/r")).unwrap();
        let root = std::fs::canonicalize(root).unwrap();
        std::fs::write(root.join("a.txt"), "old a").unwrap();
        std::fs::write(prop.join("backup/r/a.txt"), "old a").unwrap();
        std::fs::set_permissions(root.join("a.txt"), std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
        let cs = json!({"schema": crate::proposal::CHANGESET_SCHEMA, "files": [
            {"root": "r", "rel": "a.txt", "path": root.join("a.txt").display().to_string(), "base_sha256": sha(b"old a"), "new_sha256": sha(b"new a"), "mode": "644"},
            {"root": "r", "rel": "sub/b.txt", "path": root.join("sub/b.txt").display().to_string(), "base_sha256": null, "new_sha256": sha(b"new b"), "mode": "644"},
            {"root": "r", "rel": ".env", "path": root.join(".env").display().to_string(), "base_sha256": null, "new_sha256": sha(b"x"), "mode": "644"}]});
        let text = serde_json::to_vec(&cs).unwrap();
        std::fs::write(prop.join("changeset.json"), &text).unwrap();
        (base, root, prop, sha(&text))
    }

    fn steps(root: &Path, prop: &Path) -> Vec<Step> {
        let (da, na) = Dir::parent_of(root, "a.txt").unwrap();
        let (db, nb) = Dir::parent_of(root, "sub/b.txt").unwrap();
        vec![
            Step { root: "r".into(), rel: "a.txt".into(), path: root.join("a.txt"), dir: da, name: na,
                   from: Some((sha(b"old a"), 0o644)), from_copy: copy_path(prop, "apply", "r", "a.txt"), to: Some((b"new a".to_vec(), 0o644)) },
            Step { root: "r".into(), rel: "sub/b.txt".into(), path: root.join("sub/b.txt"), dir: db, name: nb,
                   from: None, from_copy: copy_path(prop, "apply", "r", "sub/b.txt"), to: Some((b"new b".to_vec(), 0o644)) },
        ]
    }

    fn roots(root: &Path) -> Vec<Root> {
        vec![Root { name: "r".into(), path: root.to_path_buf() }]
    }

    /// The state a crash leaves after the journal and the first replacement: a signed journal, a.txt replaced.
    fn crash_after_first_write(prop: &Path, root: &Path, digest: &str, signer: &SigningKey, extra: Option<Value>) {
        let mut files = vec![
            json!({"root": "r", "rel": "a.txt", "from_sha256": sha(b"old a"), "from_mode": "644", "to_sha256": sha(b"new a"), "to_mode": "644"}),
            json!({"root": "r", "rel": "sub/b.txt", "from_sha256": null, "from_mode": null, "to_sha256": sha(b"new b"), "to_mode": "644"}),
        ];
        files.extend(extra);
        let j = json!({"schema": JOURNAL_SCHEMA, "action": "apply", "changeset_sha256": digest, "started_at": "t", "files": files});
        std::fs::write(prop.join(JOURNAL), attest::sign_typed(signer, JOURNAL_PAYLOAD_TYPE, &j)).unwrap();
        std::fs::write(root.join("a.txt"), "new a").unwrap();
    }

    #[test]
    fn a_failure_after_writing_puts_every_file_back() {
        let (base, root, prop, digest) = setup("finish");
        let s = steps(&root, &prop);
        let r = transact(&prop, &key(7), "apply", &digest, &s, || Ok(()), || Err("signing failed".into()), || {});
        assert!(r.unwrap_err().contains("every file was put back"));
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "old a");
        assert!(!root.join("sub/b.txt").exists());
        assert!(!prop.join(JOURNAL).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_file_changed_mid_transaction_stops_it_and_the_rest_is_put_back() {
        let (base, root, prop, digest) = setup("midway");
        let s = steps(&root, &prop);
        std::fs::write(root.join("sub/b.txt"), "someone else").unwrap();
        let r = transact(&prop, &key(7), "apply", &digest, &s, || Ok(()), || Ok(()), || {});
        assert!(r.unwrap_err().contains("changed while the transaction ran"));
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "old a");
        assert_eq!(std::fs::read_to_string(root.join("sub/b.txt")).unwrap(), "someone else");
        assert!(!prop.join(JOURNAL).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_restore_whose_copy_is_bad_changes_nothing_and_keeps_the_journal() {
        let (base, root, prop, digest) = setup("stuck");
        let s = steps(&root, &prop);
        let r = transact(&prop, &key(7), "apply", &digest, &s,
                         || std::fs::write(prop.join("backup/r/a.txt"), "damaged").map_err(|e| e.to_string()),
                         || Err("signing failed".into()), || {});
        let e = r.unwrap_err();
        assert!(e.contains("RESTORE INCOMPLETE") && e.contains("change recover"), "{e}");
        assert!(prop.join(JOURNAL).exists());
        // Planned first: nothing was put back, not even b.txt, whose restore needed no copy.
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "new a");
        assert!(root.join("sub/b.txt").exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn recover_undoes_an_interrupted_apply_from_a_signed_journal() {
        let (base, root, prop, digest) = setup("recover");
        crash_after_first_write(&prop, &root, &digest, &key(7), None);
        let out = recover(&prop, &key(7), &roots(&root), &[]).unwrap();
        assert!(out.starts_with("CHANGE_RECOVER OK"), "{out}");
        let rec = signed_record(&prop, "recover", &key(7).verifying_key()).unwrap().unwrap();
        assert_eq!(rec["temp_files_removed"], 0);
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "old a");
        assert_eq!(mode_of(&root.join("a.txt")), 0o644);
        assert!(!prop.join(JOURNAL).exists());
        assert!(signed_record(&prop, "recover", &key(7).verifying_key()).unwrap().is_some());
        assert!(recover(&prop, &key(7), &roots(&root), &[]).unwrap_err().contains("nothing to recover"));
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn recover_preserves_unverified_pattern_file_and_signed_journal() {
        let (base, root, prop, digest) = setup("unowned-temp");
        crash_after_first_write(&prop, &root, &digest, &key(7), None);
        // A plausible name does not identify its creator or the interrupted transaction.
        let unrelated = root.join(".hercules-apply-99-0123456789abcdef");
        std::fs::write(&unrelated, "somebody else's file").unwrap();
        let e = recover(&prop, &key(7), &roots(&root), &[]).unwrap_err();
        assert!(e.contains("unverified temp") && e.contains("journal") && e.contains("none removed"), "{e}");
        assert_eq!(std::fs::read_to_string(&unrelated).unwrap(), "somebody else's file");
        assert!(prop.join(JOURNAL).exists(), "recoverable journal lost on refused cleanup");
        assert!(signed_record(&prop, "recover", &key(7).verifying_key()).unwrap().is_none());
        // The owner can investigate and separately remove the candidate; only then retry.
        std::fs::remove_file(&unrelated).unwrap();
        assert!(recover(&prop, &key(7), &roots(&root), &[]).unwrap().starts_with("CHANGE_RECOVER OK"));
        assert!(!prop.join(JOURNAL).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn recover_readdir_failure_preserves_journal_and_allows_retry() {
        struct InjectionReset;
        impl Drop for InjectionReset {
            fn drop(&mut self) { crate::anchored::inject_readdir_error_for_test(false); }
        }
        let (base, root, prop, digest) = setup("read-error");
        crash_after_first_write(&prop, &root, &digest, &key(7), None);
        crate::anchored::inject_readdir_error_for_test(true);
        let reset = InjectionReset;
        let e = recover(&prop, &key(7), &roots(&root), &[]).unwrap_err();
        drop(reset);
        assert!(e.contains("listing transaction temp candidates") && e.contains("journal"), "{e}");
        assert!(prop.join(JOURNAL).exists(), "journal lost on directory read error");
        assert!(signed_record(&prop, "recover", &key(7).verifying_key()).unwrap().is_none());
        assert!(recover(&prop, &key(7), &roots(&root), &[]).unwrap().starts_with("CHANGE_RECOVER OK"));
        assert!(!prop.join(JOURNAL).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn recover_refuses_a_journal_it_cannot_trust() {
        // Signed by another key.
        let (base, root, prop, digest) = setup("forged");
        crash_after_first_write(&prop, &root, &digest, &key(9), None);
        assert!(recover(&prop, &key(7), &roots(&root), &[]).unwrap_err().contains("not signed by this config's key"));
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "new a");
        // Signed for another changeset.
        crash_after_first_write(&prop, &root, &sha(b"other"), &key(7), None);
        assert!(recover(&prop, &key(7), &roots(&root), &[]).unwrap_err().contains("another changeset"));
        // A file that is not in the changeset.
        let stray = json!({"root": "r", "rel": "elsewhere.txt", "from_sha256": null, "from_mode": null, "to_sha256": sha(b"x"), "to_mode": "644"});
        crash_after_first_write(&prop, &root, &digest, &key(7), Some(stray));
        assert!(recover(&prop, &key(7), &roots(&root), &[]).unwrap_err().contains("not in this changeset"));
        // A deny-listed file, even though the changeset lists it.
        let env = json!({"root": "r", "rel": ".env", "from_sha256": null, "from_mode": null, "to_sha256": sha(b"x"), "to_mode": "644"});
        crash_after_first_write(&prop, &root, &digest, &key(7), Some(env));
        assert!(recover(&prop, &key(7), &roots(&root), &[]).unwrap_err().contains("nothing changed"));
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "new a");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn recover_checks_every_copy_before_changing_anything() {
        let (base, root, prop, digest) = setup("precheck");
        crash_after_first_write(&prop, &root, &digest, &key(7), None);
        // b.txt was also written (no copy needed: it was absent before), but a.txt's backup is gone.
        std::fs::write(root.join("sub/b.txt"), "new b").unwrap();
        std::fs::remove_file(prop.join("backup/r/a.txt")).unwrap();
        let e = recover(&prop, &key(7), &roots(&root), &[]).unwrap_err();
        assert!(e.contains("nothing changed") && e.contains("saved copy"), "{e}");
        assert!(root.join("sub/b.txt").exists(), "b.txt was removed although the recovery could not finish");
        assert!(prop.join(JOURNAL).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn one_change_at_a_time_in_a_write_root_across_proposals() {
        let (base, root, prop, digest) = setup("rootlock");
        crash_after_first_write(&prop, &root, &digest, &key(7), None);
        // Another proposal's command holds the write root (flock on the root directory).
        let r = roots(&root);
        let held = lock_roots(&[&r[0]]).unwrap();
        assert!(lock_roots(&[&r[0]]).is_err(), "a second lock on the same write root must be refused");
        let e = recover(&prop, &key(7), &r, &[]).unwrap_err();
        assert!(e.contains("another change is being applied in write root"), "{e}");
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "new a");
        drop(held);
        assert!(recover(&prop, &key(7), &r, &[]).is_ok());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn sync_tree_covers_every_folder_created_in_the_backup() {
        let base = std::env::temp_dir().join(format!("hercules-apply-synctree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let b = base.join("backup");
        std::fs::create_dir_all(b.join("r/alpha")).unwrap();
        std::fs::write(b.join("r/alpha/first.txt"), "1").unwrap();
        std::fs::create_dir_all(b.join("r/beta/deeper")).unwrap();
        std::fs::write(b.join("r/beta/deeper/second.txt"), "2").unwrap();
        // Every folder is listed by the walk sync_tree uses (fsync itself cannot be observed in a test).
        assert!(sync_tree(&b).is_ok());
        let mut seen = vec![b.clone()];
        let mut i = 0;
        while i < seen.len() {
            for e in std::fs::read_dir(&seen[i]).unwrap() {
                let e = e.unwrap();
                if e.file_type().unwrap().is_dir() {
                    seen.push(e.path());
                }
            }
            i += 1;
        }
        for d in ["r", "r/alpha", "r/beta", "r/beta/deeper"] {
            assert!(seen.contains(&b.join(d)), "{d}");
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn nested_write_roots_lock_each_other_out_whichever_config_names_them() {
        let base = std::env::temp_dir().join(format!("hercules-apply-nested-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(base.join("ws/project")).unwrap();
        let ws = std::fs::canonicalize(base.join("ws")).unwrap();
        let outer = Root { name: "outer".into(), path: ws.clone() };
        let inner = Root { name: "inner".into(), path: ws.join("project") };
        let sibling = { std::fs::create_dir_all(base.join("other")).unwrap(); Root { name: "other".into(), path: std::fs::canonicalize(base.join("other")).unwrap() } };
        {
            let _a = lock_roots(&[&outer]).unwrap();
            assert!(lock_roots(&[&inner]).unwrap_err().contains("contains write root inner"));
            assert!(lock_roots(&[&sibling]).is_ok(), "unrelated roots must not conflict");
        }
        {
            let _b = lock_roots(&[&inner]).unwrap();
            assert!(lock_roots(&[&outer]).unwrap_err().contains("or a folder inside it"));
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn recover_refuses_when_the_config_maps_the_root_somewhere_else() {
        let (base, root, prop, digest) = setup("remap");
        crash_after_first_write(&prop, &root, &digest, &key(7), None);
        // Same root name, another folder, holding the post-apply content.
        let other = base.join("other");
        std::fs::create_dir_all(other.join("sub")).unwrap();
        let other = std::fs::canonicalize(other).unwrap();
        std::fs::write(other.join("a.txt"), "new a").unwrap();
        let remapped = vec![Root { name: "r".into(), path: other.clone() }];
        let e = recover(&prop, &key(7), &remapped, &[]).unwrap_err();
        assert!(e.contains("does not match its root") && e.contains("nothing changed"), "{e}");
        assert_eq!(std::fs::read_to_string(other.join("a.txt")).unwrap(), "new a");
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "new a");
        assert!(prop.join(JOURNAL).exists());
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn one_change_command_at_a_time() {
        let (base, root, prop, digest) = setup("lock");
        crash_after_first_write(&prop, &root, &digest, &key(7), None);
        let held = lock(&prop).unwrap();
        assert!(recover(&prop, &key(7), &roots(&root), &[]).unwrap_err().contains("another change command is running"));
        assert!(rollback(&prop, &key(7), &roots(&root), &[]).unwrap_err().contains("another change command is running"));
        drop(held);
        assert!(recover(&prop, &key(7), &roots(&root), &[]).is_ok());
        std::fs::remove_dir_all(&base).unwrap();
    }
}
