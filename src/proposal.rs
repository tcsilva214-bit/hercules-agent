//! Gate 10: the write lane's proposal overlay.
//!
//! Design: DESIGN_OSS_WRITE_LANE.md (approved 2026-10-30). In a run with write roots (`--write-roots`), the
//! model's `fs.write` / `fs.replace` never touch the root: each file lands in an overlay folder outside every
//! root, `<proposal-dir>/<session_id>/files/<root name>/<relative path>`. Reads through HERCULES (readers.rs,
//! and the native cmd.run commands built on it) see the overlay first, so the model works on its own edits;
//! `git` and `plutil` read the disk and see the originals. At run end the overlay becomes a changeset (base
//! hash, new hash, a unified diff) that the run's signed statement binds. Nothing reaches the root until the
//! operator runs `change apply` (apply.rs).

use crate::roots::{Root, RootPolicy};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

pub const MAX_FILE_BYTES: usize = 256 * 1024;
pub const MAX_FILES: usize = 50;
pub const MAX_TOTAL_BYTES: usize = 2 * 1024 * 1024;
pub const CHANGESET_SCHEMA: &str = "hercules_changeset_v1";

#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub root: String,
    pub rel: String,
    /// SHA-256 of the root file when the path was first touched; None for a new file.
    pub base_sha256: Option<String>,
    pub sha256: String,
    pub bytes: usize,
    pub mode: u32,
}

#[derive(Debug)]
pub struct Proposal {
    pub dir: PathBuf,
    pub files_dir: PathBuf,
    pub write_roots: Vec<Root>,
    state: Mutex<BTreeMap<PathBuf, Entry>>,
}

#[derive(Debug)]
pub struct WriteErr {
    pub code: &'static str,
    pub detail: String,
    pub policy: bool,
}

fn werr(code: &'static str, detail: impl Into<String>) -> WriteErr {
    WriteErr { code, detail: detail.into(), policy: true }
}

fn wfail(code: &'static str, detail: impl Into<String>) -> WriteErr {
    WriteErr { code, detail: detail.into(), policy: false }
}

fn sha(b: &[u8]) -> String {
    crate::audit::sha256_bytes(b)
}

/// Write bytes atomically: a temp file in the same directory, fsync, rename, fsync the directory.
pub fn atomic_write(path: &Path, bytes: &[u8], mode: u32) -> std::io::Result<()> {
    let parent = path.parent().ok_or_else(|| std::io::Error::other("no parent"))?;
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let tmp = parent.join(format!(".hercules-write-{}-{nonce}", std::process::id()));
    let r = (|| {
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(mode).custom_flags(libc::O_NOFOLLOW).open(&tmp)?;
        f.write_all(bytes)?;
        f.set_permissions(std::fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if r.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    r?;
    // The new name must be on disk too: a failed directory sync is an error, not ignored.
    std::fs::File::open(parent)?.sync_all()
}

impl Proposal {
    /// A fresh proposal folder `<base>/<session_id>` (refused if it exists), or on resume the existing one.
    pub fn open(base: &Path, session_id: &str, write_roots: Vec<Root>, resume: bool) -> Result<Proposal, String> {
        let dir = base.join(session_id);
        let files_dir = dir.join("files");
        let mut state = BTreeMap::new();
        if resume && dir.is_dir() {
            let raw = std::fs::read_to_string(dir.join("state.json")).map_err(|e| format!("proposal state: {e}"))?;
            let v: Value = serde_json::from_str(&raw).map_err(|e| format!("proposal state: {e}"))?;
            for f in v["files"].as_array().cloned().unwrap_or_default() {
                let key = PathBuf::from(f["path"].as_str().unwrap_or(""));
                state.insert(
                    key,
                    Entry {
                        root: f["root"].as_str().unwrap_or("").into(),
                        rel: f["rel"].as_str().unwrap_or("").into(),
                        base_sha256: f["base_sha256"].as_str().map(str::to_string),
                        sha256: f["sha256"].as_str().unwrap_or("").into(),
                        bytes: f["bytes"].as_u64().unwrap_or(0) as usize,
                        mode: f["mode"].as_u64().unwrap_or(0o644) as u32,
                    },
                );
            }
        } else {
            // Private to the operator (0700): a proposal holds file contents.
            let mut b = std::fs::DirBuilder::new();
            std::os::unix::fs::DirBuilderExt::mode(&mut b, 0o700);
            b.create(&dir).map_err(|e| format!("proposal folder {}: {e}", dir.display()))?;
            b.create(&files_dir).map_err(|e| format!("proposal folder {}: {e}", files_dir.display()))?;
        }
        let p = Proposal { dir, files_dir, write_roots, state: Mutex::new(state) };
        p.save_state().map_err(|e| format!("proposal state: {e}"))?;
        Ok(p)
    }

    fn entries(&self) -> BTreeMap<PathBuf, Entry> {
        self.state.lock().map(|g| g.clone()).unwrap_or_default()
    }

    fn save_state(&self) -> std::io::Result<()> {
        let files: Vec<Value> = self
            .entries()
            .iter()
            .map(|(k, e)| json!({"path": k.display().to_string(), "root": e.root, "rel": e.rel, "base_sha256": e.base_sha256, "sha256": e.sha256, "bytes": e.bytes, "mode": e.mode}))
            .collect();
        atomic_write(&self.dir.join("state.json"), format!("{}\n", json!({"files": files})).as_bytes(), 0o600)
    }

    fn overlay_path(&self, e: &Entry) -> PathBuf {
        self.files_dir.join(&e.root).join(&e.rel)
    }

    fn write_root_of(&self, p: &Path) -> Option<&Root> {
        self.write_roots.iter().filter(|r| p.starts_with(&r.path)).max_by_key(|r| r.path.as_os_str().len())
    }

    /// The overlay key for an absolute path: its canonical parent plus its file name. None when the path is not
    /// absolute, has `.`/`..` components, or its parent does not exist.
    pub fn key_for(raw: &str) -> Option<PathBuf> {
        let p = Path::new(raw);
        if !p.is_absolute() || raw.contains('\0') || raw.len() > 1024 {
            return None;
        }
        if p.components().any(|c| matches!(c, Component::CurDir | Component::ParentDir)) {
            return None;
        }
        let name = p.file_name()?;
        let parent = std::fs::canonicalize(p.parent()?).ok()?;
        Some(parent.join(name))
    }

    /// Overlay content for `raw`, if the model has written that file in this run.
    pub fn read(&self, raw: &str) -> Option<(PathBuf, String, Vec<u8>)> {
        let key = Self::key_for(raw)?;
        let e = self.state.lock().ok()?.get(&key).cloned()?;
        let bytes = std::fs::read(self.overlay_path(&e)).ok()?;
        Some((key, e.root, bytes))
    }

    /// Size and mode of an overlay file, for stat and listings.
    pub fn stat(&self, raw: &str) -> Option<(PathBuf, String, usize, u32, i64)> {
        let key = Self::key_for(raw)?;
        let e = self.state.lock().ok()?.get(&key).cloned()?;
        let mtime = std::fs::metadata(self.overlay_path(&e)).map(|m| m.mtime()).unwrap_or(0);
        Some((key, e.root, e.bytes, e.mode, mtime))
    }

    /// Overlay files directly inside `dir` (canonical): (name, bytes, mode, is_new).
    pub fn children(&self, dir: &Path) -> Vec<(String, usize, u32, bool, i64)> {
        self.entries()
            .iter()
            .filter(|(k, _)| k.parent() == Some(dir))
            .map(|(k, e)| {
                let mtime = std::fs::metadata(self.overlay_path(e)).map(|m| m.mtime()).unwrap_or(0);
                (k.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), e.bytes, e.mode, e.base_sha256.is_none(), mtime)
            })
            .collect()
    }

    /// True when the model has written `raw` in this run (the file may exist only in the proposal).
    pub fn has(&self, raw: &str) -> bool {
        Self::key_for(raw).is_some_and(|k| self.state.lock().map(|s| s.contains_key(&k)).unwrap_or(false))
    }

    pub fn is_write_target(&self, raw: &str) -> bool {
        Self::key_for(raw).map(|k| self.write_root_of(&k).is_some()).unwrap_or(false)
    }

    /// Where a write to `raw` may go: the key, its write root, the path relative to it. Applies the deny list
    /// (from the run's full root policy) and refuses symlinks and anything that is not a regular file.
    fn target(&self, roots: &RootPolicy, raw: &str) -> Result<(PathBuf, Root, String), WriteErr> {
        if !Path::new(raw).is_absolute() {
            return Err(werr("WRITE_ROOT_POLICY", format!("{raw}: give an absolute path inside a write root")));
        }
        let key = Self::key_for(raw).ok_or_else(|| {
            werr("WRITE_ROOT_POLICY", format!("{raw}: no '.'/'..' components, and the parent directory must already exist in the root"))
        })?;
        let root = self.write_root_of(&key).cloned().ok_or_else(|| {
            let names: Vec<String> = self.write_roots.iter().map(|r| format!("{}: {}", r.name, r.path.display())).collect();
            werr("WRITE_ROOT_POLICY", format!("{raw} is outside the write roots [{}]", names.join("; ")))
        })?;
        if key == root.path {
            return Err(werr("WRITE_ROOT_POLICY", "the root itself is not a file"));
        }
        if let Some(why) = roots.deny_reason(&key, &root) {
            return Err(werr("DENY_LIST", format!("{raw}: {why}")));
        }
        match std::fs::symlink_metadata(&key) {
            Ok(m) if m.file_type().is_symlink() => return Err(werr("WRITE_TARGET_POLICY", format!("{raw} is a symlink; proposals never write through links"))),
            Ok(m) if !m.is_file() => return Err(werr("WRITE_TARGET_POLICY", format!("{raw} exists and is not a regular file"))),
            _ => {}
        }
        let rel = key.strip_prefix(&root.path).map(|r| r.to_string_lossy().to_string()).unwrap_or_default();
        Ok((key, root, rel))
    }

    /// The root file's bytes and mode through a race-checked open, or None if it does not exist.
    fn root_file(roots: &RootPolicy, key: &Path) -> Result<Option<(Vec<u8>, u32)>, WriteErr> {
        if std::fs::symlink_metadata(key).is_err() {
            return Ok(None);
        }
        let r = roots.resolve(&key.to_string_lossy()).map_err(|e| werr("WRITE_TARGET_POLICY", format!("{}: {}", e.code, e.detail)))?;
        let (mut f, size) = roots.open_file(&r).map_err(|e| werr("WRITE_TARGET_POLICY", format!("{}: {}", e.code, e.detail)))?;
        if size as usize > MAX_FILE_BYTES {
            return Err(werr("WRITE_LIMIT", format!("{} is {size} bytes; the write lane handles files up to {MAX_FILE_BYTES} bytes", key.display())));
        }
        let mode = f.metadata().map(|m| m.mode() & 0o777).unwrap_or(0o644);
        let mut b = Vec::new();
        (&mut f).take(MAX_FILE_BYTES as u64 + 1).read_to_end(&mut b).map_err(|e| wfail("WRITE_READ_FAILED", e.to_string()))?;
        Ok(Some((b, mode)))
    }

    /// The current text of a target: the overlay version, else the root file.
    fn current(&self, roots: &RootPolicy, key: &Path) -> Result<Option<(Vec<u8>, u32)>, WriteErr> {
        let e = self.state.lock().ok().and_then(|g| g.get(key).cloned());
        match e {
            Some(e) => std::fs::read(self.overlay_path(&e)).map(|b| Some((b, e.mode))).map_err(|e| wfail("WRITE_READ_FAILED", e.to_string())),
            None => Self::root_file(roots, key),
        }
    }

    /// fs.write: create or replace a file in the proposal.
    pub fn write(&self, roots: &RootPolicy, raw: &str, content: &str) -> Result<Value, WriteErr> {
        let (key, root, rel) = self.target(roots, raw)?;
        self.store(roots, raw, &key, &root, &rel, content.as_bytes(), None)
    }

    /// fs.replace: replace exactly one occurrence of `old` in the current version.
    pub fn replace(&self, roots: &RootPolicy, raw: &str, old: &str, new: &str) -> Result<Value, WriteErr> {
        let (key, root, rel) = self.target(roots, raw)?;
        if old.is_empty() {
            return Err(werr("FS_REPLACE_POLICY", "old must not be empty"));
        }
        let (cur, _) = self.current(roots, &key)?.ok_or_else(|| wfail("FS_REPLACE_MISSING", format!("{raw} does not exist; create it with fs.write")))?;
        let text = String::from_utf8(cur).map_err(|_| wfail("FS_REPLACE_UTF8", format!("{raw} is not UTF-8 text")))?;
        let n = text.matches(old).count();
        if n != 1 {
            return Err(wfail("FS_REPLACE_MATCH_COUNT", format!("expected exactly one match of old in {raw}; found {n}")));
        }
        let out = text.replacen(old, new, 1);
        self.store(roots, raw, &key, &root, &rel, out.as_bytes(), Some(1))
    }

    #[allow(clippy::too_many_arguments)]
    fn store(&self, roots: &RootPolicy, raw: &str, key: &Path, root: &Root, rel: &str, bytes: &[u8], replacements: Option<u32>) -> Result<Value, WriteErr> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(werr("WRITE_LIMIT", format!("{} bytes; one file may be at most {MAX_FILE_BYTES}", bytes.len())));
        }
        if bytes.contains(&0) || std::str::from_utf8(bytes).is_err() {
            return Err(werr("WRITE_TEXT_ONLY", "content must be UTF-8 text without NUL bytes"));
        }
        let mut g = self.state.lock().map_err(|_| wfail("WRITE_STATE", "proposal state unavailable"))?;
        let prior = g.get(key).cloned();
        if prior.is_none() && g.len() >= MAX_FILES {
            return Err(werr("WRITE_LIMIT", format!("a proposal may touch at most {MAX_FILES} files")));
        }
        let total: usize = g.iter().filter(|(k, _)| k.as_path() != key).map(|(_, e)| e.bytes).sum::<usize>() + bytes.len();
        if total > MAX_TOTAL_BYTES {
            return Err(werr("WRITE_LIMIT", format!("the proposal would hold {total} bytes; the limit is {MAX_TOTAL_BYTES}")));
        }
        let (base, mode) = match &prior {
            Some(e) => (e.base_sha256.clone(), e.mode),
            None => {
                drop(g);
                let rf = Self::root_file(roots, key)?;
                g = self.state.lock().map_err(|_| wfail("WRITE_STATE", "proposal state unavailable"))?;
                match rf {
                    Some((b, m)) => (Some(sha(&b)), m),
                    None => (None, 0o644),
                }
            }
        };
        let e = Entry { root: root.name.clone(), rel: rel.to_string(), base_sha256: base.clone(), sha256: sha(bytes), bytes: bytes.len(), mode };
        let op = self.overlay_path(&e);
        if let Some(parent) = op.parent() {
            std::fs::create_dir_all(parent).map_err(|x| wfail("WRITE_FAILED", x.to_string()))?;
        }
        atomic_write(&op, bytes, 0o600).map_err(|x| wfail("WRITE_FAILED", x.to_string()))?;
        g.insert(key.to_path_buf(), e.clone());
        drop(g);
        self.save_state().map_err(|x| wfail("WRITE_FAILED", format!("proposal state: {x}")))?;
        let mut v = json!({
            "path": raw, "root": root.name, "status": "proposed",
            "change": if base.is_none() { "create" } else { "modify" },
            "bytes": bytes.len(), "base_sha256": base, "prior_sha256": prior.map(|p| p.sha256), "after_sha256": e.sha256,
            "note": "written to the proposal only; the file in the root is unchanged until the operator applies the changeset"
        });
        if let Some(n) = replacements {
            v["replacements"] = n.into();
        }
        Ok(v)
    }

    /// The receipt target of a write.
    pub fn target_json(v: &Value, canonical: &Path) -> Value {
        json!({"path": canonical.display().to_string(), "requested": v["path"], "root": v["root"], "kind": "file", "source": "proposal",
               "write": true, "base_sha256": v["base_sha256"], "prior_sha256": v["prior_sha256"], "after_sha256": v["after_sha256"], "bytes": v["bytes"]})
    }

    /// Write changeset.json and changeset.diff at run end. Returns the changeset digest, or None if nothing
    /// changed. Files whose proposed content equals their base are left out.
    pub fn finish(&self, roots: &RootPolicy, run_id: &str, session_id: &str) -> Result<Option<String>, String> {
        let mut files = Vec::new();
        let mut diff = String::new();
        let mut total = 0usize;
        for (key, e) in self.entries() {
            if e.base_sha256.as_deref() == Some(e.sha256.as_str()) {
                continue;
            }
            let new = std::fs::read(self.overlay_path(&e)).map_err(|x| format!("overlay {}: {x}", key.display()))?;
            if sha(&new) != e.sha256 {
                return Err(format!("overlay file {} changed outside HERCULES", key.display()));
            }
            let label = format!("{}/{}", e.root, e.rel);
            match &e.base_sha256 {
                None => diff.push_str(&crate::diff::unified(None, &new, &label, 3)),
                Some(base) => match Self::root_file(roots, &key) {
                    Ok(Some((b, _))) if sha(&b) == *base => diff.push_str(&crate::diff::unified(Some(&b), &new, &label, 3)),
                    // The root file changed during the run: show the whole proposed file; apply will refuse (drift).
                    _ => {
                        diff.push_str(&format!("# {label}: the file in the root changed after this run first read it; apply will refuse until it is re-proposed\n"));
                        diff.push_str(&crate::diff::unified(None, &new, &label, 3));
                    }
                },
            }
            total += e.bytes;
            files.push(json!({"root": e.root, "rel": e.rel, "path": key.display().to_string(), "change": if e.base_sha256.is_none() { "create" } else { "modify" },
                              "base_sha256": e.base_sha256, "new_sha256": e.sha256, "bytes": e.bytes, "mode": format!("{:o}", e.mode)}));
        }
        if files.is_empty() {
            return Ok(None);
        }
        atomic_write(&self.dir.join("changeset.diff"), diff.as_bytes(), 0o644).map_err(|e| format!("changeset.diff: {e}"))?;
        let cs = json!({
            "schema": CHANGESET_SCHEMA,
            "run_id": run_id,
            "session_id": session_id,
            "write_roots": self.write_roots.iter().map(|r| json!({"name": r.name, "path": r.path.display().to_string()})).collect::<Vec<_>>(),
            "files": files,
            "total_bytes": total,
            "diff_sha256": sha(diff.as_bytes()),
        });
        let text = format!("{}\n", serde_json::to_string_pretty(&cs).unwrap_or_default());
        atomic_write(&self.dir.join("changeset.json"), text.as_bytes(), 0o644).map_err(|e| format!("changeset.json: {e}"))?;
        Ok(Some(sha(text.as_bytes())))
    }
}

/// The system-prompt paragraph for a run with write roots. Tool names are spelled as the run's protocol expects
/// them: `fs.replace` in TOOL_REQUEST lines, `fs_replace` as a native function name.
pub fn guide_for(write_roots: &[Root], native: bool) -> String {
    let roots: Vec<String> = write_roots.iter().map(|r| format!("{}: {}", r.name, r.path.display())).collect();
    let n = |t: &'static str| -> &'static str {
        if native {
            crate::native::NAMES.iter().find(|(i, _)| *i == t).map(|(_, w)| *w).unwrap_or(t)
        } else {
            t
        }
    };
    format!("\nWRITE LANE: you may propose file changes in these write roots: {}. {} {{path, content}} creates or replaces a whole file; {} {{path, old, new}} replaces exactly one occurrence. Paths are absolute; the parent directory must exist. Your writes go into a proposal, not the files: reads through {}, {}, {} and {} (except git and plutil) show your proposed versions. The operator reviews the diff and decides whether to apply it. There is no delete or rename. Limits: {} bytes per file, {} files, {} bytes in all. One write per response.",
            roots.join("; "),
            n("fs.write"),
            n("fs.replace"),
            n("fs.read"),
            n("fs.list"),
            n("fs.stat"),
            n("cmd.run"),
            MAX_FILE_BYTES,
            MAX_FILES,
            MAX_TOTAL_BYTES
        )
}

/// Check a proposal folder against its changeset: the changeset digest, the diff digest, and every overlay
/// file's content. Returns the problems found (empty = consistent).
pub fn check_folder(dir: &Path, want_changeset_sha256: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let Ok(text) = std::fs::read(dir.join("changeset.json")) else {
        return vec!["changeset.json unreadable".into()];
    };
    if sha(&text) != want_changeset_sha256 {
        problems.push("changeset_sha256".into());
    }
    let Ok(cs) = serde_json::from_slice::<Value>(&text) else {
        return vec!["changeset.json is not JSON".into()];
    };
    match std::fs::read(dir.join("changeset.diff")) {
        Ok(d) if Some(sha(&d).as_str()) == cs["diff_sha256"].as_str() => {}
        _ => problems.push("changeset.diff".into()),
    }
    for f in cs["files"].as_array().cloned().unwrap_or_default() {
        let p = dir.join("files").join(f["root"].as_str().unwrap_or("")).join(f["rel"].as_str().unwrap_or(""));
        match std::fs::read(&p) {
            Ok(b) if Some(sha(&b).as_str()) == f["new_sha256"].as_str() => {}
            _ => problems.push(format!("file({}/{})", f["root"].as_str().unwrap_or(""), f["rel"].as_str().unwrap_or(""))),
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_write_lane_guide_uses_the_protocol_s_tool_names() {
        let roots = [Root { name: "w".into(), path: PathBuf::from("/w") }];
        let text = guide_for(&roots, false);
        assert!(text.contains("fs.replace {path, old, new}") && text.contains("fs.write {path, content}") && text.contains("fs.read"), "{text}");
        assert!(!text.contains("fs_"), "TOOL_REQUEST runs must not be shown native names: {text}");
        let native = guide_for(&roots, true);
        assert!(native.contains("fs_replace {path, old, new}") && native.contains("cmd_run"), "{native}");
        assert!(!native.contains("fs.replace"), "{native}");
    }

    fn setup(tag: &str) -> (PathBuf, PathBuf, RootPolicy, Proposal) {
        let base = std::env::temp_dir().join(format!(
            "hercules-prop-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let root = base.join("root");
        let pdir = base.join("proposals");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(&pdir).unwrap();
        let root = std::fs::canonicalize(&root).unwrap();
        std::fs::write(root.join("a.txt"), "one\ntwo\nthree\n").unwrap();
        std::fs::write(root.join(".env"), "SECRET=1\n").unwrap();
        std::os::unix::fs::symlink(root.join("a.txt"), root.join("link.txt")).unwrap();
        let r = Root { name: "w".into(), path: root.clone() };
        let pol = RootPolicy::new(vec![r.clone()], vec![]);
        let p = Proposal::open(&std::fs::canonicalize(&pdir).unwrap(), "s1", vec![r], false).unwrap();
        (base, root, pol, p)
    }

    #[test]
    fn writes_go_to_the_overlay_only() {
        let (base, root, pol, p) = setup("ov");
        let a = root.join("a.txt").display().to_string();
        let v = p.replace(&pol, &a, "two", "TWO").unwrap();
        assert_eq!(v["change"], "modify");
        assert_eq!(std::fs::read_to_string(root.join("a.txt")).unwrap(), "one\ntwo\nthree\n", "root untouched");
        assert_eq!(p.read(&a).unwrap().2, b"one\nTWO\nthree\n");
        // A second edit builds on the overlay version; the base stays the root's.
        let v2 = p.replace(&pol, &a, "one", "ONE").unwrap();
        assert_eq!(v2["prior_sha256"], v["after_sha256"]);
        assert_eq!(v2["base_sha256"], v["base_sha256"]);
        let n = root.join("sub/new.rs").display().to_string();
        assert_eq!(p.write(&pol, &n, "fn main() {}\n").unwrap()["change"], "create");
        assert!(!root.join("sub/new.rs").exists());
        assert_eq!(p.children(&root.join("sub")).len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn refusals() {
        let (base, root, pol, p) = setup("ref");
        let s = |x: &str| root.join(x).display().to_string();
        assert_eq!(p.write(&pol, &s(".env"), "x").unwrap_err().code, "DENY_LIST");
        assert_eq!(p.write(&pol, &s("link.txt"), "x").unwrap_err().code, "WRITE_TARGET_POLICY");
        assert_eq!(p.write(&pol, &s("sub"), "x").unwrap_err().code, "WRITE_TARGET_POLICY");
        assert_eq!(p.write(&pol, &s("nodir/x.txt"), "x").unwrap_err().code, "WRITE_ROOT_POLICY");
        assert_eq!(p.write(&pol, &format!("{}/../x.txt", s("sub")), "x").unwrap_err().code, "WRITE_ROOT_POLICY");
        assert_eq!(p.write(&pol, "relative.txt", "x").unwrap_err().code, "WRITE_ROOT_POLICY");
        assert_eq!(p.write(&pol, "/etc/passwd", "x").unwrap_err().code, "WRITE_ROOT_POLICY");
        assert_eq!(p.write(&pol, &s("b.txt"), "a\0b").unwrap_err().code, "WRITE_TEXT_ONLY");
        assert_eq!(p.write(&pol, &s("b.txt"), &"x".repeat(MAX_FILE_BYTES + 1)).unwrap_err().code, "WRITE_LIMIT");
        assert_eq!(p.replace(&pol, &s("a.txt"), "o", "0").unwrap_err().code, "FS_REPLACE_MATCH_COUNT");
        assert_eq!(p.replace(&pol, &s("a.txt"), "", "0").unwrap_err().code, "FS_REPLACE_POLICY");
        assert_eq!(p.replace(&pol, &s("nope.txt"), "a", "b").unwrap_err().code, "FS_REPLACE_MISSING");
        for i in 0..MAX_FILES {
            p.write(&pol, &s(&format!("f{i}.txt")), "x").unwrap();
        }
        assert_eq!(p.write(&pol, &s("one-more.txt"), "x").unwrap_err().code, "WRITE_LIMIT");
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn changeset_and_resume() {
        let (base, root, pol, p) = setup("cs");
        let a = root.join("a.txt").display().to_string();
        p.replace(&pol, &a, "two", "TWO").unwrap();
        p.write(&pol, &root.join("sub/new.txt").display().to_string(), "hi\n").unwrap();
        // A file written back to its original content is not part of the changeset.
        let same = root.join("sub/same.txt");
        std::fs::write(&same, "same\n").unwrap();
        p.write(&pol, &same.display().to_string(), "same\n").unwrap();
        let d = p.finish(&pol, "run1", "s1").unwrap().unwrap();
        let cs: Value = serde_json::from_str(&std::fs::read_to_string(p.dir.join("changeset.json")).unwrap()).unwrap();
        assert_eq!(cs["files"].as_array().unwrap().len(), 2);
        let diff = std::fs::read_to_string(p.dir.join("changeset.diff")).unwrap();
        assert!(diff.contains("-two\n+TWO\n") && diff.contains("--- /dev/null\n+++ b/w/sub/new.txt"), "{diff}");
        assert!(check_folder(&p.dir, &d).is_empty());
        std::fs::write(p.dir.join("files/w/a.txt"), "tampered\n").unwrap();
        assert!(check_folder(&p.dir, &d).iter().any(|x| x.starts_with("file(")));
        // Resume reloads the state.
        let p2 = Proposal::open(p.dir.parent().unwrap(), "s1", p.write_roots.clone(), true).unwrap();
        assert_eq!(p2.entries().len(), 3);
        let _ = std::fs::remove_dir_all(&base);
    }
}
