//! Build 1, item 1: declared read-only workspace roots.
//!
//! The operator config declares roots; `--roots` selects which of them a run may read.
//! An absolute path is readable only if it canonicalises inside a granted root and no
//! component below that root is on the deny list. Opens are race-checked: the file is
//! opened with O_NOFOLLOW, then the path is re-canonicalised and the (device, inode) of
//! the opened descriptor must equal that of the path. A swap of any path component
//! between check and open is therefore detected, on macOS and Linux alike, without
//! relying on case-sensitive path comparison.

use std::ffi::CStr;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};

/// Any path component below a root with one of these names is denied.
pub const DENY_COMPONENTS: [&str; 4] = [".git", ".ssh", ".gnupg", ".aws"];
/// Any path component below a root matching one of these basename globs is denied.
pub const DENY_BASENAMES: [&str; 13] = [
    ".env",
    ".env.*",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "credentials*",
];

/// Largest file a root read will open (content is still windowed and capped).
pub const MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Clone, Debug)]
pub struct Root {
    pub name: String,
    pub path: PathBuf,
}

#[derive(Clone, Debug, Default)]
pub struct RootPolicy {
    roots: Vec<Root>,
    deny_extra: Vec<String>,
    /// The session sandbox reuses the verified-open machinery without the deny list.
    no_deny: bool,
}

#[derive(Clone, Debug)]
pub struct Resolved {
    pub path: PathBuf,
    pub root: String,
}

#[derive(Debug)]
pub struct RootError {
    pub code: &'static str,
    pub detail: String,
}

fn err(code: &'static str, detail: impl Into<String>) -> RootError {
    RootError {
        code,
        detail: detail.into(),
    }
}

/// `*` matches any run of characters (including none); everything else is literal.
pub fn glob_match(pattern: &str, name: &str) -> bool {
    let p = pattern.as_bytes();
    let n = name.as_bytes();
    let (mut pi, mut ni) = (0usize, 0usize);
    let (mut star, mut mark) = (None, 0usize);
    while ni < n.len() {
        if pi < p.len() && p[pi] != b'*' && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star = Some(pi);
            mark = ni;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            mark += 1;
            ni = mark;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

impl RootPolicy {
    pub fn new(roots: Vec<Root>, deny_extra: Vec<String>) -> Self {
        RootPolicy { roots, deny_extra, no_deny: false }
    }

    /// A single-root policy for the session sandbox (no deny list: the sandbox is the
    /// model's own scratch space, exactly as in hercules-2).
    pub fn sandbox(path: &Path) -> Self {
        RootPolicy {
            roots: vec![Root { name: "sandbox".into(), path: path.to_path_buf() }],
            deny_extra: Vec::new(),
            no_deny: true,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    pub fn roots(&self) -> &[Root] {
        &self.roots
    }

    pub fn deny_extra(&self) -> Vec<String> {
        self.deny_extra.clone()
    }

    /// "example_repo: /Users/x/example-repo; libexec: /usr/local/libexec"
    pub fn describe(&self) -> String {
        if self.roots.is_empty() {
            return "none".into();
        }
        self.roots
            .iter()
            .map(|r| format!("{}: {}", r.name, r.path.display()))
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub fn summary_json(&self) -> serde_json::Value {
        serde_json::json!({
            "roots": self.roots.iter().map(|r| serde_json::json!({"name": r.name, "path": r.path.display().to_string(), "mode": "read"})).collect::<Vec<_>>(),
            "deny_components": DENY_COMPONENTS,
            "deny_basenames": DENY_BASENAMES,
            "deny_extra": self.deny_extra,
        })
    }

    /// True when `p` is inside (or equal to) any granted root, by canonical path.
    pub fn contains(&self, p: &Path) -> bool {
        self.root_for(p).is_some()
    }

    fn root_for(&self, canonical: &Path) -> Option<&Root> {
        self.roots
            .iter()
            .filter(|r| canonical.starts_with(&r.path))
            .max_by_key(|r| r.path.as_os_str().len())
    }

    /// Why a canonical path inside `root` is denied, if it is.
    pub fn deny_reason(&self, canonical: &Path, root: &Root) -> Option<String> {
        if self.no_deny {
            return None;
        }
        let rel = canonical.strip_prefix(&root.path).ok()?;
        for c in rel.components() {
            let Component::Normal(os) = c else { continue };
            let name = os.to_string_lossy();
            // Case-insensitive: on APFS/HFS+ ".ENV" opens ".env".
            let lower = name.to_ascii_lowercase();
            if DENY_COMPONENTS.iter().any(|d| lower == *d) {
                return Some(format!("component '{name}' is on the deny list"));
            }
            for pat in DENY_BASENAMES.iter().copied().chain(self.deny_extra.iter().map(String::as_str)) {
                if glob_match(&pat.to_ascii_lowercase(), &lower) {
                    return Some(format!("'{name}' matches deny pattern '{pat}'"));
                }
            }
        }
        None
    }

    /// Denial text that tells the model what it can do instead.
    fn outside(&self, shown: &str) -> RootError {
        err(
            "ROOT_POLICY",
            format!(
                "{shown} is outside the granted read-only roots [{}]; relative paths mean the session sandbox",
                self.describe()
            ),
        )
    }

    /// Resolve an absolute path to its canonical form inside a granted root.
    pub fn resolve(&self, raw: &str) -> Result<Resolved, RootError> {
        if raw.is_empty() || raw.len() > 1024 || raw.contains('\0') {
            return Err(err("ROOT_POLICY", "path empty, too long, or contains NUL"));
        }
        let p = Path::new(raw);
        if !p.is_absolute() {
            return Err(err("ROOT_POLICY", format!("{raw} is not absolute")));
        }
        if self.roots.is_empty() {
            return Err(err(
                "ROOT_POLICY",
                "no read-only roots are granted for this run; relative paths mean the session sandbox",
            ));
        }
        let canonical = std::fs::canonicalize(p).map_err(|e| {
            // Do not reveal whether a path outside the roots exists.
            let plain = p.components().all(|c| matches!(c, Component::RootDir | Component::Normal(_)));
            let lexically_inside = plain && self.roots.iter().any(|r| p.starts_with(&r.path));
            if lexically_inside {
                err("ROOT_NOT_FOUND", format!("{raw}: {e}"))
            } else {
                self.outside(raw)
            }
        })?;
        let root = self.root_for(&canonical).ok_or_else(|| self.outside(raw))?;
        if let Some(reason) = self.deny_reason(&canonical, root) {
            return Err(err("DENY_LIST", format!("{raw}: {reason}")));
        }
        Ok(Resolved {
            path: canonical,
            root: root.name.clone(),
        })
    }

    /// Open a regular file for reading, race-checked. Returns the descriptor and its size.
    pub fn open_file(&self, resolved: &Resolved) -> Result<(File, u64), RootError> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&resolved.path)
            .map_err(|e| err("ROOT_OPEN_FAILED", format!("{}: {e}", resolved.path.display())))?;
        let meta = self.verify_fd(&f, resolved)?;
        if !meta.is_file() {
            return Err(err("ROOT_POLICY", format!("{} is not a regular file", resolved.path.display())));
        }
        // Clear O_NONBLOCK now that we know it is a regular file (it only mattered for FIFOs).
        unsafe {
            let fl = libc::fcntl(f.as_raw_fd(), libc::F_GETFL);
            if fl >= 0 {
                libc::fcntl(f.as_raw_fd(), libc::F_SETFL, fl & !libc::O_NONBLOCK);
            }
        }
        Ok((f, meta.len()))
    }

    /// Open a directory, race-checked. The listing is then read from this descriptor.
    pub fn open_dir(&self, resolved: &Resolved) -> Result<File, RootError> {
        let f = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_DIRECTORY)
            .open(&resolved.path)
            .map_err(|e| err("ROOT_OPEN_FAILED", format!("{}: {e}", resolved.path.display())))?;
        let meta = self.verify_fd(&f, resolved)?;
        if !meta.is_dir() {
            return Err(err("ROOT_POLICY", format!("{} is not a directory", resolved.path.display())));
        }
        Ok(f)
    }

    /// The opened descriptor must be the object the canonical path names *now*,
    /// and the path must still canonicalise to itself inside the same checks.
    fn verify_fd(&self, f: &File, resolved: &Resolved) -> Result<std::fs::Metadata, RootError> {
        let fd_meta = f
            .metadata()
            .map_err(|e| err("ROOT_OPEN_FAILED", format!("fstat: {e}")))?;
        let again = std::fs::canonicalize(&resolved.path)
            .map_err(|e| err("ROOT_RACE_DETECTED", format!("path changed during open: {e}")))?;
        if again != resolved.path {
            return Err(err(
                "ROOT_RACE_DETECTED",
                format!("{} now resolves to {}", resolved.path.display(), again.display()),
            ));
        }
        let path_meta = std::fs::symlink_metadata(&again)
            .map_err(|e| err("ROOT_RACE_DETECTED", format!("lstat after open: {e}")))?;
        if path_meta.dev() != fd_meta.dev() || path_meta.ino() != fd_meta.ino() {
            return Err(err(
                "ROOT_RACE_DETECTED",
                format!("{} was replaced during open", resolved.path.display()),
            ));
        }
        let root = self
            .root_for(&again)
            .ok_or_else(|| self.outside(&again.display().to_string()))?;
        if let Some(reason) = self.deny_reason(&again, root) {
            return Err(err("DENY_LIST", reason));
        }
        Ok(fd_meta)
    }
}

#[derive(Clone, Debug)]
pub struct DirEntryInfo {
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub mtime: i64,
}

fn kind_of(mode: u32) -> &'static str {
    match mode & (libc::S_IFMT as u32) {
        m if m == libc::S_IFREG as u32 => "file",
        m if m == libc::S_IFDIR as u32 => "directory",
        m if m == libc::S_IFLNK as u32 => "symlink",
        _ => "other",
    }
}

/// List a directory from an already-verified descriptor. Entries are lstat'ed relative
/// to that descriptor (fstatat + AT_SYMLINK_NOFOLLOW), so nothing is followed.
pub fn list_dir_fd(dir: &File, max_entries: usize) -> Result<(Vec<DirEntryInfo>, bool), RootError> {
    let fd = dir.as_raw_fd();
    let dup = unsafe { libc::dup(fd) };
    if dup < 0 {
        return Err(err("ROOT_LIST_FAILED", "dup failed"));
    }
    let dirp = unsafe { libc::fdopendir(dup) };
    if dirp.is_null() {
        unsafe { libc::close(dup) };
        return Err(err("ROOT_LIST_FAILED", "fdopendir failed"));
    }
    let mut out = Vec::new();
    let mut truncated = false;
    loop {
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            break;
        }
        let name_c = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let name_b = name_c.to_bytes();
        if name_b == b"." || name_b == b".." {
            continue;
        }
        if out.len() >= max_entries {
            truncated = true;
            break;
        }
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::fstatat(fd, name_c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) };
        let name = String::from_utf8_lossy(name_b).to_string();
        if rc != 0 {
            out.push(DirEntryInfo { name, kind: "other", size: 0, mode: 0, uid: 0, mtime: 0 });
            continue;
        }
        let mode = st.st_mode as u32;
        out.push(DirEntryInfo {
            name,
            kind: kind_of(mode),
            size: st.st_size as u64,
            mode: mode & 0o7777,
            uid: st.st_uid as u32,
            mtime: st.st_mtime as i64,
        });
    }
    unsafe { libc::closedir(dirp) };
    Ok((out, truncated))
}

/// Metadata for a verified path, symlinks not followed.
pub fn stat_info(meta: &std::fs::Metadata) -> (&'static str, u64, u32, u32, i64) {
    let mode = meta.mode();
    (kind_of(mode), meta.len(), mode & 0o7777, meta.uid(), meta.mtime())
}

/// User name for a uid, or the number as text.
pub fn user_name(uid: u32) -> String {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc == 0 && !result.is_null() && !pwd.pw_name.is_null() {
        unsafe { CStr::from_ptr(pwd.pw_name) }.to_string_lossy().to_string()
    } else {
        uid.to_string()
    }
}

/// `-rw-r--r--` style mode string.
pub fn mode_string(kind: &str, mode: u32) -> String {
    let t = match kind {
        "directory" => 'd',
        "symlink" => 'l',
        "file" => '-',
        _ => '?',
    };
    let mut s = String::with_capacity(10);
    s.push(t);
    for shift in [6u32, 3, 0] {
        let bits = (mode >> shift) & 7;
        s.push(if bits & 4 != 0 { 'r' } else { '-' });
        s.push(if bits & 2 != 0 { 'w' } else { '-' });
        s.push(if bits & 1 != 0 { 'x' } else { '-' });
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "hercules-roots-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    fn policy(dirs: &[(&str, &Path)]) -> RootPolicy {
        RootPolicy::new(
            dirs.iter()
                .map(|(n, p)| Root { name: n.to_string(), path: p.to_path_buf() })
                .collect(),
            vec!["*.sqlite".into()],
        )
    }

    #[test]
    fn glob() {
        assert!(glob_match("*.pem", "server.pem"));
        assert!(glob_match(".env.*", ".env.local"));
        assert!(!glob_match(".env.*", ".env"));
        assert!(glob_match("id_rsa*", "id_rsa.pub"));
        assert!(glob_match("*", ""));
        assert!(!glob_match("*.key", "keys.txt"));
        assert!(glob_match("a*b*c", "aXXbYYc"));
    }

    #[test]
    fn inside_outside_and_no_roots() {
        let a = tmpdir("a");
        let outside = tmpdir("out");
        std::fs::write(a.join("ok.txt"), "hi").unwrap();
        std::fs::write(outside.join("secret.txt"), "no").unwrap();
        let p = policy(&[("a", &a)]);
        let r = p.resolve(a.join("ok.txt").to_str().unwrap()).unwrap();
        assert_eq!(r.root, "a");
        let e = p.resolve(outside.join("secret.txt").to_str().unwrap()).unwrap_err();
        assert_eq!(e.code, "ROOT_POLICY");
        assert!(e.detail.contains("a: "), "denial lists granted roots: {}", e.detail);
        // Non-existent path outside roots must not reveal existence.
        let e = p.resolve("/definitely/not/here").unwrap_err();
        assert_eq!(e.code, "ROOT_POLICY");
        // Non-existent inside a root is a plain not-found.
        let e = p.resolve(a.join("nope").to_str().unwrap()).unwrap_err();
        assert_eq!(e.code, "ROOT_NOT_FOUND");
        let e = RootPolicy::default().resolve(a.join("ok.txt").to_str().unwrap()).unwrap_err();
        assert_eq!(e.code, "ROOT_POLICY");
        assert!(p.resolve("relative.txt").is_err());
    }

    #[test]
    fn dotdot_cannot_escape() {
        let a = tmpdir("dd");
        let outside = tmpdir("ddout");
        std::fs::write(outside.join("x"), "no").unwrap();
        let p = policy(&[("a", &a)]);
        let raw = format!("{}/../{}/x", a.display(), outside.file_name().unwrap().to_string_lossy());
        assert_eq!(p.resolve(&raw).unwrap_err().code, "ROOT_POLICY");
    }

    #[test]
    fn symlinks_escape_denied_between_roots_allowed() {
        let a = tmpdir("sa");
        let b = tmpdir("sb");
        let outside = tmpdir("sout");
        std::fs::write(outside.join("secret"), "no").unwrap();
        std::fs::write(b.join("shared"), "yes").unwrap();
        symlink(outside.join("secret"), a.join("escape")).unwrap();
        symlink(b.join("shared"), a.join("tob")).unwrap();
        let p = policy(&[("a", &a), ("b", &b)]);
        assert_eq!(p.resolve(a.join("escape").to_str().unwrap()).unwrap_err().code, "ROOT_POLICY");
        let r = p.resolve(a.join("tob").to_str().unwrap()).unwrap();
        assert_eq!(r.root, "b");
    }

    #[test]
    fn deny_list_every_entry() {
        let a = tmpdir("deny");
        let p = policy(&[("a", &a)]);
        for comp in DENY_COMPONENTS {
            std::fs::create_dir_all(a.join(comp)).unwrap();
            std::fs::write(a.join(comp).join("config"), "x").unwrap();
            let e = p.resolve(a.join(comp).join("config").to_str().unwrap()).unwrap_err();
            assert_eq!(e.code, "DENY_LIST", "{comp}");
        }
        for name in [".env", ".env.prod", ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_rsa.pub",
                     "id_ed25519", "id_ecdsa_sk", "tls.pem", "server.key", "cert.p12", "cert.pfx",
                     "credentials.json", "state.sqlite"] {
            std::fs::write(a.join(name), "x").unwrap();
            let e = p.resolve(a.join(name).to_str().unwrap()).unwrap_err();
            assert_eq!(e.code, "DENY_LIST", "{name}");
        }
        std::fs::write(a.join("notes.txt"), "x").unwrap();
        assert!(p.resolve(a.join("notes.txt").to_str().unwrap()).is_ok());
        // Case variants are denied too (case-insensitive filesystems open .env for .ENV).
        let root = Root { name: "a".into(), path: a.clone() };
        for v in [".ENV", ".Env.Local", "ID_RSA", "Server.PEM", ".GIT/config", ".SSH/known_hosts", "State.SQLITE"] {
            assert!(p.deny_reason(&a.join(v), &root).is_some(), "{v}");
        }
    }

    #[test]
    fn dotdot_does_not_reveal_outside_existence() {
        let a = tmpdir("oracle");
        let outside = tmpdir("oracleout");
        std::fs::write(outside.join("exists"), "x").unwrap();
        let p = policy(&[("a", &a)]);
        let name = outside.file_name().unwrap().to_string_lossy().to_string();
        let e1 = p.resolve(&format!("{}/../{name}/exists", a.display())).unwrap_err();
        let e2 = p.resolve(&format!("{}/../{name}/missing", a.display())).unwrap_err();
        assert_eq!((e1.code, e2.code), ("ROOT_POLICY", "ROOT_POLICY"));
    }

    #[test]
    fn open_detects_swap_after_resolve() {
        let a = tmpdir("race");
        let outside = tmpdir("raceout");
        std::fs::write(a.join("f"), "inside").unwrap();
        std::fs::write(outside.join("f"), "outside").unwrap();
        std::fs::create_dir(a.join("d")).unwrap();
        std::fs::write(a.join("d").join("f"), "inside-d").unwrap();
        let p = policy(&[("a", &a)]);
        // Resolve, then swap the final component for a symlink before open.
        let r = p.resolve(a.join("f").to_str().unwrap()).unwrap();
        std::fs::remove_file(a.join("f")).unwrap();
        symlink(outside.join("f"), a.join("f")).unwrap();
        let e = p.open_file(&r).unwrap_err();
        assert!(matches!(e.code, "ROOT_OPEN_FAILED" | "ROOT_RACE_DETECTED"), "{}", e.code);
        // Resolve, then swap an intermediate directory for a symlink before open.
        let r = p.resolve(a.join("d").join("f").to_str().unwrap()).unwrap();
        std::fs::remove_dir_all(a.join("d")).unwrap();
        symlink(&outside, a.join("d")).unwrap();
        let e = p.open_file(&r).unwrap_err();
        assert_eq!(e.code, "ROOT_RACE_DETECTED");
        // Resolve, then replace the file with a different inode.
        std::fs::write(a.join("g"), "one").unwrap();
        let r = p.resolve(a.join("g").to_str().unwrap()).unwrap();
        let (_f, n) = p.open_file(&r).unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn fifo_is_not_a_file_and_does_not_block() {
        let a = tmpdir("fifo");
        let c = CString::new(a.join("pipe").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let p = policy(&[("a", &a)]);
        let r = p.resolve(a.join("pipe").to_str().unwrap()).unwrap();
        assert_eq!(p.open_file(&r).unwrap_err().code, "ROOT_POLICY");
    }

    #[test]
    fn list_from_fd() {
        let a = tmpdir("list");
        std::fs::write(a.join("one"), "1").unwrap();
        std::fs::create_dir(a.join("sub")).unwrap();
        symlink("/etc/hostname", a.join("link")).unwrap();
        let p = policy(&[("a", &a)]);
        let r = p.resolve(a.to_str().unwrap()).unwrap();
        let d = p.open_dir(&r).unwrap();
        let (mut entries, trunc) = list_dir_fd(&d, 100).unwrap();
        entries.sort_by(|x, y| x.name.cmp(&y.name));
        assert!(!trunc);
        let kinds: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert_eq!(kinds, vec![("link", "symlink"), ("one", "file"), ("sub", "directory")]);
        assert_eq!(mode_string("file", 0o644), "-rw-r--r--");
    }
}
