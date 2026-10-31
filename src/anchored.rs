//! File operations anchored to directory handles, for the write lane's apply, rollback and recover.
//!
//! A target `root/a/b/file` is reached by opening the write root (canonical, as the config resolved it), then
//! each directory below it with `O_NOFOLLOW | O_DIRECTORY`, so no symlink is ever traversed under the root. Every
//! later read, write, rename and unlink happens relative to the directory handle that was opened and checked,
//! never by path name, so swapping a directory for a link after the check cannot redirect a write outside the
//! root. Files are read with `O_NOFOLLOW` and must be regular files.
//!
//! Not covered: a concurrent process that renames a whole directory elsewhere while the handle is held. Writes
//! then still land in that same directory (wherever it now is), under the names the changeset gives, and never
//! through a link.

use std::ffi::CString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

pub struct Dir {
    fd: OwnedFd,
}

/// What a name in a directory currently holds.
#[derive(Debug)]
pub enum State {
    Absent,
    File { bytes: Vec<u8>, mode: u32 },
}

fn cstr(s: &str) -> Result<CString, String> {
    CString::new(s).map_err(|_| format!("{s:?}: NUL byte in name"))
}

fn last_err() -> std::io::Error {
    std::io::Error::last_os_error()
}

// readdir returns NULL on both EOF and failure. Clear errno before each read, then check it
// immediately after NULL; silently treating an I/O failure as EOF is unsafe for recovery.
#[cfg(target_os = "macos")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: libc returns the current thread's errno pointer.
    unsafe { libc::__error() }
}

#[cfg(target_os = "linux")]
fn errno_location() -> *mut libc::c_int {
    // SAFETY: libc returns the current thread's errno pointer.
    unsafe { libc::__errno_location() }
}

#[cfg(test)]
thread_local! {
    static INJECT_READDIR_ERROR: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

// Test-only failure injection follows the actual readdir/errno error path. It never ships in
// release builds and is thread-local so parallel Rust tests cannot interfere with one another.
fn next_entry(dirp: *mut libc::DIR) -> *mut libc::dirent {
    #[cfg(test)]
    if INJECT_READDIR_ERROR.with(|v| v.get()) {
        // SAFETY: errno_location points to this thread's writable errno.
        unsafe { *errno_location() = libc::EIO };
        return std::ptr::null_mut();
    }
    // SAFETY: the caller holds a live fdopendir stream.
    unsafe { libc::readdir(dirp) }
}

#[cfg(test)]
pub(crate) fn inject_readdir_error_for_test(enabled: bool) {
    INJECT_READDIR_ERROR.with(|v| v.set(enabled));
}

fn fstat(fd: RawFd) -> Result<libc::stat, String> {
    // SAFETY: `st` is a plain C struct that fstat fills in; `fd` is a valid descriptor owned by the caller.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 {
        return Err(format!("fstat: {}", last_err()));
    }
    Ok(st)
}

fn is_reg(st: &libc::stat) -> bool {
    (st.st_mode & libc::S_IFMT) == libc::S_IFREG
}

/// A temp file name `replace` creates: `.hercules-apply-<pid>-<16 hex digits>`.
pub fn is_temp_name(n: &str) -> bool {
    let Some((pid, hex)) = n.strip_prefix(".hercules-apply-").and_then(|r| r.split_once('-')) else {
        return false;
    };
    !pid.is_empty() && pid.bytes().all(|c| c.is_ascii_digit()) && hex.len() == 16 && hex.bytes().all(|c| c.is_ascii_hexdigit())
}

/// Split a changeset's relative path into its directories and file name; refuses empty, `.` and `..` parts.
pub fn split_rel(rel: &str) -> Result<(Vec<&str>, &str), String> {
    let parts: Vec<&str> = rel.split('/').collect();
    if rel.is_empty() || parts.iter().any(|c| c.is_empty() || *c == "." || *c == "..") {
        return Err(format!("{rel}: not a plain relative path"));
    }
    let (name, dirs) = parts.split_last().expect("non-empty");
    Ok((dirs.to_vec(), name))
}

impl Dir {
    fn from_raw(fd: RawFd, what: &str) -> Result<Dir, String> {
        if fd < 0 {
            return Err(format!("{what}: {}", last_err()));
        }
        // SAFETY: `fd` was just returned by open/openat and is owned by nobody else.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(fd.as_raw_fd())?;
        if (st.st_mode & libc::S_IFMT) != libc::S_IFDIR {
            return Err(format!("{what}: not a directory"));
        }
        Ok(Dir { fd })
    }

    /// The directory holding `root/rel`, and the file name. Every directory under the root must exist and may
    /// not be a link.
    pub fn parent_of(root: &Path, rel: &str) -> Result<(Dir, String), String> {
        let (dirs, name) = split_rel(rel)?;
        let root_c = CString::new(root.as_os_str().as_bytes()).map_err(|_| "root path has a NUL byte".to_string())?;
        let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW;
        // SAFETY: a valid NUL-terminated path and plain flags.
        let mut dir = Dir::from_raw(unsafe { libc::open(root_c.as_ptr(), flags) }, &format!("write root {}", root.display()))?;
        let mut walked = root.to_path_buf();
        for d in dirs {
            walked.push(d);
            let c = cstr(d)?;
            // SAFETY: a valid directory descriptor and a NUL-terminated single path component.
            let fd = unsafe { libc::openat(dir.fd.as_raw_fd(), c.as_ptr(), flags) };
            dir = Dir::from_raw(fd, &format!("{} (directories under a write root must exist and may not be links)", walked.display()))?;
        }
        Ok((dir, name.to_string()))
    }

    /// Read `name` in this directory: Absent, or a regular file's bytes and mode. Symlinks and other kinds refused.
    pub fn read(&self, name: &str) -> Result<State, String> {
        let c = cstr(name)?;
        let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
        // SAFETY: a valid directory descriptor and a NUL-terminated name.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), c.as_ptr(), flags) };
        if fd < 0 {
            let e = last_err();
            return match e.raw_os_error() {
                Some(libc::ENOENT) => Ok(State::Absent),
                Some(libc::ELOOP) => Err(format!("{name} is a symlink")),
                _ => Err(format!("{name}: {e}")),
            };
        }
        // SAFETY: `fd` was just opened and is owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = fstat(fd.as_raw_fd())?;
        if !is_reg(&st) {
            return Err(format!("{name} is not a regular file"));
        }
        let mut bytes = Vec::new();
        std::fs::File::from(fd).read_to_end(&mut bytes).map_err(|e| format!("{name}: {e}"))?;
        Ok(State::File { bytes, mode: (st.st_mode as u32) & 0o777 })
    }

    /// Replace `name` with `bytes` atomically: an exclusive, never-followed temp file in this directory, fsync,
    /// `renameat` over the name, fsync the directory.
    pub fn replace(&self, name: &str, bytes: &[u8], mode: u32) -> Result<(), String> {
        let target = cstr(name)?;
        let tmp_name = format!(".hercules-apply-{}-{:016x}", std::process::id(), crate::audit::random_u64()?);
        let tmp = cstr(&tmp_name)?;
        let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        // SAFETY: a valid directory descriptor, a NUL-terminated name and a mode for O_CREAT.
        let fd = unsafe { libc::openat(self.fd.as_raw_fd(), tmp.as_ptr(), flags, 0o600 as libc::c_uint) };
        if fd < 0 {
            return Err(format!("{name}: temp file: {}", last_err()));
        }
        // SAFETY: `fd` was just created and is owned here.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let raw = fd.as_raw_fd();
        let mut f = std::fs::File::from(fd);
        let r = (|| -> Result<(), String> {
            f.write_all(bytes).map_err(|e| e.to_string())?;
            // SAFETY: `raw` is the descriptor `f` owns, still open.
            if unsafe { libc::fchmod(raw, (mode & 0o777) as libc::mode_t) } != 0 {
                return Err(format!("fchmod: {}", last_err()));
            }
            f.sync_all().map_err(|e| e.to_string())?;
            // SAFETY: both descriptors are this directory's; both names are NUL-terminated single components.
            if unsafe { libc::renameat(self.fd.as_raw_fd(), tmp.as_ptr(), self.fd.as_raw_fd(), target.as_ptr()) } != 0 {
                return Err(format!("rename: {}", last_err()));
            }
            Ok(())
        })();
        if let Err(e) = r {
            // SAFETY: as above; removing our own temp name.
            unsafe { libc::unlinkat(self.fd.as_raw_fd(), tmp.as_ptr(), 0) };
            return Err(format!("{name}: {e}"));
        }
        self.sync()
    }

    /// Remove `name`, which must be a regular file (never a link or a directory).
    pub fn remove(&self, name: &str) -> Result<(), String> {
        let c = cstr(name)?;
        // SAFETY: a plain C struct filled by fstatat on a valid descriptor and NUL-terminated name.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstatat(self.fd.as_raw_fd(), c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) } != 0 {
            return Err(format!("{name}: {}", last_err()));
        }
        if !is_reg(&st) {
            return Err(format!("{name} is not a regular file; not removed"));
        }
        // SAFETY: as above.
        if unsafe { libc::unlinkat(self.fd.as_raw_fd(), c.as_ptr(), 0) } != 0 {
            return Err(format!("{name}: {}", last_err()));
        }
        self.sync()
    }

    /// Enumerate names resembling abandoned transaction temps without deleting them. The old
    /// filename convention contains a PID and random suffix, but NO signed transaction identity;
    /// a matching name is NOT proof that a file belongs to this interrupted changeset.
    ///
    /// Fail closed on enumeration/closedir errors. Recovery must keep its signed journal when
    /// any unverified candidate is present, so the operator can inspect it and retry safely.
    pub fn unverified_temp_candidates(&self) -> Result<Vec<String>, String> {
        // SAFETY: the same anchored directory, opened as a new independent directory stream.
        let dup = unsafe { libc::openat(self.fd.as_raw_fd(), c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if dup < 0 {
            return Err(format!("listing transaction temp candidates: {}", last_err()));
        }
        // SAFETY: fdopendir owns dup on success; closedir closes it even on enumeration error.
        let dirp = unsafe { libc::fdopendir(dup) };
        if dirp.is_null() {
            let err = last_err();
            // SAFETY: fdopendir failed and did not consume dup.
            unsafe { libc::close(dup) };
            return Err(format!("listing transaction temp candidates: {err}"));
        }
        let mut names = Vec::new();
        let mut scan_error = None;
        loop {
            // SAFETY: errno_location is thread-local. POSIX readdir uses errno to distinguish
            // end-of-directory (0) from a failed enumeration (nonzero).
            unsafe { *errno_location() = 0 };
            let ent = next_entry(dirp);
            if ent.is_null() {
                let err = last_err();
                if err.raw_os_error() != Some(0) {
                    scan_error = Some(format!("listing transaction temp candidates: {err}"));
                }
                break;
            }
            // SAFETY: readdir returned a valid entry and d_name is NUL-terminated.
            let name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_string_lossy().into_owned();
            if is_temp_name(&name) {
                // Deliberately do NOT unlink even regular files: filename, type, PID and suffix
                // cannot establish ownership. Also leave matching links/directories untouched.
                names.push(name);
            }
        }
        // SAFETY: fdopendir returned this stream, which must be closed exactly once.
        let closed = unsafe { libc::closedir(dirp) };
        let close_error = if closed != 0 { Some(last_err()) } else { None };
        if let Some(err) = scan_error {
            return Err(err);
        }
        if let Some(err) = close_error {
            return Err(format!("closing transaction temp enumeration: {err}"));
        }
        names.sort();
        Ok(names)
    }

    pub fn sync(&self) -> Result<(), String> {
        // SAFETY: a valid descriptor.
        if unsafe { libc::fsync(self.fd.as_raw_fd()) } != 0 {
            return Err(format!("fsync directory: {}", last_err()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("hercules-anchored-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::canonicalize(&d).unwrap()
    }

    #[test]
    fn never_traverses_or_follows_links_under_the_root() {
        let base = tmpdir("links");
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("f.txt"), "outside").unwrap();
        // A directory under the root replaced by a link to a directory outside it.
        std::os::unix::fs::symlink(&outside, root.join("linked")).unwrap();
        assert!(Dir::parent_of(&root, "linked/f.txt").is_err());
        // A file that is a link.
        std::os::unix::fs::symlink(outside.join("f.txt"), root.join("sub/l.txt")).unwrap();
        let (d, n) = Dir::parent_of(&root, "sub/l.txt").unwrap();
        assert!(d.read(&n).unwrap_err().contains("symlink"));
        assert!(d.remove(&n).unwrap_err().contains("not a regular file"));
        // Replacing a link swaps the link itself; the file it pointed to is untouched.
        d.replace(&n, b"new", 0o640).unwrap();
        assert_eq!(std::fs::read_to_string(outside.join("f.txt")).unwrap(), "outside");
        assert!(matches!(d.read(&n).unwrap(), State::File { ref bytes, mode } if bytes == b"new" && mode == 0o640));
        // Bad relative paths.
        for bad in ["", "../x", "a//b", "./x", "a/../b"] {
            assert!(Dir::parent_of(&root, bad).is_err(), "{bad}");
        }
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn unverified_temp_candidates_are_reported_and_never_deleted() {
        let base = tmpdir("temps");
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("keep.txt"), "outside").unwrap();
        let ours = ".hercules-apply-4242-00ff00ff00ff00ff";
        std::fs::write(root.join("sub").join(ours), "half written").unwrap();
        // Look-alikes, a link with our pattern, and a folder with our pattern all stay.
        for keep in [".hercules-apply-4242-00ff", ".hercules-apply-x-00ff00ff00ff00ff", ".hercules-write-1-2", "a.txt"] {
            std::fs::write(root.join("sub").join(keep), "user").unwrap();
        }
        std::os::unix::fs::symlink(outside.join("keep.txt"), root.join("sub/.hercules-apply-1-1111111111111111")).unwrap();
        std::fs::create_dir(root.join("sub/.hercules-apply-2-2222222222222222")).unwrap();
        let (d, _) = Dir::parent_of(&root, "sub/a.txt").unwrap();
        let candidates = d.unverified_temp_candidates().unwrap();
        assert!(candidates.contains(&ours.to_string()));
        assert_eq!(candidates.len(), 3, "matching symlinks and directories also remain unverified: {candidates:?}");
        assert!(root.join("sub").join(ours).exists(), "unowned candidate was deleted");
        let left: Vec<String> = std::fs::read_dir(root.join("sub")).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        assert_eq!(left.len(), 7, "{left:?}");
        assert_eq!(std::fs::read_to_string(outside.join("keep.txt")).unwrap(), "outside");
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_held_directory_is_not_redirected_by_a_later_swap() {
        let base = tmpdir("swap");
        let root = base.join("root");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let (d, n) = Dir::parent_of(&root, "sub/f.txt").unwrap();
        // After the check: the directory is moved away and a link to the outside put in its place.
        std::fs::rename(root.join("sub"), base.join("moved")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("sub")).unwrap();
        d.replace(&n, b"x", 0o644).unwrap();
        assert!(!outside.join("f.txt").exists(), "a write went through the swapped-in link");
        assert_eq!(std::fs::read_to_string(base.join("moved/f.txt")).unwrap(), "x");
        std::fs::remove_dir_all(&base).unwrap();
    }
}
