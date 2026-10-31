//! Build 1: the one read path shared by fs.read / fs.list / fs.stat and the native
//! cmd.run commands. Absolute paths go through the granted roots (deny list +
//! race-checked open); relative paths mean the session sandbox, as in hercules-2.

use crate::authority::AuthorityContext;
use crate::roots::{self, RootPolicy};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

pub struct ReadErr {
    pub code: String,
    pub detail: String,
    /// true = the harness refused (policy); false = the read itself failed.
    pub policy: bool,
}

fn policy_err(code: &str, detail: impl Into<String>) -> ReadErr {
    ReadErr { code: code.into(), detail: detail.into(), policy: true }
}

fn fail(code: &str, detail: impl Into<String>) -> ReadErr {
    ReadErr { code: code.into(), detail: detail.into(), policy: false }
}

#[derive(Clone, Debug)]
pub struct Target {
    /// The path as the model wrote it.
    pub shown: String,
    pub canonical: PathBuf,
    /// Root name, or "sandbox".
    pub root: String,
    /// Gate 10: true when the content came from the run's proposal overlay, not the root.
    pub from_proposal: bool,
}

impl Target {
    pub fn json(&self, kind: &str) -> serde_json::Value {
        let mut v = serde_json::json!({"path": self.canonical.display().to_string(), "requested": self.shown, "root": self.root, "kind": kind});
        if self.from_proposal {
            v["source"] = "proposal".into();
        }
        v
    }
}

fn from_root_err(e: roots::RootError) -> ReadErr {
    let policy = !matches!(e.code, "ROOT_NOT_FOUND" | "ROOT_OPEN_FAILED" | "ROOT_LIST_FAILED");
    ReadErr { code: e.code.into(), detail: e.detail, policy }
}

fn sandbox_relative(raw: &str) -> Result<PathBuf, ReadErr> {
    if raw.is_empty() {
        return Err(policy_err("SANDBOX_POLICY", "path is empty"));
    }
    if raw == "." {
        return Ok(PathBuf::new()); // Build 3.2: "." is the sandbox root
    }
    let p = Path::new(raw);
    for c in p.components() {
        if !matches!(c, Component::Normal(_)) {
            return Err(policy_err("SANDBOX_POLICY", format!("bad path component: {c:?}")));
        }
    }
    Ok(p.to_path_buf())
}

/// Which policy governs `raw`, and the absolute path to resolve under it.
fn policy_for(ctx: &AuthorityContext, raw: &str) -> Result<(RootPolicy, String, bool), ReadErr> {
    // Build 3.2: an absolute path inside the session sandbox, or one with "." components, means the
    // sandbox; the usual checks below still apply to the rewritten path.
    let rewritten = crate::authority::sandbox_relative_form(ctx, raw);
    let raw = rewritten.as_deref().unwrap_or(raw);
    if Path::new(raw).is_absolute() {
        if ctx.roots.is_empty() {
            return Err(policy_err(
                "ROOT_POLICY",
                "absolute paths need a granted read-only root; none are granted for this run. Relative paths mean the session sandbox",
            ));
        }
        return Ok((ctx.roots.clone(), raw.to_string(), false));
    }
    let sandbox = ctx
        .sandbox_root
        .as_deref()
        .ok_or_else(|| policy_err("SANDBOX_ROOT_REQUIRED", "sandbox root not configured"))?;
    let rel = sandbox_relative(raw)?;
    let abs = sandbox.join(rel).to_string_lossy().to_string();
    Ok((RootPolicy::sandbox(sandbox), abs, true))
}

fn map_sandbox(e: ReadErr, is_sandbox: bool) -> ReadErr {
    if !is_sandbox {
        return e;
    }
    let code = match e.code.as_str() {
        "ROOT_POLICY" => "SANDBOX_ESCAPE",
        "ROOT_NOT_FOUND" => "SANDBOX_POLICY",
        other => other,
    };
    ReadErr { code: code.into(), ..e }
}

pub fn resolve(ctx: &AuthorityContext, raw: &str) -> Result<(RootPolicy, roots::Resolved, Target), ReadErr> {
    let (pol, abs, is_sandbox) = policy_for(ctx, raw)?;
    let r = pol.resolve(&abs).map_err(|e| map_sandbox(from_root_err(e), is_sandbox))?;
    let t = Target { shown: raw.to_string(), canonical: r.path.clone(), root: r.root.clone(), from_proposal: false };
    Ok((pol, r, t))
}

/// Read a whole file (up to roots::MAX_FILE_BYTES) through a verified descriptor.
pub fn read_bytes(ctx: &AuthorityContext, raw: &str) -> Result<(Target, Vec<u8>), ReadErr> {
    // Gate 10: a file the model has written in this run is read from its proposal.
    if let Some((key, root, bytes)) = ctx.proposal.as_ref().and_then(|p| p.read(raw)) {
        return Ok((Target { shown: raw.to_string(), canonical: key, root, from_proposal: true }, bytes));
    }
    let (pol, r, t) = resolve(ctx, raw)?;
    let (mut f, size) = pol.open_file(&r).map_err(from_root_err)?;
    if size > roots::MAX_FILE_BYTES {
        return Err(fail(
            "FS_READ_LIMIT",
            format!(
                "{} is {size} bytes (limit {}); read a line range, or use cmd.run grep/head/tail",
                raw,
                roots::MAX_FILE_BYTES
            ),
        ));
    }
    let mut buf = Vec::with_capacity(size as usize);
    (&mut f)
        .take(roots::MAX_FILE_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| fail("FS_READ_FAILED", format!("{raw}: {e}")))?;
    if buf.len() as u64 > roots::MAX_FILE_BYTES {
        return Err(fail("FS_READ_LIMIT", format!("{raw} grew past the limit while reading")));
    }
    Ok((t, buf))
}

#[derive(Clone, Debug)]
pub struct Entry {
    pub name: String,
    pub kind: &'static str,
    pub size: u64,
    pub mode: String,
    pub owner: String,
    pub mtime: i64,
}

impl Entry {
    pub fn json(&self) -> serde_json::Value {
        serde_json::json!({"name": self.name, "kind": self.kind, "size": self.size, "mode": self.mode, "owner": self.owner, "mtime": self.mtime})
    }
}

pub struct Listing {
    pub target: Target,
    pub entries: Vec<Entry>,
    pub total: usize,
    pub truncated: bool,
    pub denied_omitted: usize,
}

pub fn list(ctx: &AuthorityContext, raw: &str, sort: &str, limit: usize, include_hidden: bool) -> Result<Listing, ReadErr> {
    let (pol, r, t) = resolve(ctx, raw)?;
    let dir = pol.open_dir(&r).map_err(from_root_err)?;
    let (raw_entries, walk_truncated) = roots::list_dir_fd(&dir, 5000).map_err(from_root_err)?;
    let root = pol.roots().iter().find(|x| x.name == r.root).cloned();
    let mut owners: HashMap<u32, String> = HashMap::new();
    let mut denied_omitted = 0usize;
    let mut entries = Vec::new();
    for e in raw_entries {
        if let Some(root) = &root {
            if pol.deny_reason(&r.path.join(&e.name), root).is_some() {
                denied_omitted += 1;
                continue;
            }
        }
        if !include_hidden && e.name.starts_with('.') {
            continue;
        }
        let owner = owners.entry(e.uid).or_insert_with(|| roots::user_name(e.uid)).clone();
        entries.push(Entry {
            mode: roots::mode_string(e.kind, e.mode),
            name: e.name,
            kind: e.kind,
            size: e.size,
            owner,
            mtime: e.mtime,
        });
    }
    // Gate 10: the proposal's files in this directory: new ones are added, changed ones show their new size.
    if let Some(p) = &ctx.proposal {
        let owner = roots::user_name(unsafe { libc::getuid() });
        for (name, bytes, mode, _new, mtime) in p.children(&r.path) {
            if !include_hidden && name.starts_with('.') {
                continue;
            }
            match entries.iter_mut().find(|e| e.name == name) {
                Some(e) => {
                    e.size = bytes as u64;
                    e.mtime = mtime;
                }
                None => entries.push(Entry { name, kind: "file", size: bytes as u64, mode: roots::mode_string("file", 0o100000 | mode), owner: owner.clone(), mtime }),
            }
        }
    }
    match sort {
        "mtime" => entries.sort_by(|a, b| b.mtime.cmp(&a.mtime).then_with(|| a.name.cmp(&b.name))),
        _ => entries.sort_by(|a, b| a.name.cmp(&b.name)),
    }
    let total = entries.len();
    let truncated = walk_truncated || entries.len() > limit;
    entries.truncate(limit);
    Ok(Listing { target: t, entries, total, truncated, denied_omitted })
}

pub fn stat(ctx: &AuthorityContext, raw: &str) -> Result<(Target, Entry), ReadErr> {
    if let Some((key, root, bytes, mode, mtime)) = ctx.proposal.as_ref().and_then(|p| p.stat(raw)) {
        let name = key.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        let owner = roots::user_name(unsafe { libc::getuid() });
        return Ok((
            Target { shown: raw.to_string(), canonical: key, root, from_proposal: true },
            Entry { name, kind: "file", size: bytes as u64, mode: roots::mode_string("file", 0o100000 | mode), owner, mtime },
        ));
    }
    let (_pol, r, t) = resolve(ctx, raw)?;
    let m = std::fs::symlink_metadata(&r.path).map_err(|e| fail("FS_STAT_FAILED", format!("{raw}: {e}")))?;
    let (kind, size, mode, uid, mtime) = roots::stat_info(&m);
    let name = r.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| "/".into());
    Ok((
        t,
        Entry { name, kind, size, mode: roots::mode_string(kind, mode), owner: roots::user_name(uid), mtime },
    ))
}

/// Number of lines, counting a final line without a trailing newline.
pub fn count_lines(text: &str) -> usize {
    if text.is_empty() {
        0
    } else {
        let nl = text.matches('\n').count();
        if text.ends_with('\n') { nl } else { nl + 1 }
    }
}

pub struct Window {
    pub content: String,
    pub start_line: usize,
    pub end_line: usize,
    pub total_lines: usize,
    pub truncated: bool,
    pub next_start_line: Option<usize>,
}

/// Budget for content inside one tool result, measured as JSON-escaped characters so
/// the whole result envelope stays under tools::RESULT_MAX_CHARS and never gets cut.
pub const CONTENT_JSON_BUDGET: usize = 28_000;

thread_local! {
    /// Build 3.4: a smaller content budget for one call of a batch (the batch's results share one result's space).
    static CONTENT_CAP: std::cell::Cell<Option<usize>> = const { std::cell::Cell::new(None) };
}

/// The content budget for the call being run: CONTENT_JSON_BUDGET, or less inside a batch.
pub fn content_budget() -> usize {
    CONTENT_CAP.with(|c| c.get()).map_or(CONTENT_JSON_BUDGET, |b| b.min(CONTENT_JSON_BUDGET))
}

/// Run `f` with the content budget capped at `cap` (None: the full budget).
pub fn with_content_budget<T>(cap: Option<usize>, f: impl FnOnce() -> T) -> T {
    let prev = CONTENT_CAP.with(|c| c.replace(cap));
    let out = f();
    CONTENT_CAP.with(|c| c.set(prev));
    out
}

fn json_len(s: &str) -> usize {
    serde_json::to_string(s).map(|x| x.len()).unwrap_or(usize::MAX)
}

/// Lines [start_line, start_line + max_lines) of `text` (1-based), whole lines only,
/// within `budget` JSON characters. A single over-long first line is cut at a char boundary.
#[cfg(test)]
pub fn window(text: &str, start_line: usize, max_lines: Option<usize>, budget: usize) -> Window {
    window_lines(text, start_line, max_lines, budget, 0)
}

/// As `window`, charging `per_line` extra characters for each line, so a rendering that
/// prefixes every line (a line number, say) also stays within `budget`.
pub fn window_lines(text: &str, start_line: usize, max_lines: Option<usize>, budget: usize, per_line: usize) -> Window {
    let total = count_lines(text);
    let start = start_line.max(1);
    let mut content = String::new();
    let mut used = 2usize; // the quotes
    let mut end = start.saturating_sub(1);
    let mut truncated = false;
    let want_end = max_lines.map(|m| start.saturating_add(m).saturating_sub(1)).unwrap_or(usize::MAX);
    for (i, line) in text.split_inclusive('\n').enumerate() {
        let n = i + 1;
        if n < start {
            continue;
        }
        if n > want_end {
            break;
        }
        let cost = json_len(line).saturating_sub(2) + per_line;
        if used + cost > budget {
            if content.is_empty() {
                // First line alone is too big: cut it.
                let mut cut = String::new();
                for ch in line.chars() {
                    let c = json_len(&ch.to_string()) - 2;
                    if used + c > budget {
                        break;
                    }
                    used += c;
                    cut.push(ch);
                }
                content = cut;
                end = n;
            }
            truncated = true;
            break;
        }
        used += cost;
        content.push_str(line);
        end = n;
    }
    // "truncated" = the file continues past what is shown (or a line was cut).
    if end < total {
        truncated = true;
    }
    let next = if end < total { Some(end + 1) } else { None };
    Window { content, start_line: start, end_line: end, total_lines: total, truncated, next_start_line: next }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_basics() {
        let t = "a\nb\nc\nd\n";
        let w = window(t, 2, Some(2), 1000);
        assert_eq!(w.content, "b\nc\n");
        assert_eq!((w.start_line, w.end_line, w.total_lines), (2, 3, 4));
        assert!(w.truncated);
        assert_eq!(w.next_start_line, Some(4));
        let w = window(t, 1, None, 1000);
        assert_eq!(w.content, t);
        assert!(!w.truncated);
        assert_eq!(w.next_start_line, None);
        let w = window(t, 9, None, 1000);
        assert_eq!(w.content, "");
    }

    #[test]
    fn window_budget_is_json_size() {
        // Quotes escape to two characters each, so the budget binds on escaped size.
        let line = "\"\"\"\"\"\n"; // 6 raw chars, 12 escaped
        let text = line.repeat(10);
        let w = window(&text, 1, None, 2 + 12 * 3);
        assert_eq!(w.end_line, 3);
        assert!(w.truncated);
        assert_eq!(w.next_start_line, Some(4));
        assert!(serde_json::to_string(&w.content).unwrap().len() <= 2 + 12 * 3);
    }

    #[test]
    fn window_cuts_one_huge_line() {
        let text = "x".repeat(100);
        let w = window(&text, 1, None, 12);
        assert_eq!(w.content.len(), 10);
        assert!(w.truncated);
    }

    // ---------------------------------------------------------------- Build 3.2: other spellings of in-sandbox paths
    fn sandbox() -> (std::path::PathBuf, AuthorityContext) {
        let d = std::env::temp_dir().join(format!("b32-{}-{}", std::process::id(), std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir_all(d.join("example-org/config")).unwrap();
        std::fs::write(d.join("example-org/config/model-routing.yaml"), "tiers: {}\n").unwrap();
        let ctx = AuthorityContext::new(Some(d.to_str().unwrap()), None, None).unwrap();
        let root = ctx.sandbox_root.clone().unwrap();
        (root, ctx)
    }

    #[test]
    fn b32_relative_form() {
        use crate::authority::sandbox_relative_form as f;
        let (root, ctx) = sandbox();
        let r = root.display().to_string();
        assert_eq!(f(&ctx, &format!("{r}/example-org/config/model-routing.yaml")).as_deref(), Some("example-org/config/model-routing.yaml"));
        assert_eq!(f(&ctx, &format!("{r}/./example-org")).as_deref(), Some("example-org"));
        assert_eq!(f(&ctx, &r).as_deref(), Some("."));
        assert_eq!(f(&ctx, &format!("{r}/")).as_deref(), Some("."));
        assert_eq!(f(&ctx, "./example-org/config").as_deref(), Some("example-org/config"));
        // Rust's Path::components() already drops an interior ".", so this one needs no rewrite and is accepted.
        assert_eq!(f(&ctx, "example-org/./config"), None);
        assert_eq!(f(&ctx, "."), None, "already the root spelling");
        assert_eq!(f(&ctx, "example-org/config"), None, "nothing to rewrite");
        assert_eq!(f(&ctx, "/etc/passwd"), None, "outside: left for the usual refusal");
        assert_eq!(f(&ctx, &format!("{r}/../x")), None, ".. is never rewritten");
        assert_eq!(f(&ctx, &format!("{r}x/a")), None, "a sibling folder whose name starts like the root");
        assert_eq!(f(&ctx, "/net/host.example/x"), None, "outside paths are matched as text, never looked up");
        assert_eq!(f(&ctx, ""), None);
    }

    #[test]
    fn b32_reads_through_other_spellings() {
        let (root, ctx) = sandbox();
        let r = root.display().to_string();
        assert!(read_bytes(&ctx, &format!("{r}/example-org/config/model-routing.yaml")).is_ok());
        assert!(read_bytes(&ctx, "./example-org/config/model-routing.yaml").is_ok());
        assert!(read_bytes(&ctx, "example-org/./config/model-routing.yaml").is_ok());
        assert!(resolve(&ctx, ".").is_ok(), "\".\" is the sandbox root");
        assert!(resolve(&ctx, &r).is_ok());
        let e = read_bytes(&ctx, "/etc/hosts").unwrap_err();
        assert_eq!(e.code, "ROOT_POLICY", "outside the sandbox is still refused");
        assert!(read_bytes(&ctx, "../etc/hosts").is_err());
    }

    #[test]
    fn b32_symlink_out_of_the_sandbox_is_still_refused() {
        let (root, ctx) = sandbox();
        std::os::unix::fs::symlink("/etc", root.join("out")).unwrap();
        let r = root.display().to_string();
        assert!(read_bytes(&ctx, &format!("{r}/out/hosts")).is_err());
        assert!(read_bytes(&ctx, "out/hosts").is_err());
    }
}
