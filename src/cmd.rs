//! Build 1, item 2: `cmd.run` — governed read-only commands.
//!
//! The model writes an argv in the vocabulary operators already use in tasks
//! (`ls`, `cat`, `sed -n`, `grep`, `shasum`, `git log`, `plutil -lint`, ...).
//! There is no shell: no pipes, redirection, globbing or variables. Every command
//! has a fixed grammar; anything else is rejected with CMD_GRAMMAR and a usage hint.
//! Most commands are implemented natively on top of `readers` (same roots, deny
//! list and race-checked opens as fs.read). Only git and plutil spawn a process,
//! from a fixed absolute path, with a cleared environment, a timeout, output caps
//! and process-group kill; git additionally runs with repository-config hardening.

use crate::authority::AuthorityContext;
use crate::capabilities::{CapabilityError, CapabilityOutcome};
use crate::readers::{self, ReadErr};
use crate::roots::{self, RootPolicy};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

pub const CATALOG_NAMES: [&str; 14] = [
    "ls", "cat", "head", "tail", "sed", "wc", "grep", "rg", "shasum", "sha256sum", "cmp", "stat",
    "git", "plutil",
];
/// Enabled when config v2 has no `cmd.enable` key: every native command, no processes.
pub const NATIVE_DEFAULT: [&str; 12] = [
    "ls", "cat", "head", "tail", "sed", "wc", "grep", "rg", "shasum", "sha256sum", "cmp", "stat",
];
/// Process commands are resolved only from these directories (never user-writable ones
/// such as /usr/local/bin or /opt/homebrew/bin).
const TRUSTED_BIN_DIRS: [&str; 2] = ["/usr/bin", "/bin"];
const GIT_MIN_VERSION: (u32, u32) = (2, 40);
/// Git's well-known empty tree: used as the attribute source so no .gitattributes applies.
const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

const STDOUT_CAP: usize = 32 * 1024;
const STDERR_CAP: usize = 4 * 1024;
const GREP_MAX_FILES: usize = 5_000;
const GREP_MAX_DIRS: usize = 20_000;
const GREP_MAX_BYTES: u64 = 256 * 1024 * 1024;
const GREP_MAX_MATCHES: usize = 1_000;
const LINE_DISPLAY_MAX: usize = 500;

pub fn is_catalog_command(name: &str) -> bool {
    CATALOG_NAMES.contains(&name)
}

#[derive(Clone, Debug)]
pub struct CmdPolicy {
    enabled: Vec<String>,
    timeout: Duration,
    git: Option<PathBuf>,
    git_version: Option<String>,
    plutil: Option<PathBuf>,
}

fn resolve_trusted(program: &str) -> Option<PathBuf> {
    TRUSTED_BIN_DIRS
        .iter()
        .map(|d| Path::new(d).join(program))
        .find(|p| p.is_file())
}

fn parse_git_version(s: &str) -> Option<(u32, u32)> {
    // "git version 2.43.0" / "git version 2.39.5 (Apple Git-154)"
    let v = s.split_whitespace().nth(2)?;
    let mut it = v.split('.');
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

impl CmdPolicy {
    pub fn disabled() -> Self {
        CmdPolicy {
            enabled: Vec::new(),
            timeout: Duration::from_secs(crate::config::CMD_TIMEOUT_DEFAULT_SECONDS),
            git: None,
            git_version: None,
            plutil: None,
        }
    }

    /// Resolve the enabled set and any process binaries once, at startup. Fails closed.
    pub fn from_config(enable: Option<&[String]>, timeout_seconds: u64) -> Result<Self, String> {
        let enabled: Vec<String> = match enable {
            Some(list) => list.to_vec(),
            None => NATIVE_DEFAULT.iter().map(|s| s.to_string()).collect(),
        };
        let mut p = CmdPolicy {
            enabled,
            timeout: Duration::from_secs(timeout_seconds),
            git: None,
            git_version: None,
            plutil: None,
        };
        if p.is_enabled("git") {
            let git = resolve_trusted("git").ok_or("cmd.enable lists git but no git in /usr/bin or /bin")?;
            let out = Command::new(&git)
                .arg("--version")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null())
                .output()
                .map_err(|e| format!("git --version failed: {e}"))?;
            let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let v = parse_git_version(&text).ok_or_else(|| format!("unrecognised git version: {text}"))?;
            if v < GIT_MIN_VERSION {
                return Err(format!(
                    "{text} is too old: git >= {}.{} is required (--attr-source isolation)",
                    GIT_MIN_VERSION.0, GIT_MIN_VERSION.1
                ));
            }
            p.git = Some(git);
            p.git_version = Some(text);
        }
        if p.is_enabled("plutil") {
            if !cfg!(target_os = "macos") {
                return Err("cmd.enable lists plutil, which is macOS only".into());
            }
            p.plutil = Some(resolve_trusted("plutil").ok_or("plutil not found in /usr/bin")?);
        }
        Ok(p)
    }

    pub fn is_enabled(&self, name: &str) -> bool {
        self.enabled.iter().any(|e| e == name)
    }

    pub fn enabled(&self) -> &[String] {
        &self.enabled
    }

    pub fn summary_json(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "timeout_seconds": self.timeout.as_secs(),
            "git": self.git.as_ref().map(|p| p.display().to_string()),
            "git_version": self.git_version,
            "plutil": self.plutil.as_ref().map(|p| p.display().to_string()),
        })
    }
}

// ---------------------------------------------------------------------------
// Grammar
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum Cmd {
    Ls { long: bool, all: bool, by_time: bool, path: String },
    Cat { file: String },
    Head { n: usize, file: String },
    Tail { n: usize, file: String },
    Sed { from: usize, to: Option<usize>, file: String },
    Wc { lines: bool, words: bool, bytes: bool, files: Vec<String> },
    Grep { number: bool, ignore_case: bool, count: bool, files_only: bool, recursive: bool, pattern: String, paths: Vec<String>, always_name: bool },
    Sha { files: Vec<String> },
    Cmp { silent: bool, a: String, b: String },
    Stat { path: String },
    Git { dir: String, sub: String, args: Vec<String>, paths: Vec<String> },
    Plutil { file: String },
}

type GErr = (String, String);

fn grammar(usage: &str, detail: impl Into<String>) -> GErr {
    ("CMD_GRAMMAR".into(), format!("{}; usage: {usage}", detail.into()))
}

fn usage_of(name: &str) -> &'static str {
    match name {
        "ls" => "ls [-l] [-a] [-t] [-1] <path>",
        "cat" => "cat <file>",
        "head" => "head [-n N] <file>",
        "tail" => "tail [-n N] <file>",
        "sed" => "sed -n 'A,Bp' <file>  (or 'Ap', or 'A,$p')",
        "wc" => "wc [-l] [-w] [-c] <file>...",
        "grep" => "grep [-n] [-i] [-c] [-l] [-r] [-F] [-e] <literal> <path>...  (fixed strings only)",
        "rg" => "rg [-n] [-i] [-c] [-l] [-F] [-e] <literal> [<path>...]  (fixed strings only)",
        "shasum" => "shasum -a 256 <file>...",
        "sha256sum" => "sha256sum <file>...",
        "cmp" => "cmp [-s] <file> <file>",
        "stat" => "stat <path>",
        "git" => "git -C <repo dir> status|log|diff|show|ls-files|rev-parse|blame [allowed flags] [<rev>...] [-- <path>...]",
        "plutil" => "plutil -lint <file>",
        _ => "see the cmd.run catalog",
    }
}

/// Split short flag clusters like "-la" into ['l','a']; returns None if not a flag cluster.
fn short_cluster(a: &str) -> Option<Vec<char>> {
    if a.len() >= 2 && a.starts_with('-') && !a.starts_with("--") {
        Some(a[1..].chars().collect())
    } else {
        None
    }
}

fn positional(usage: &str, a: &str) -> Result<String, GErr> {
    if a.starts_with('-') && a != "-" {
        return Err(grammar(usage, format!("unexpected option {a}")));
    }
    if a == "-" {
        return Err(grammar(usage, "stdin is not available"));
    }
    Ok(a.to_string())
}

fn parse_count(usage: &str, v: &str) -> Result<usize, GErr> {
    match v.parse::<usize>() {
        Ok(n) if (1..=5_000).contains(&n) => Ok(n),
        _ => Err(grammar(usage, format!("N must be 1..=5000, got {v}"))),
    }
}

/// grep/rg patterns are fixed strings (decision D1). Reject anything that would be
/// a regular expression so results are never silently different from what was asked.
fn literal_pattern(usage: &str, p: &str, rg: bool, fixed: bool) -> Result<String, GErr> {
    if p.is_empty() {
        return Err(grammar(usage, "empty pattern"));
    }
    if !fixed {
        let special: &[char] = if rg {
            &['[', ']', '*', '^', '$', '\\', '+', '?', '(', ')', '{', '}', '|']
        } else {
            &['[', ']', '*', '^', '$', '\\']
        };
        if let Some(c) = p.chars().find(|c| special.contains(c)) {
            return Err(grammar(
                usage,
                format!("regular expressions are not supported ('{c}' in pattern); pass -F to search for the literal text, and run one search per term to look for several terms"),
            ));
        }
    }
    Ok(p.to_string())
}

fn parse(argv: &[String]) -> Result<Cmd, GErr> {
    let name = argv[0].as_str();
    if name.contains('/') {
        return Err(("CMD_GRAMMAR".into(), format!("argv[0] must be a catalog name, not a path: {name}")));
    }
    if !is_catalog_command(name) {
        return Err((
            "CMD_UNKNOWN".into(),
            format!("{name} is not in the cmd.run catalog: {}", CATALOG_NAMES.join(", ")),
        ));
    }
    let u = usage_of(name);
    let rest = &argv[1..];
    match name {
        "ls" => {
            let (mut long, mut all, mut by_time) = (false, false, false);
            let mut paths = Vec::new();
            for a in rest {
                if let Some(cs) = short_cluster(a) {
                    for c in cs {
                        match c {
                            'l' => long = true,
                            'a' | 'A' => all = true,
                            't' => by_time = true,
                            '1' | 'h' => {}
                            _ => return Err(grammar(u, format!("unsupported flag -{c}"))),
                        }
                    }
                } else {
                    paths.push(positional(u, a)?);
                }
            }
            if paths.len() != 1 {
                return Err(grammar(u, "exactly one path is required"));
            }
            Ok(Cmd::Ls { long, all, by_time, path: paths.remove(0) })
        }
        "cat" => {
            if rest.len() != 1 {
                return Err(grammar(u, "exactly one file"));
            }
            Ok(Cmd::Cat { file: positional(u, &rest[0])? })
        }
        "head" | "tail" => {
            let mut n = 10usize;
            let mut file = None;
            let mut i = 0;
            while i < rest.len() {
                let a = &rest[i];
                if a == "-n" {
                    let v = rest.get(i + 1).ok_or_else(|| grammar(u, "-n needs a value"))?;
                    n = parse_count(u, v)?;
                    i += 2;
                    continue;
                } else if let Some(v) = a.strip_prefix("-n") {
                    n = parse_count(u, v)?;
                } else if a.starts_with('-') && a[1..].chars().all(|c| c.is_ascii_digit()) && a.len() > 1 {
                    n = parse_count(u, &a[1..])?;
                } else if file.is_none() {
                    file = Some(positional(u, a)?);
                } else {
                    return Err(grammar(u, "exactly one file"));
                }
                i += 1;
            }
            let file = file.ok_or_else(|| grammar(u, "a file is required"))?;
            Ok(if name == "head" { Cmd::Head { n, file } } else { Cmd::Tail { n, file } })
        }
        "sed" => {
            if rest.len() != 3 || rest[0] != "-n" {
                return Err(grammar(u, "only the form sed -n 'A,Bp' <file> is supported"));
            }
            let script = rest[1].trim_matches(|c| c == '\'' || c == '"');
            let body = script.strip_suffix('p').ok_or_else(|| grammar(u, "script must end with p"))?;
            let (a, b) = match body.split_once(',') {
                Some((a, b)) => (a, Some(b)),
                None => (body, None),
            };
            let from = a.parse::<usize>().ok().filter(|v| *v >= 1).ok_or_else(|| grammar(u, "A must be a line number >= 1"))?;
            let to = match b {
                None => Some(from),
                Some("$") => None,
                Some(b) => {
                    let to = b.parse::<usize>().ok().filter(|v| *v >= from).ok_or_else(|| grammar(u, "B must be a line number >= A, or $"))?;
                    Some(to)
                }
            };
            Ok(Cmd::Sed { from, to, file: positional(u, &rest[2])? })
        }
        "wc" => {
            let (mut lines, mut words, mut bytes) = (false, false, false);
            let mut files = Vec::new();
            for a in rest {
                if let Some(cs) = short_cluster(a) {
                    for c in cs {
                        match c {
                            'l' => lines = true,
                            'w' => words = true,
                            'c' => bytes = true,
                            _ => return Err(grammar(u, format!("unsupported flag -{c}"))),
                        }
                    }
                } else {
                    files.push(positional(u, a)?);
                }
            }
            if files.is_empty() || files.len() > 16 {
                return Err(grammar(u, "1..=16 files"));
            }
            if !lines && !words && !bytes {
                lines = true;
                words = true;
                bytes = true;
            }
            Ok(Cmd::Wc { lines, words, bytes, files })
        }
        "grep" | "rg" => {
            let rg = name == "rg";
            let (mut number, mut ignore_case, mut count, mut files_only, mut recursive, mut fixed) =
                (rg, false, false, false, rg, false);
            let mut pattern: Option<String> = None;
            let mut paths = Vec::new();
            let mut i = 0;
            let mut after_dd = false;
            while i < rest.len() {
                let a = rest[i].as_str();
                if !after_dd && a == "--" {
                    after_dd = true;
                } else if !after_dd && (a == "-e" || a == "--regexp") {
                    let v = rest.get(i + 1).ok_or_else(|| grammar(u, "-e needs a pattern"))?;
                    if pattern.is_some() {
                        return Err(grammar(u, "only one pattern"));
                    }
                    pattern = Some(v.clone());
                    i += 1;
                } else if !after_dd && a.starts_with("--") {
                    match a {
                        "--fixed-strings" => fixed = true,
                        "--line-number" => number = true,
                        "--ignore-case" => ignore_case = true,
                        "--count" => count = true,
                        "--files-with-matches" => files_only = true,
                        "--recursive" => recursive = true,
                        "--no-heading" | "--color=never" | "--no-color" => {}
                        _ => return Err(grammar(u, format!("unsupported option {a}"))),
                    }
                } else if !after_dd && a.len() > 1 && a.starts_with('-') {
                    for c in a[1..].chars() {
                        match c {
                            'n' => number = true,
                            'i' => ignore_case = true,
                            'c' => count = true,
                            'l' => files_only = true,
                            'r' | 'R' => recursive = true,
                            'F' => fixed = true,
                            'H' | 's' => {}
                            'E' | 'P' | 'G' => return Err(grammar(u, "regular expressions are not supported; use -F with a literal")),
                            _ => return Err(grammar(u, format!("unsupported flag -{c}"))),
                        }
                    }
                } else if pattern.is_none() {
                    pattern = Some(a.to_string());
                } else {
                    paths.push(positional(u, a)?);
                }
                i += 1;
            }
            let pattern = pattern.ok_or_else(|| grammar(u, "a pattern is required"))?;
            let pattern = literal_pattern(u, &pattern, rg, fixed)?;
            if paths.is_empty() {
                if rg {
                    paths.push(".".into());
                } else {
                    return Err(grammar(u, "a path is required (stdin is not available)"));
                }
            }
            if paths.len() > 16 {
                return Err(grammar(u, "at most 16 paths"));
            }
            let always_name = recursive || paths.len() > 1;
            Ok(Cmd::Grep { number, ignore_case, count, files_only, recursive, pattern, paths, always_name })
        }
        "shasum" => {
            let mut algo_ok = false;
            let mut files = Vec::new();
            let mut i = 0;
            while i < rest.len() {
                let a = rest[i].as_str();
                if a == "-a" {
                    if rest.get(i + 1).map(String::as_str) != Some("256") {
                        return Err(grammar(u, "only -a 256 is supported"));
                    }
                    algo_ok = true;
                    i += 2;
                    continue;
                } else if a == "-a256" || a == "--algorithm=256" {
                    algo_ok = true;
                } else {
                    files.push(positional(u, a)?);
                }
                i += 1;
            }
            if !algo_ok {
                return Err(grammar(u, "pass -a 256 (the default SHA-1 is not offered)"));
            }
            if files.is_empty() || files.len() > 32 {
                return Err(grammar(u, "1..=32 files"));
            }
            Ok(Cmd::Sha { files })
        }
        "sha256sum" => {
            let files = rest.iter().map(|a| positional(u, a)).collect::<Result<Vec<_>, _>>()?;
            if files.is_empty() || files.len() > 32 {
                return Err(grammar(u, "1..=32 files"));
            }
            Ok(Cmd::Sha { files })
        }
        "cmp" => {
            let mut silent = false;
            let mut files = Vec::new();
            for a in rest {
                if a == "-s" || a == "--silent" || a == "--quiet" {
                    silent = true;
                } else {
                    files.push(positional(u, a)?);
                }
            }
            if files.len() != 2 {
                return Err(grammar(u, "exactly two files"));
            }
            let b = files.pop().unwrap_or_default();
            let a = files.pop().unwrap_or_default();
            Ok(Cmd::Cmp { silent, a, b })
        }
        "stat" => {
            if rest.len() != 1 {
                return Err(grammar(u, "exactly one path"));
            }
            Ok(Cmd::Stat { path: positional(u, &rest[0])? })
        }
        "plutil" => {
            if rest.len() != 2 || rest[0] != "-lint" {
                return Err(grammar(u, "only plutil -lint <file> is supported"));
            }
            Ok(Cmd::Plutil { file: positional(u, &rest[1])? })
        }
        "git" => parse_git(rest),
        _ => Err(grammar(u, "not implemented")),
    }
}

fn valid_rev_strict(s: &str) -> bool {
    if s.is_empty() || s.len() > 100 || s.starts_with('-') {
        return false;
    }
    let parts: Vec<&str> = if s.contains("...") {
        s.split("...").collect()
    } else {
        s.split("..").collect()
    };
    parts.len() <= 2
        && parts.iter().all(|p| {
            p.chars().all(|c| c.is_ascii_alphanumeric() || "._/~^@{}-".contains(c)) && !p.starts_with('-')
        })
}

fn safe_value(v: &str) -> bool {
    v.len() <= 100 && v.chars().all(|c| c.is_ascii_alphanumeric() || " ._-:/+@".contains(c))
}

/// Per-subcommand flag allowlists. Anything not listed is rejected.
fn git_flag_ok(sub: &str, a: &str) -> bool {
    let exact: &[&str] = match sub {
        "status" => &["--porcelain", "--porcelain=v1", "--porcelain=v2", "-s", "--short", "-b", "--branch", "-uno", "--untracked-files=no", "--untracked-files=normal", "--untracked-files=all", "--ignored", "-sb"],
        "log" => &["--oneline", "--stat", "--shortstat", "--numstat", "--name-only", "--name-status", "--decorate", "--no-decorate", "--graph", "--reverse", "--first-parent", "--no-merges", "--merges", "-p", "--patch", "--all", "--abbrev-commit"],
        "diff" => &["--stat", "--shortstat", "--numstat", "--name-only", "--name-status", "--cached", "--staged", "--no-color", "--summary", "-w", "--ignore-all-space"],
        "show" => &["--stat", "--shortstat", "--numstat", "--name-only", "--name-status", "--oneline", "-s", "--no-patch", "--no-color", "--abbrev-commit"],
        "ls-files" => &["--cached", "-c", "--modified", "-m", "--deleted", "-d", "--others", "-o", "--exclude-standard", "-s", "--stage"],
        "rev-parse" => &["--abbrev-ref", "--short", "--verify", "--show-toplevel", "--is-inside-work-tree", "--git-dir"],
        "blame" => &["-w", "-s", "--porcelain", "-e"],
        _ => &[],
    };
    if exact.contains(&a) {
        return true;
    }
    let with_value = |prefix: &str| a.strip_prefix(prefix).map(safe_value).unwrap_or(false);
    match sub {
        "log" => {
            (a.starts_with('-') && a.len() > 1 && a[1..].chars().all(|c| c.is_ascii_digit()) && a[1..].parse::<u32>().map(|n| n <= 500).unwrap_or(false))
                || a.strip_prefix("--max-count=").and_then(|v| v.parse::<u32>().ok()).map(|n| n <= 500).unwrap_or(false)
                || with_value("--since=")
                || with_value("--until=")
                || with_value("--author=")
                || with_value("--grep=")
                || matches!(a, "--date=iso" | "--date=short" | "--date=relative" | "--date=iso-strict")
                || matches!(a, "--pretty=oneline" | "--pretty=short" | "--pretty=medium" | "--pretty=full" | "--pretty=fuller" | "--format=oneline" | "--format=short" | "--format=medium" | "--format=full" | "--format=fuller")
        }
        "diff" | "show" => a.strip_prefix("--unified=").or_else(|| a.strip_prefix("-U")).and_then(|v| v.parse::<u32>().ok()).map(|n| n <= 50).unwrap_or(false),
        "rev-parse" => a.strip_prefix("--short=").and_then(|v| v.parse::<u32>().ok()).map(|n| n <= 40).unwrap_or(false),
        "blame" => {
            // -L A,B
            a.strip_prefix("-L").map(|v| {
                let v = v.trim();
                let mut it = v.split(',');
                matches!((it.next(), it.next(), it.next()), (Some(x), Some(y), None) if x.parse::<u32>().is_ok() && y.parse::<u32>().is_ok())
            }).unwrap_or(false)
        }
        _ => false,
    }
}

fn parse_git(rest: &[String]) -> Result<Cmd, GErr> {
    let u = usage_of("git");
    let mut i = 0;
    let mut dir = None;
    if rest.first().map(String::as_str) == Some("-C") {
        dir = Some(rest.get(1).ok_or_else(|| grammar(u, "-C needs a directory"))?.clone());
        i = 2;
    }
    let dir = dir.ok_or_else(|| grammar(u, "start with -C <repo dir> (a directory inside a granted root, or relative for the sandbox)"))?;
    if dir.starts_with('-') {
        return Err(grammar(u, "bad -C directory"));
    }
    let sub = rest.get(i).ok_or_else(|| grammar(u, "a subcommand is required"))?.clone();
    if !matches!(sub.as_str(), "status" | "log" | "diff" | "show" | "ls-files" | "rev-parse" | "blame") {
        return Err(grammar(u, format!("git {sub} is not allowed")));
    }
    i += 1;
    let mut args = Vec::new();
    let mut paths = Vec::new();
    let mut after_dd = false;
    let mut it = rest[i..].iter().peekable();
    while let Some(a) = it.next() {
        if after_dd {
            paths.push(positional(u, a)?);
            continue;
        }
        if a == "--" {
            after_dd = true;
            continue;
        }
        if a == "-n" && sub == "log" {
            let v = it.next().ok_or_else(|| grammar(u, "-n needs a value"))?;
            match v.parse::<u32>() {
                Ok(n) if (1..=500).contains(&n) => {
                    args.push(format!("--max-count={n}"));
                    continue;
                }
                _ => return Err(grammar(u, "-n must be 1..=500")),
            }
        }
        if a == "-L" && sub == "blame" {
            let v = it.next().ok_or_else(|| grammar(u, "-L needs A,B"))?;
            let joined = format!("-L{v}");
            if !git_flag_ok("blame", &joined) {
                return Err(grammar(u, "-L must be A,B line numbers"));
            }
            args.push(joined);
            continue;
        }
        if a.starts_with('-') {
            if !git_flag_ok(&sub, a) {
                return Err(grammar(u, format!("git {sub} does not allow {a}")));
            }
            args.push(a.clone());
            continue;
        }
        // Revisions (and rev:path for show).
        if sub == "show" {
            if let Some((rev, path)) = a.split_once(':') {
                if !(rev.is_empty() || valid_rev_strict(rev)) || path.is_empty() || path.starts_with('-') {
                    return Err(grammar(u, format!("bad rev:path {a}")));
                }
                args.push(a.clone());
                continue;
            }
        }
        if matches!(sub.as_str(), "status" | "ls-files") {
            // These take only paths; treat bare words as paths.
            paths.push(positional(u, a)?);
            continue;
        }
        if sub == "blame" {
            // blame [<rev>] <file>: a bare word that is not a rev is the file.
            if valid_rev_strict(a) && it.peek().is_some() {
                args.push(a.clone());
            } else {
                paths.push(positional(u, a)?);
            }
            continue;
        }
        if !valid_rev_strict(a) {
            return Err(grammar(u, format!("bad revision {a}")));
        }
        args.push(a.clone());
    }
    if sub == "blame" && paths.len() != 1 {
        return Err(grammar(u, "git blame needs exactly one file"));
    }
    for p in &paths {
        if p.len() > 512 || p.contains(':') && p.starts_with(':') {
            return Err(grammar(u, format!("bad pathspec {p} (pathspec magic is not allowed)")));
        }
    }
    Ok(Cmd::Git { dir, sub, args, paths })
}

// ---------------------------------------------------------------------------
// Authorisation (called by the authority broker before dispatch)
// ---------------------------------------------------------------------------

fn cmd_name(argv: &[String]) -> &str {
    argv.first().map(String::as_str).unwrap_or("")
}

fn argv_of(args: &serde_json::Value) -> Vec<String> {
    args["argv"]
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap_or("").to_string()).collect())
        .unwrap_or_default()
}

fn paths_of(c: &Cmd) -> Vec<&str> {
    match c {
        Cmd::Ls { path, .. } | Cmd::Stat { path } => vec![path],
        Cmd::Cat { file } | Cmd::Head { file, .. } | Cmd::Tail { file, .. } | Cmd::Sed { file, .. } | Cmd::Plutil { file } => vec![file],
        Cmd::Wc { files, .. } | Cmd::Sha { files } => files.iter().map(String::as_str).collect(),
        Cmd::Grep { paths, .. } => paths.iter().map(String::as_str).collect(),
        Cmd::Cmp { a, b, .. } => vec![a, b],
        Cmd::Git { dir, .. } => vec![dir],
    }
}

/// Grammar + enabled + every path argument resolves. Returns a one-line summary.
pub fn authorize(args: &serde_json::Value, ctx: &AuthorityContext) -> Result<String, (String, String)> {
    let argv = argv_of(args);
    if argv.is_empty() {
        return Err(("CMD_GRAMMAR".into(), "argv is empty".into()));
    }
    let name = cmd_name(&argv).to_string();
    if !is_catalog_command(&name) {
        return Err(parse(&argv).err().unwrap_or_else(|| ("CMD_UNKNOWN".into(), name.clone())));
    }
    if !ctx.cmd.is_enabled(&name) {
        return Err((
            "CMD_POLICY".into(),
            format!("{name} is not enabled for this run; enabled: {}", ctx.cmd.enabled().join(", ")),
        ));
    }
    let c = parse(&argv)?;
    for p in paths_of(&c) {
        // Gate 10: a file this run proposed is read from the proposal (git reads the disk and gets no exception).
        if !matches!(c, Cmd::Git { .. }) && ctx.proposal.as_ref().is_some_and(|pr| pr.has(p)) {
            continue;
        }
        readers::resolve(ctx, p).map_err(|e| (e.code, e.detail))?;
    }
    if let Cmd::Git { dir, .. } = &c {
        git_repo(ctx, dir).map_err(|e| (e.code, e.detail))?;
    }
    Ok(format!("{name}: arguments inside granted roots or the sandbox"))
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

struct Out {
    stdout: String,
    stderr: String,
    exit: i32,
    targets: Vec<serde_json::Value>,
    native: bool,
    note: Option<String>,
}

impl Out {
    fn new() -> Self {
        Out { stdout: String::new(), stderr: String::new(), exit: 0, targets: Vec::new(), native: true, note: None }
    }
    fn target(&mut self, t: &readers::Target, kind: &str) {
        self.targets.push(t.json(kind));
    }
}

fn to_cap(e: ReadErr) -> CapabilityError {
    e.into()
}

/// UTC "YYYY-MM-DD HH:MM" without a date library.
pub fn utc(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}", secs / 3600, (secs % 3600) / 60)
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).to_string()
}

fn lines_of(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

fn run_ls(ctx: &AuthorityContext, long: bool, all: bool, by_time: bool, path: &str, o: &mut Out) -> Result<(), CapabilityError> {
    let proposed_only = ctx
        .proposal
        .as_ref()
        .and_then(|p| p.stat(path))
        .is_some_and(|(key, ..)| std::fs::symlink_metadata(&key).is_err());
    let (t, is_dir) = if proposed_only {
        (None, false)
    } else {
        let (_pol, r, t) = readers::resolve(ctx, path).map_err(to_cap)?;
        (Some(t), std::fs::symlink_metadata(&r.path).map(|m| m.is_dir()).unwrap_or(false))
    };
    let fmt = |e: &readers::Entry| {
        if long {
            format!("{} {:>8} {:>10} {} {}\n", e.mode, e.owner, e.size, utc(e.mtime), e.name)
        } else {
            format!("{}\n", e.name)
        }
    };
    if !is_dir {
        let (t, mut e) = readers::stat(ctx, path).map_err(to_cap)?;
        e.name = path.to_string();
        o.stdout.push_str(&fmt(&e));
        o.target(&t, "stat");
        return Ok(());
    }
    let l = readers::list(ctx, path, if by_time { "mtime" } else { "name" }, 5_000, all).map_err(to_cap)?;
    for e in &l.entries {
        o.stdout.push_str(&fmt(e));
    }
    if l.denied_omitted > 0 {
        o.note = Some(format!("{} entries on the deny list were omitted", l.denied_omitted));
    }
    if l.truncated {
        o.note = Some(format!("{} listing truncated at {} entries", o.note.clone().unwrap_or_default(), l.entries.len()));
    }
    if let Some(t) = &t {
        o.target(t, "directory");
    }
    Ok(())
}

fn run_grep(ctx: &AuthorityContext, c: &Cmd, o: &mut Out) -> Result<(), CapabilityError> {
    let Cmd::Grep { number, ignore_case, count, files_only, recursive, pattern, paths, always_name } = c else {
        return Ok(());
    };
    let needle = if *ignore_case { pattern.to_lowercase() } else { pattern.clone() };
    let mut matches_total = 0usize;
    let mut files_scanned = 0usize;
    let mut skipped_binary = 0usize;
    let mut skipped_large = 0usize;
    let mut any = false;
    for p in paths {
        // Gate 10: a file that exists only in the run's proposal is searched there.
        let overlay_only = ctx
            .proposal
            .as_ref()
            .and_then(|pr| pr.read(p))
            .filter(|(key, _, _)| std::fs::symlink_metadata(key).is_err())
            .map(|(key, root, _)| (key, root));
        let (pol, r, t, is_dir) = match overlay_only {
            Some((key, root)) => {
                let t = readers::Target { shown: p.clone(), canonical: key.clone(), root: root.clone(), from_proposal: true };
                (ctx.roots.clone(), roots::Resolved { path: key, root }, t, false)
            }
            None => {
                let (pol, r, t) = readers::resolve(ctx, p).map_err(to_cap)?;
                let meta = std::fs::symlink_metadata(&r.path).map_err(|e| to_cap(ReadErr { code: "FS_STAT_FAILED".into(), detail: e.to_string(), policy: false }))?;
                (pol, r, t, meta.is_dir())
            }
        };
        // Collect files: the path itself, or a depth-first walk (no symlinks followed).
        let mut files: Vec<(String, roots::Resolved)> = Vec::new();
        if is_dir {
            if !*recursive {
                o.stderr.push_str(&format!("grep: {p}: is a directory (use -r)\n"));
                continue;
            }
            o.target(&t, "directory");
            let mut stack = vec![r.clone()];
            let mut dirs_seen = 0usize;
            while let Some(dir) = stack.pop() {
                dirs_seen += 1;
                if dirs_seen > GREP_MAX_DIRS {
                    o.note = Some(format!("stopped after {GREP_MAX_DIRS} directories"));
                    break;
                }
                if crate::gateway::CANCELLED.load(Ordering::SeqCst) {
                    return Err(CapabilityError { code: "CAPABILITY_CANCELLED".into(), detail: "grep walk cancelled".into(), policy_rejection: false, real_execution: true });
                }
                let d = pol.open_dir(&dir).map_err(|e| to_cap(ReadErr { code: e.code.into(), detail: e.detail, policy: true }))?;
                let (mut entries, _) = roots::list_dir_fd(&d, 50_000).map_err(|e| to_cap(ReadErr { code: e.code.into(), detail: e.detail, policy: false }))?;
                entries.sort_by(|a, b| b.name.cmp(&a.name));
                for e in entries {
                    let child = dir.path.join(&e.name);
                    let Ok(res) = pol.resolve(&child.to_string_lossy()) else { continue }; // denied or vanished
                    match e.kind {
                        "directory" => stack.push(res),
                        "file" => {
                            let shown = if let Ok(rel) = child.strip_prefix(&r.path) {
                                format!("{}/{}", p.trim_end_matches('/'), rel.display())
                            } else {
                                child.display().to_string()
                            };
                            files.push((shown, res));
                        }
                        _ => {}
                    }
                    if files.len() >= GREP_MAX_FILES {
                        break;
                    }
                }
                // Gate 10: new files the proposal adds to this directory.
                if let Some(pr) = &ctx.proposal {
                    for (name, _, _, is_new, _) in pr.children(&dir.path) {
                        if !is_new || files.len() >= GREP_MAX_FILES {
                            continue;
                        }
                        let child = dir.path.join(&name);
                        let shown = match child.strip_prefix(&r.path) {
                            Ok(rel) => format!("{}/{}", p.trim_end_matches('/'), rel.display()),
                            Err(_) => child.display().to_string(),
                        };
                        files.push((shown, roots::Resolved { path: child, root: dir.root.clone() }));
                    }
                }
                if files.len() >= GREP_MAX_FILES {
                    o.note = Some(format!("stopped after {GREP_MAX_FILES} files"));
                    break;
                }
            }
            // Walk order: stack pops reverse-sorted children, giving sorted output per directory.
        } else {
            o.target(&t, "file");
            files.push((p.clone(), r.clone()));
        }
        let mut bytes_scanned = 0u64;
        for (shown, res) in files {
            if crate::gateway::CANCELLED.load(Ordering::SeqCst) {
                return Err(CapabilityError { code: "CAPABILITY_CANCELLED".into(), detail: "grep cancelled".into(), policy_rejection: false, real_execution: true });
            }
            if bytes_scanned > GREP_MAX_BYTES {
                o.note = Some(format!("stopped after scanning {GREP_MAX_BYTES} bytes"));
                break;
            }
            // Gate 10: the proposal's version first.
            let buf = if let Some((_, _, b)) = ctx.proposal.as_ref().and_then(|pr| pr.read(&res.path.to_string_lossy())) {
                b
            } else {
                let (mut f, size) = match pol.open_file(&res) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                if size > roots::MAX_FILE_BYTES {
                    skipped_large += 1;
                    continue;
                }
                let mut buf = Vec::new();
                if (&mut f).take(roots::MAX_FILE_BYTES).read_to_end(&mut buf).is_err() {
                    continue;
                }
                buf
            };
            files_scanned += 1;
            bytes_scanned += buf.len() as u64;
            if buf.iter().take(8192).any(|b| *b == 0) {
                skipped_binary += 1;
                continue;
            }
            let text = text_of(&buf);
            let mut file_count = 0usize;
            for (i, line) in text.lines().enumerate() {
                let hay = if *ignore_case { line.to_lowercase() } else { line.to_string() };
                if !hay.contains(&needle) {
                    continue;
                }
                file_count += 1;
                any = true;
                if *files_only || *count {
                    continue;
                }
                matches_total += 1;
                if matches_total > GREP_MAX_MATCHES {
                    break;
                }
                let mut shown_line: String = line.chars().take(LINE_DISPLAY_MAX).collect();
                if line.chars().count() > LINE_DISPLAY_MAX {
                    shown_line.push('…');
                }
                let prefix = match (*always_name, *number) {
                    (true, true) => format!("{shown}:{}:", i + 1),
                    (true, false) => format!("{shown}:"),
                    (false, true) => format!("{}:", i + 1),
                    (false, false) => String::new(),
                };
                o.stdout.push_str(&format!("{prefix}{shown_line}\n"));
            }
            if *files_only && file_count > 0 {
                o.stdout.push_str(&format!("{shown}\n"));
            } else if *count && !*files_only {
                if *always_name {
                    o.stdout.push_str(&format!("{shown}:{file_count}\n"));
                } else {
                    o.stdout.push_str(&format!("{file_count}\n"));
                }
            }
            if matches_total > GREP_MAX_MATCHES {
                o.note = Some(format!("stopped after {GREP_MAX_MATCHES} matching lines"));
                break;
            }
        }
    }
    let mut notes = Vec::new();
    if let Some(n) = o.note.take() {
        notes.push(n);
    }
    notes.push(format!("fixed-string search; {files_scanned} files scanned"));
    if skipped_binary > 0 {
        notes.push(format!("{skipped_binary} binary files skipped"));
    }
    if skipped_large > 0 {
        notes.push(format!("{skipped_large} files over {} bytes skipped", roots::MAX_FILE_BYTES));
    }
    o.note = Some(notes.join("; "));
    o.exit = if any { 0 } else { 1 };
    Ok(())
}

fn run_native(ctx: &AuthorityContext, c: &Cmd, o: &mut Out) -> Result<(), CapabilityError> {
    match c {
        Cmd::Ls { long, all, by_time, path } => run_ls(ctx, *long, *all, *by_time, path, o)?,
        Cmd::Cat { file } => {
            let (t, b) = readers::read_bytes(ctx, file).map_err(to_cap)?;
            o.stdout = text_of(&b);
            o.target(&t, "file");
        }
        Cmd::Head { n, file } | Cmd::Tail { n, file } => {
            let (t, b) = readers::read_bytes(ctx, file).map_err(to_cap)?;
            let text = text_of(&b);
            let lines = lines_of(&text);
            let pick: Vec<&str> = if matches!(c, Cmd::Head { .. }) {
                lines.iter().take(*n).copied().collect()
            } else {
                lines.iter().skip(lines.len().saturating_sub(*n)).copied().collect()
            };
            o.stdout = pick.concat();
            o.target(&t, "file");
        }
        Cmd::Sed { from, to, file } => {
            let (t, b) = readers::read_bytes(ctx, file).map_err(to_cap)?;
            let text = text_of(&b);
            let end = to.unwrap_or(usize::MAX);
            o.stdout = lines_of(&text)
                .iter()
                .enumerate()
                .filter(|(i, _)| i + 1 >= *from && i + 1 <= end)
                .map(|(_, l)| *l)
                .collect();
            o.target(&t, "file");
        }
        Cmd::Wc { lines, words, bytes, files } => {
            for f in files {
                let (t, b) = readers::read_bytes(ctx, f).map_err(to_cap)?;
                let text = text_of(&b);
                let mut cols = Vec::new();
                if *lines {
                    cols.push(format!("{:>8}", b.iter().filter(|x| **x == b'\n').count()));
                }
                if *words {
                    cols.push(format!("{:>8}", text.split_whitespace().count()));
                }
                if *bytes {
                    cols.push(format!("{:>8}", b.len()));
                }
                o.stdout.push_str(&format!("{} {f}\n", cols.join("")));
                o.target(&t, "file");
            }
        }
        Cmd::Grep { .. } => run_grep(ctx, c, o)?,
        Cmd::Sha { files } => {
            for f in files {
                let (t, b) = readers::read_bytes(ctx, f).map_err(to_cap)?;
                let d = crate::audit::sha256_bytes(&b);
                o.stdout.push_str(&format!("{d}  {f}\n"));
                let mut j = t.json("file");
                j["sha256"] = serde_json::json!(d);
                o.targets.push(j);
            }
        }
        Cmd::Cmp { silent, a, b } => {
            let (ta, ba) = readers::read_bytes(ctx, a).map_err(to_cap)?;
            let (tb, bb) = readers::read_bytes(ctx, b).map_err(to_cap)?;
            o.target(&ta, "file");
            o.target(&tb, "file");
            let first_diff = ba.iter().zip(bb.iter()).position(|(x, y)| x != y);
            match first_diff {
                None if ba.len() == bb.len() => o.exit = 0,
                None => {
                    o.exit = 1;
                    if !silent {
                        let shorter = if ba.len() < bb.len() { a } else { b };
                        o.stderr = format!("cmp: EOF on {shorter} after byte {}\n", ba.len().min(bb.len()));
                    }
                }
                Some(i) => {
                    o.exit = 1;
                    if !silent {
                        let line = ba[..i].iter().filter(|c| **c == b'\n').count() + 1;
                        o.stdout = format!("{a} {b} differ: byte {}, line {line}\n", i + 1);
                    }
                }
            }
        }
        Cmd::Stat { path } => {
            let (t, e) = readers::stat(ctx, path).map_err(to_cap)?;
            o.stdout = format!(
                "  File: {path}\n  Kind: {}\n  Size: {}\n  Mode: {}\n Owner: {}\nModify: {} UTC\n",
                e.kind, e.size, e.mode, e.owner, utc(e.mtime)
            );
            o.target(&t, "stat");
        }
        Cmd::Git { .. } | Cmd::Plutil { .. } => unreachable!("process commands are not native"),
    }
    Ok(())
}

/// Run a program from a fixed path with a cleared environment, no stdin, its own
/// process group, concurrent capped reads of stdout/stderr, and a timeout.
fn spawn_capped(program: &Path, args: &[String], cwd: &Path, env: &[(&str, String)], timeout: Duration) -> Result<(i32, Vec<u8>, bool, Vec<u8>, bool), CapabilityError> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .current_dir(cwd)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.process_group(0);
    let mut child = cmd.spawn().map_err(|e| CapabilityError {
        code: "CMD_SPAWN_FAILED".into(),
        detail: format!("{}: {e}", program.display()),
        policy_rejection: false,
        real_execution: false,
    })?;
    let pgid = child.id() as i32;
    fn reader(mut s: impl Read + Send + 'static, cap: usize) -> std::thread::JoinHandle<(Vec<u8>, bool)> {
        std::thread::spawn(move || {
            let mut keep = Vec::new();
            let mut buf = [0u8; 8192];
            let mut over = false;
            loop {
                match s.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let room = cap.saturating_sub(keep.len());
                        keep.extend_from_slice(&buf[..n.min(room)]);
                        if n > room {
                            over = true; // keep draining so the child never blocks
                        }
                    }
                }
            }
            (keep, over)
        })
    }
    let out_h = reader(child.stdout.take().expect("piped"), STDOUT_CAP);
    let err_h = reader(child.stderr.take().expect("piped"), STDERR_CAP);
    let start = Instant::now();
    let kill = |child: &mut std::process::Child| {
        unsafe {
            libc::kill(-pgid, libc::SIGKILL);
        }
        let _ = child.kill();
        let _ = child.wait();
    };
    let status = loop {
        if crate::gateway::CANCELLED.load(Ordering::SeqCst) {
            kill(&mut child);
            return Err(CapabilityError { code: "CAPABILITY_CANCELLED".into(), detail: format!("process_group={pgid}"), policy_rejection: false, real_execution: true });
        }
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) => {}
            Err(e) => {
                kill(&mut child);
                return Err(CapabilityError { code: "CMD_WAIT_FAILED".into(), detail: e.to_string(), policy_rejection: false, real_execution: true });
            }
        }
        if start.elapsed() >= timeout {
            kill(&mut child);
            return Err(CapabilityError {
                code: "CAPABILITY_TIMEOUT".into(),
                detail: format!("{} exceeded {} s; process group {pgid} killed", program.display(), timeout.as_secs()),
                policy_rejection: false,
                real_execution: true,
            });
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // Kill anything the child left behind in its group before collecting output.
    unsafe {
        libc::kill(-pgid, libc::SIGKILL);
    }
    let (out, out_over) = out_h.join().unwrap_or_default();
    let (err, err_over) = err_h.join().unwrap_or_default();
    Ok((status.code().unwrap_or(-1), out, out_over, err, err_over))
}

/// Find the repository for `dir`: walk up from it to the granting root looking for a
/// real `.git` directory. A `.git` *file* (worktree/submodule pointer) is refused,
/// because it can point outside the root.
fn git_repo(ctx: &AuthorityContext, dir: &str) -> Result<(RootPolicy, PathBuf), ReadErr> {
    let (pol, r, _t) = readers::resolve(ctx, dir)?;
    if !std::fs::symlink_metadata(&r.path).map(|m| m.is_dir()).unwrap_or(false) {
        return Err(ReadErr { code: "CMD_POLICY".into(), detail: format!("{dir} is not a directory"), policy: true });
    }
    let root_path = pol.roots().iter().find(|x| x.name == r.root).map(|x| x.path.clone()).unwrap_or_default();
    let mut cur = r.path.clone();
    loop {
        let dotgit = cur.join(".git");
        if let Ok(m) = std::fs::symlink_metadata(&dotgit) {
            if m.is_dir() {
                git_dir_safe(&dotgit)?;
                return Ok((pol, cur));
            }
            return Err(ReadErr {
                code: "CMD_POLICY".into(),
                detail: format!("{} is not a plain .git directory (worktree or submodule pointers are refused)", dotgit.display()),
                policy: true,
            });
        }
        if cur == root_path || !cur.pop() || !cur.starts_with(&root_path) {
            break;
        }
    }
    Err(ReadErr { code: "CMD_POLICY".into(), detail: format!("no git repository at or above {dir} inside its root"), policy: true })
}

/// Refuse repository layouts that could make git read or run things outside the root:
/// $GIT_DIR/info/attributes (the one attribute source --attr-source does not replace),
/// object alternates, a worktree common dir, and symlinks among git's own files.
fn git_dir_safe(dotgit: &Path) -> Result<(), ReadErr> {
    let refuse = |why: String| ReadErr { code: "CMD_POLICY".into(), detail: why, policy: true };
    for rel in ["info/attributes", "objects/info/alternates", "objects/info/http-alternates", "commondir"] {
        if std::fs::symlink_metadata(dotgit.join(rel)).is_ok() {
            return Err(refuse(format!("{} exists; git is refused for this repository", dotgit.join(rel).display())));
        }
    }
    for rel in ["config", "HEAD", "index", "packed-refs", "objects", "refs", "info", "objects/pack"] {
        if let Ok(m) = std::fs::symlink_metadata(dotgit.join(rel)) {
            if m.file_type().is_symlink() {
                return Err(refuse(format!("{} is a symlink; git is refused for this repository", dotgit.join(rel).display())));
            }
        }
    }
    Ok(())
}

/// Object type of `rev` (commit, tag, tree, blob), using the same hardened invocation.
fn git_object_type(git: &Path, repo: &Path, env: &[(&str, String)], base: &[String], rev: &str, timeout: Duration) -> Result<String, CapabilityError> {
    let mut a: Vec<String> = base.to_vec();
    a.extend(["cat-file".to_string(), "-t".to_string(), "--end-of-options".to_string(), format!("{rev}^{{object}}")]);
    let (code, out, _, err, _) = spawn_capped(git, &a, repo, env, timeout)?;
    if code != 0 {
        return Err(CapabilityError { code: "CMD_FAILED".into(), detail: format!("git cannot resolve {rev}: {}", text_of(&err).trim()), policy_rejection: false, real_execution: true });
    }
    Ok(text_of(&out).trim().to_string())
}

/// Pathspecs that keep deny-listed files out of git output (history included).
fn git_exclusions(extra: &[String]) -> Vec<String> {
    let mut v = Vec::new();
    for c in roots::DENY_COMPONENTS {
        v.push(format!(":(exclude,glob)**/{c}/**"));
    }
    for b in roots::DENY_BASENAMES.iter().map(|s| s.to_string()).chain(extra.iter().cloned()) {
        v.push(format!(":(exclude,glob)**/{b}"));
    }
    v
}

fn denied_repo_path(pol: &RootPolicy, root_name: &str, repo: &Path, rel: &str) -> Option<String> {
    let root = pol.roots().iter().find(|r| r.name == root_name)?;
    let p = repo.join(rel);
    pol.deny_reason(&p, root)
}

fn run_git(ctx: &AuthorityContext, c: &Cmd, o: &mut Out) -> Result<(), CapabilityError> {
    let Cmd::Git { dir, sub, args, paths } = c else { return Ok(()) };
    let git = ctx.cmd.git.clone().ok_or_else(|| CapabilityError { code: "CMD_POLICY".into(), detail: "git is not enabled".into(), policy_rejection: true, real_execution: false })?;
    let (pol, repo) = git_repo(ctx, dir).map_err(to_cap)?;
    let (_p, r, t) = readers::resolve(ctx, dir).map_err(to_cap)?;
    // Deny-listed paths may not be named directly (paths, rev:path, blame file).
    let rev_paths = args
        .iter()
        .filter(|a| !a.starts_with('-'))
        .filter_map(|a| a.split_once(':').map(|(_, p)| p));
    for rel in paths.iter().map(String::as_str).chain(rev_paths) {
        let rel = rel.trim_start_matches("./");
        if rel.starts_with('/') || rel.split('/').any(|c| c == "..") {
            return Err(CapabilityError { code: "CMD_GRAMMAR".into(), detail: format!("git paths must be relative to the repository without '..': {rel}"), policy_rejection: true, real_execution: false });
        }
        if let Some(reason) = denied_repo_path(&pol, &r.root, &repo, rel) {
            return Err(CapabilityError { code: "DENY_LIST".into(), detail: format!("{rel}: {reason}"), policy_rejection: true, real_execution: false });
        }
    }
    let git_dir = repo.join(".git");
    let base: Vec<String> = vec![
        "--no-pager".into(),
        format!("--attr-source={EMPTY_TREE}"),
        "-c".into(), "core.attributesFile=/dev/null".into(),
        "-c".into(), "submodule.recurse=false".into(),
        "-c".into(), "diff.ignoreSubmodules=all".into(),
        "-c".into(), "status.submoduleSummary=false".into(),
        "-c".into(), "core.fsmonitor=false".into(),
        "-c".into(), "core.pager=cat".into(),
        "-c".into(), "core.hooksPath=/dev/null".into(),
        "-c".into(), "diff.external=".into(),
        "-c".into(), "log.showSignature=false".into(),
        "-c".into(), "gpg.program=/usr/bin/false".into(),
        "-c".into(), "gpg.ssh.program=/usr/bin/false".into(),
        "-c".into(), "gpg.x509.program=/usr/bin/false".into(),
        "-c".into(), "log.mailmap=false".into(),
        "-c".into(), "mailmap.file=/dev/null".into(),
        "-c".into(), "mailmap.blob=".into(),
        "-c".into(), "blame.ignoreRevsFile=".into(),
        "-c".into(), "protocol.allow=never".into(),
        "-c".into(), "core.sshCommand=/usr/bin/false".into(),
        "-c".into(), format!("safe.directory={}", repo.display()),
    ];
    let env = [
        ("PATH", "/usr/bin:/bin".to_string()),
        ("LC_ALL", "C".to_string()),
        ("HOME", ctx.sandbox_root.as_ref().map(|p| p.display().to_string()).unwrap_or_else(|| "/nonexistent".into())),
        ("GIT_DIR", git_dir.display().to_string()),
        ("GIT_WORK_TREE", repo.display().to_string()),
        ("GIT_CONFIG_NOSYSTEM", "1".to_string()),
        ("GIT_CONFIG_GLOBAL", "/dev/null".to_string()),
        ("GIT_ATTR_NOSYSTEM", "1".to_string()),
        ("GIT_OPTIONAL_LOCKS", "0".to_string()),
        ("GIT_TERMINAL_PROMPT", "0".to_string()),
        ("GIT_NO_LAZY_FETCH", "1".to_string()),
        ("GIT_NO_REPLACE_OBJECTS", "1".to_string()),
        ("GIT_PAGER", "cat".to_string()),
    ];
    // Bare object names can reach a deny-listed file's content with no path attached
    // (e.g. a blob hash taken from `git show HEAD^{tree}`), so revisions given to
    // show/diff/log/blame must resolve to commits, tags or trees. Blobs are only
    // reachable as <rev>:<path>, whose path was deny-checked above.
    if matches!(sub.as_str(), "show" | "diff" | "log" | "blame") {
        for rev in args.iter().filter(|a| !a.starts_with('-') && !a.contains(':')) {
            let parts: Vec<&str> = if rev.contains("...") { rev.split("...").collect() } else { rev.split("..").collect() };
            for part in parts.into_iter().filter(|p| !p.is_empty()) {
                let kind = git_object_type(&git, &repo, &env, &base, part, ctx.cmd.timeout)?;
                if !matches!(kind.as_str(), "commit" | "tag" | "tree") {
                    return Err(CapabilityError {
                        code: "DENY_LIST".into(),
                        detail: format!("{part} is a {kind}; name file contents as <rev>:<path> so the path can be checked"),
                        policy_rejection: true,
                        real_execution: false,
                    });
                }
            }
        }
    }
    let mut full = base.clone();
    full.push(sub.clone());
    if matches!(sub.as_str(), "status" | "diff") {
        full.push("--ignore-submodules=all".into());
    }
    if matches!(sub.as_str(), "log" | "diff" | "show") {
        full.push("--no-ext-diff".into());
        full.push("--no-textconv".into());
        full.push("--no-color".into());
    }
    if sub == "blame" {
        full.push("--no-textconv".into());
    }
    full.extend(args.iter().cloned());
    if matches!(sub.as_str(), "log" | "diff" | "show" | "status" | "ls-files") {
        full.push("--".into());
        full.extend(paths.iter().cloned());
        full.extend(git_exclusions(&ctx.roots.deny_extra()));
    } else if sub == "blame" {
        full.push("--".into());
        full.extend(paths.iter().cloned());
    }
    let (code, out, out_over, err, _err_over) = spawn_capped(&git, &full, &repo, &env, ctx.cmd.timeout)?;
    o.native = false;
    o.exit = code;
    o.stdout = text_of(&out);
    o.stderr = text_of(&err);
    if out_over {
        o.note = Some(format!("git output truncated at {STDOUT_CAP} bytes"));
    }
    let mut j = t.json("git_repository");
    j["git_dir"] = serde_json::json!(git_dir.display().to_string());
    o.targets.push(j);
    Ok(())
}

fn run_plutil(ctx: &AuthorityContext, file: &str, o: &mut Out) -> Result<(), CapabilityError> {
    let plutil = ctx.cmd.plutil.clone().ok_or_else(|| CapabilityError { code: "CMD_POLICY".into(), detail: "plutil is not enabled".into(), policy_rejection: true, real_execution: false })?;
    // plutil never opens the original path: it lints a copy of the bytes read through the
    // race-checked descriptor, so a swap after the check cannot redirect it.
    let (t, bytes) = readers::read_bytes(ctx, file).map_err(to_cap)?;
    let scratch_dir = ctx.sandbox_root.clone().unwrap_or_else(std::env::temp_dir);
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let copy = scratch_dir.join(format!(".hercules-plutil-{}-{nonce}.plist", std::process::id()));
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&copy)
            .map_err(|e| CapabilityError { code: "CMD_SPAWN_FAILED".into(), detail: format!("scratch copy: {e}"), policy_rejection: false, real_execution: false })?;
        f.write_all(&bytes)
            .map_err(|e| CapabilityError { code: "CMD_SPAWN_FAILED".into(), detail: format!("scratch copy: {e}"), policy_rejection: false, real_execution: false })?;
    }
    let env = [("PATH", "/usr/bin:/bin".to_string()), ("LC_ALL", "C".to_string())];
    let args = vec!["-lint".to_string(), "--".to_string(), copy.display().to_string()];
    let result = spawn_capped(&plutil, &args, &scratch_dir, &env, ctx.cmd.timeout);
    let _ = std::fs::remove_file(&copy);
    let (code, out, _, err, _) = result?;
    o.native = false;
    o.exit = code;
    o.stdout = text_of(&out).replace(&copy.display().to_string(), file);
    o.stderr = text_of(&err).replace(&copy.display().to_string(), file);
    o.target(&t, "file");
    Ok(())
}

/// Keep stdout within the JSON budget, cutting at a line boundary.
fn bound_stdout(s: &str) -> (String, bool) {
    // Each shown line is rendered with a "| " prefix (tools::render_observation).
    // (Build 3.4: inside a batch the budget is the space the batch has left.)
    let w = readers::window_lines(s, 1, None, readers::content_budget().saturating_sub(2_000).max(256), 3);
    (w.content, w.truncated)
}

pub fn run(args: &serde_json::Value, ctx: &AuthorityContext) -> Result<CapabilityOutcome, CapabilityError> {
    let argv = argv_of(args);
    let c = parse(&argv).map_err(|(code, detail)| CapabilityError { code, detail, policy_rejection: true, real_execution: false })?;
    if !ctx.cmd.is_enabled(cmd_name(&argv)) {
        return Err(CapabilityError { code: "CMD_POLICY".into(), detail: "not enabled".into(), policy_rejection: true, real_execution: false });
    }
    let mut o = Out::new();
    match &c {
        Cmd::Git { .. } => run_git(ctx, &c, &mut o)?,
        Cmd::Plutil { file } => run_plutil(ctx, file, &mut o)?,
        _ => run_native(ctx, &c, &mut o)?,
    }
    let (stdout, truncated) = bound_stdout(&o.stdout);
    let shown = crate::audit::sha256_text(&stdout);
    for t in o.targets.iter_mut() {
        t["shown_sha256"] = serde_json::json!(shown);
    }
    let mut value = serde_json::json!({
        "argv": argv,
        "exit_code": o.exit,
        "stdout": stdout,
        "stdout_truncated": truncated,
        "stderr": o.stderr.chars().take(STDERR_CAP).collect::<String>(),
        "native": o.native,
    });
    if let Some(n) = o.note {
        value["note"] = serde_json::json!(n);
    }
    Ok(CapabilityOutcome { value, real_execution: true, targets: o.targets })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn grammar_accepts_task_vocabulary() {
        for ok in [
            &["ls", "-l", "/x"][..],
            &["ls", "-la", "/x"],
            &["ls", "-t", "/x"],
            &["cat", "/x/f"],
            &["head", "-n", "20", "/x/f"],
            &["head", "-20", "/x/f"],
            &["tail", "-n5", "/x/f"],
            &["sed", "-n", "1,60p", "/x/f"],
            &["sed", "-n", "'1,60p'", "/x/f"],
            &["sed", "-n", "5p", "/x/f"],
            &["sed", "-n", "5,$p", "/x/f"],
            &["wc", "-l", "/x/f"],
            &["grep", "-n", "worker", "/x/f"],
            &["grep", "-rn", "model.default", "/x"],
            &["grep", "-nF", "a[b]", "/x/f"],
            &["rg", "-n", "fallback", "/x"],
            &["rg", "escalation"],
            &["shasum", "-a", "256", "/x/f", "/x/g"],
            &["sha256sum", "/x/f"],
            &["cmp", "/x/f", "/x/g"],
            &["cmp", "-s", "/x/f", "/x/g"],
            &["stat", "/x/f"],
            &["plutil", "-lint", "/x/p.plist"],
            &["git", "-C", "/x", "log", "--oneline", "-n", "5"],
            &["git", "-C", "/x", "status", "--porcelain"],
            &["git", "-C", "/x", "diff", "--stat", "HEAD~1", "--", "src"],
            &["git", "-C", "/x", "show", "HEAD:src/main.rs"],
            &["git", "-C", "/x", "blame", "-L", "1,20", "src/a.rs"],
            &["git", "-C", "/x", "rev-parse", "--short", "HEAD"],
        ] {
            assert!(parse(&a(ok)).is_ok(), "should accept {ok:?}: {:?}", parse(&a(ok)).err());
        }
    }

    #[test]
    fn grammar_rejects() {
        for (bad, code) in [
            (&["bash", "-c", "id"][..], "CMD_UNKNOWN"),
            (&["/bin/ls", "/x"], "CMD_GRAMMAR"),
            (&["python3", "x.py"], "CMD_UNKNOWN"),
            (&["ls", "-R", "/x"], "CMD_GRAMMAR"),
            (&["cat", "/x/a", "/x/b"], "CMD_GRAMMAR"),
            (&["cat", "-"], "CMD_GRAMMAR"),
            (&["sed", "-i", "s/a/b/", "/x/f"], "CMD_GRAMMAR"),
            (&["sed", "-n", "1,5d", "/x/f"], "CMD_GRAMMAR"),
            (&["sed", "-n", "5,1p", "/x/f"], "CMD_GRAMMAR"),
            (&["grep", "-E", "a|b", "/x/f"], "CMD_GRAMMAR"),
            (&["grep", "^import", "/x/f"], "CMD_GRAMMAR"),
            (&["grep", "pattern"], "CMD_GRAMMAR"),
            (&["rg", "a.*b", "/x"], "CMD_GRAMMAR"),
            (&["shasum", "/x/f"], "CMD_GRAMMAR"),
            (&["shasum", "-a", "1", "/x/f"], "CMD_GRAMMAR"),
            (&["plutil", "-convert", "xml1", "/x/p"], "CMD_GRAMMAR"),
            (&["git", "log"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "diff", "--output=/tmp/pwn"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "diff", "--ext-diff"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "log", "--show-signature"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "log", "--format=%G?"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "log", "--exec=id"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "grep", "x"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "checkout", "main"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "-c", "core.pager=id", "log"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "log", "--upload-pack=id"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "log", "-n", "9999"], "CMD_GRAMMAR"),
            (&["git", "-C", "/x", "status", "--", ":(top)x"], "CMD_GRAMMAR"),
        ] {
            let e = parse(&a(bad)).expect_err(&format!("should reject {bad:?}"));
            assert_eq!(e.0, code, "{bad:?} -> {e:?}");
        }
    }

    #[test]
    fn utc_format() {
        assert_eq!(utc(0), "1970-01-01 00:00");
        assert_eq!(utc(1_790_806_282), "2026-09-30 22:11");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00");
    }

    /// Live (non-zombie) processes whose command line contains `marker`.
    /// Zombies are dead: some container inits never reap orphans; launchd does.
    fn live_with_marker(marker: &str) -> Vec<String> {
        let ps = Command::new("/bin/ps").args(["-eo", "stat=,args="]).output().unwrap();
        String::from_utf8_lossy(&ps.stdout)
            .lines()
            .filter(|l| l.contains(marker) && !l.trim_start().starts_with('Z') && !l.contains("ps -eo"))
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn runner_timeout_kills_whole_group() {
        let t0 = Instant::now();
        let e = spawn_capped(
            Path::new("/bin/sh"),
            &a(&["-c", "sleep 31.1 & sleep 31.1 & wait"]),
            Path::new("/"),
            &[("PATH", "/usr/bin:/bin".into())],
            Duration::from_secs(1),
        )
        .err()
        .expect("must time out");
        assert_eq!(e.code, "CAPABILITY_TIMEOUT");
        assert!(t0.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(150));
        let live = live_with_marker("sleep 31.1");
        assert!(live.is_empty(), "grandchildren must be killed: {live:?}");
    }

    #[test]
    fn runner_env_is_cleared() {
        std::env::set_var("HERCULES_TEST_LEAK", "leaked");
        let (code, out, _, _, _) = spawn_capped(
            Path::new("/usr/bin/env"),
            &[],
            Path::new("/"),
            &[("PATH", "/usr/bin:/bin".into()), ("LC_ALL", "C".into())],
            Duration::from_secs(5),
        )
        .ok()
        .unwrap();
        assert_eq!(code, 0);
        let text = String::from_utf8_lossy(&out);
        let mut keys: Vec<&str> = text.lines().filter_map(|l| l.split('=').next()).collect();
        keys.sort();
        assert_eq!(keys, vec!["LC_ALL", "PATH"], "{text}");
    }

    #[test]
    fn runner_large_output_does_not_deadlock() {
        let t0 = Instant::now();
        let (code, out, over, _, _) = spawn_capped(
            Path::new("/usr/bin/head"),
            &a(&["-c", "1000000", "/dev/zero"]),
            Path::new("/"),
            &[("PATH", "/usr/bin:/bin".into())],
            Duration::from_secs(5),
        )
        .ok()
        .unwrap();
        assert_eq!(code, 0);
        assert_eq!(out.len(), STDOUT_CAP);
        assert!(over);
        assert!(t0.elapsed() < Duration::from_secs(4));
    }

    #[test]
    fn runner_leaves_no_background_children() {
        let t0 = Instant::now();
        let (code, _, _, _, _) = spawn_capped(
            Path::new("/bin/sh"),
            &a(&["-c", "sleep 32.2 >/dev/null 2>&1 & echo started"]),
            Path::new("/"),
            &[("PATH", "/usr/bin:/bin".into())],
            Duration::from_secs(5),
        )
        .ok()
        .unwrap();
        assert_eq!(code, 0);
        assert!(t0.elapsed() < Duration::from_secs(4), "must not wait for the background child");
        std::thread::sleep(Duration::from_millis(150));
        let live = live_with_marker("sleep 32.2");
        assert!(live.is_empty(), "orphaned child survived: {live:?}");
    }

    #[test]
    fn git_version_parse() {
        assert_eq!(parse_git_version("git version 2.43.0"), Some((2, 43)));
        assert_eq!(parse_git_version("git version 2.39.5 (Apple Git-154)"), Some((2, 39)));
        assert!(parse_git_version("git version 2.39.5 (Apple Git-154)").unwrap() < GIT_MIN_VERSION);
    }
}
