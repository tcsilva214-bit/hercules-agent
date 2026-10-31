//! Gate 02 config: strict line-based `key = value` format, versioned.
//! Rules (frozen): unknown key -> CONFIG_MALFORMED. Missing required key -> CONFIG_MALFORMED.
//! config_version != 1 -> CONFIG_VERSION_UNSUPPORTED. Bad typed value -> CONFIG_INVALID_VALUE.
//! No defaults for provider endpoint or model identity: absence is an error, never a silent pick.
//! provider.api_key is secret: never printed by inspection.
//! Build 1: config_version 2 adds optional read-only roots (`root.<name> = read:<abs path>`),
//! `root.deny`, `cmd.enable` and `cmd.timeout_seconds`. Those keys are unknown (and so
//! rejected) in a v1 config, which keeps v1 behaviour byte-for-byte unchanged.
//! v2 also adds `model.sampling = model | greedy`: `model` (the v2 default) leaves sampling
//! to the model's own settings with a fixed seed; `greedy` forces temperature 0, as v1 does.
//! Greedy decoding makes some models (Qwen3 among them) repeat themselves without end.
//! Build 2 (v2 only): `provider.kind = openai` talks to an OpenAI-compatible
//! `/v1/chat/completions` server (oMLX, llama.cpp, vLLM, ...); `provider.api_key_file`
//! names a file holding its bearer key (read at run time, never printed, refused when
//! readable by other users); `provider.thinking = off` asks a chat template to skip its
//! thinking phase (`chat_template_kwargs.enable_thinking = false`; `server`, the default,
//! sends nothing and leaves it to the server).
//! Signed runs (v2, required): `sign.key_file` names the Ed25519 signing key (PEM, made by `keygen`). Its
//! absence refuses the whole v2 config; the file itself is read when a mission starts (attest.rs).

use crate::errors::{AppError, ErrCat};
use std::collections::BTreeMap;

pub const SUPPORTED_CONFIG_VERSIONS: [u32; 2] = [1, 2];
pub const CMD_TIMEOUT_DEFAULT_SECONDS: u64 = 10;
pub const CMD_TIMEOUT_MAX_SECONDS: u64 = 30;

#[derive(Debug)]
pub struct Config {
    pub config_version: u32,
    pub provider_kind: String,     // "ollama" (v1, v2) | "openai" (v2 only)
    pub provider_endpoint: String, // e.g. http://localhost:11434 — NOT contacted in Gate 02
    pub model_default: String,     // exact identity string; no alias logic exists
    pub model_context_length: u64,
    pub agent_max_iterations: u64,
    pub agent_request_timeout_seconds: u64,
    pub provider_api_key: Option<String>, // secret; masked on inspect
    /// v2 only: declared read-only roots, name -> canonical directory, in name order.
    pub roots: Vec<(String, std::path::PathBuf)>,
    /// v2 only: extra deny patterns added to the built-in deny list.
    pub root_deny: Vec<String>,
    /// v2 only: enabled cmd.run commands. None = the default set.
    pub cmd_enable: Option<Vec<String>>,
    pub cmd_timeout_seconds: u64,
    /// true = temperature 0 (v1 always; v2 with model.sampling = greedy).
    pub sampling_greedy: bool,
    /// v2 only: file holding the provider's bearer key (read at run time).
    pub provider_api_key_file: Option<String>,
    /// v2 only (openai): true = ask the chat template to skip thinking.
    pub provider_thinking_off: bool,
    /// Build 3.6, v2 only (openai): true = `provider.tool_calls = native` (tools sent, tool_calls read).
    pub provider_native_tools: bool,
    /// Signed runs, v2 (required there): the absolute path of the Ed25519 signing key.
    pub sign_key_file: Option<String>,
    /// Gate 10, v2: names of roots declared `write:` (they may receive proposals; they are also readable).
    pub write_roots: Vec<String>,
}

/// Longest key a key file may hold (bytes, after trimming).
pub const API_KEY_MAX_BYTES: u64 = 4096;

impl Config {
    /// The provider's bearer key, if one is configured. Reads `provider.api_key_file` now
    /// (it may be readable only by the account HERCULES runs as). The key is never logged.
    pub fn api_key(&self) -> Result<Option<String>, AppError> {
        if let Some(k) = &self.provider_api_key {
            return Ok(Some(k.clone()));
        }
        let Some(path) = &self.provider_api_key_file else { return Ok(None) };
        read_key_file(path).map(Some)
    }
}

fn read_key_file(path: &str) -> Result<String, AppError> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let bad = |d: String| AppError::new(ErrCat::ConfigInvalidValue, format!("key=provider.api_key_file {d}"));
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| bad(format!("cannot open: {e}")))?;
    let md = f.metadata().map_err(|e| bad(format!("stat: {e}")))?;
    if !md.file_type().is_file() {
        return Err(bad("is not a regular file".to_string()));
    }
    if md.mode() & 0o004 != 0 {
        return Err(bad("is readable by every user; restrict it (for example mode 0640)".to_string()));
    }
    if md.len() > API_KEY_MAX_BYTES + 2 {
        return Err(bad("is too large to be a key".to_string()));
    }
    let mut s = String::new();
    f.read_to_string(&mut s).map_err(|e| bad(format!("read: {e}")))?;
    let k = s.trim();
    if k.is_empty() || k.contains('\n') || k.contains('\r') || k.chars().any(|c| c.is_control()) {
        return Err(bad("must hold one key on one line".to_string()));
    }
    Ok(k.to_string())
}

const REQUIRED_KEYS: [&str; 7] = [
    "config_version",
    "provider.kind",
    "provider.endpoint",
    "model.default",
    "model.context_length",
    "agent.max_iterations",
    "agent.request_timeout_seconds",
];
const OPTIONAL_KEYS: [&str; 1] = ["provider.api_key"];

pub fn load(path: &str) -> Result<Config, AppError> {
    let raw = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            return Err(AppError::new(
                ErrCat::ConfigMissing,
                format!("path={path} err={e}"),
            ))
        }
    };
    let mut kv: BTreeMap<String, String> = BTreeMap::new();
    for (lineno, line) in raw.lines().enumerate() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let Some((k, v)) = l.split_once('=') else {
            return Err(AppError::new(
                ErrCat::ConfigMalformed,
                format!("line={} not key=value", lineno + 1),
            ));
        };
        let k = k.trim().to_string();
        let v = v.trim().to_string();
        if !REQUIRED_KEYS.contains(&k.as_str())
            && !OPTIONAL_KEYS.contains(&k.as_str())
            && !is_v2_key(&k)
        {
            return Err(AppError::new(
                ErrCat::ConfigMalformed,
                format!("unknown_key={k} line={}", lineno + 1),
            ));
        }
        if kv.insert(k.clone(), v).is_some() {
            return Err(AppError::new(
                ErrCat::ConfigMalformed,
                format!("duplicate_key={k}"),
            ));
        }
    }
    for k in REQUIRED_KEYS {
        if !kv.contains_key(k) {
            return Err(AppError::new(
                ErrCat::ConfigMalformed,
                format!("missing_key={k}"),
            ));
        }
    }
    let parse_u64 = |key: &str| -> Result<u64, AppError> {
        kv[key].parse::<u64>().map_err(|_| {
            AppError::new(
                ErrCat::ConfigInvalidValue,
                format!("key={key} value={}", kv[key]),
            )
        })
    };
    let version = kv["config_version"]
        .parse::<u32>()
        .map_err(|_| AppError::new(ErrCat::ConfigInvalidValue, "key=config_version".to_string()))?;
    if !SUPPORTED_CONFIG_VERSIONS.contains(&version) {
        return Err(AppError::new(
            ErrCat::ConfigVersion,
            format!("found={version} supported=1,2"),
        ));
    }
    if version == 1 {
        if let Some(k) = kv.keys().find(|k| is_v2_key(k)) {
            return Err(AppError::new(
                ErrCat::ConfigMalformed,
                format!("unknown_key={k} (requires config_version = 2)"),
            ));
        }
    }
    let v2 = parse_v2(&kv)?;
    let provider_kind = kv["provider.kind"].clone();
    let kinds_allowed: &[&str] = if version >= 2 { &["ollama", "openai"] } else { &["ollama"] };
    if !kinds_allowed.contains(&provider_kind.as_str()) {
        return Err(AppError::new(
            ErrCat::ConfigInvalidValue,
            format!("key=provider.kind value={provider_kind} allowed={}", kinds_allowed.join("|")),
        ));
    }
    if kv.contains_key("provider.api_key") && kv.contains_key("provider.api_key_file") {
        return Err(AppError::new(
            ErrCat::ConfigInvalidValue,
            "provider.api_key and provider.api_key_file are both set; keep one".to_string(),
        ));
    }
    if version >= 2 && v2.sign_key_file.is_none() {
        return Err(AppError::new(
            ErrCat::ConfigMalformed,
            "missing_key=sign.key_file (every v2 run is signed; make a key with `keygen --out <dir>`)".to_string(),
        ));
    }
    if v2.native_tools && provider_kind != "openai" {
        return Err(AppError::new(
            ErrCat::ConfigInvalidValue,
            "key=provider.tool_calls = native applies to provider.kind = openai only".to_string(),
        ));
    }
    if v2.thinking_off && provider_kind != "openai" {
        return Err(AppError::new(
            ErrCat::ConfigInvalidValue,
            "key=provider.thinking applies to provider.kind = openai only (ollama always sends think=false)".to_string(),
        ));
    }
    let endpoint = kv["provider.endpoint"].clone();
    if !(endpoint.starts_with("http://") || endpoint.starts_with("https://")) {
        return Err(AppError::new(
            ErrCat::ConfigInvalidValue,
            "key=provider.endpoint must be http(s) URL".to_string(),
        ));
    }
    let model_default = kv["model.default"].clone();
    if model_default.is_empty() {
        return Err(AppError::new(
            ErrCat::ConfigInvalidValue,
            "key=model.default empty".to_string(),
        ));
    }
    Ok(Config {
        config_version: version,
        provider_kind,
        provider_endpoint: endpoint,
        model_default,
        model_context_length: parse_u64("model.context_length")?,
        agent_max_iterations: parse_u64("agent.max_iterations")?,
        agent_request_timeout_seconds: parse_u64("agent.request_timeout_seconds")?,
        provider_api_key: kv.get("provider.api_key").cloned(),
        roots: v2.roots,
        root_deny: v2.root_deny,
        cmd_enable: v2.cmd_enable,
        cmd_timeout_seconds: v2.cmd_timeout_seconds,
        sampling_greedy: if version >= 2 { v2.sampling_greedy } else { true },
        provider_api_key_file: v2.api_key_file,
        provider_thinking_off: v2.thinking_off,
        provider_native_tools: v2.native_tools,
        sign_key_file: v2.sign_key_file,
        write_roots: v2.write_roots,
    })
}

fn is_v2_key(k: &str) -> bool {
    k.starts_with("root.")
        || k == "cmd.enable"
        || k == "cmd.timeout_seconds"
        || k == "model.sampling"
        || k == "provider.api_key_file"
        || k == "provider.thinking"
        || k == "provider.tool_calls"
        || k == "sign.key_file"
}

pub fn valid_root_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

struct V2 {
    roots: Vec<(String, std::path::PathBuf)>,
    root_deny: Vec<String>,
    cmd_enable: Option<Vec<String>>,
    cmd_timeout_seconds: u64,
    sampling_greedy: bool,
    api_key_file: Option<String>,
    thinking_off: bool,
    native_tools: bool,
    sign_key_file: Option<String>,
    write_roots: Vec<String>,
}

fn list_value(v: &str) -> Vec<String> {
    v.split(',')
        .map(|x| x.trim().to_string())
        .filter(|x| !x.is_empty())
        .collect()
}

fn parse_v2(kv: &BTreeMap<String, String>) -> Result<V2, AppError> {
    let invalid = |detail: String| AppError::new(ErrCat::ConfigInvalidValue, detail);
    let mut roots = Vec::new();
    let mut write_roots = Vec::new();
    let mut root_deny = Vec::new();
    for (k, v) in kv {
        let Some(name) = k.strip_prefix("root.") else { continue };
        if name == "deny" {
            root_deny = list_value(v);
            for pat in &root_deny {
                if pat.contains('/') || pat.len() > 128 {
                    return Err(invalid(format!(
                        "key=root.deny pattern={pat} (basename globs only, no '/')"
                    )));
                }
            }
            continue;
        }
        if !valid_root_name(name) {
            return Err(invalid(format!("key={k} root name must match [a-z0-9_]{{1,32}}")));
        }
        // Gate 10: `write:` declares a root that may receive proposals (and is readable).
        let (path, write) = match (v.strip_prefix("read:"), v.strip_prefix("write:")) {
            (Some(p), _) => (p, false),
            (None, Some(p)) => (p, true),
            _ => return Err(invalid(format!("key={k} value must be read:<absolute path> or write:<absolute path>"))),
        };
        if write {
            write_roots.push(name.to_string());
        }
        let path = path.trim();
        if !std::path::Path::new(path).is_absolute() {
            return Err(invalid(format!("key={k} path must be absolute")));
        }
        let canonical = std::fs::canonicalize(path)
            .map_err(|e| invalid(format!("key={k} path={path} err={e}")))?;
        if !canonical.is_dir() {
            return Err(invalid(format!("key={k} path={path} is not a directory")));
        }
        if canonical == std::path::Path::new("/") {
            return Err(invalid(format!("key={k} the filesystem root cannot be a root")));
        }
        roots.push((name.to_string(), canonical));
    }
    // Write roots may not overlap (one inside another, or the same folder twice): change commands lock each write
    // root they touch, and that only serializes every change to a file if each file lies in exactly one write root.
    let wpaths: Vec<&(String, std::path::PathBuf)> = roots.iter().filter(|(n, _)| write_roots.contains(n)).collect();
    for (i, (an, ap)) in wpaths.iter().map(|x| (&x.0, &x.1)).enumerate() {
        for (bn, bp) in wpaths.iter().skip(i + 1).map(|x| (&x.0, &x.1)) {
            if ap.starts_with(bp) || bp.starts_with(ap) {
                return Err(invalid(format!(
                    "key=root.{an} key=root.{bn} write roots must not overlap ({} and {})",
                    ap.display(),
                    bp.display()
                )));
            }
        }
    }
    let cmd_enable = match kv.get("cmd.enable") {
        None => None,
        Some(v) => {
            let names = list_value(v);
            for n in &names {
                if !crate::cmd::is_catalog_command(n) {
                    return Err(invalid(format!("key=cmd.enable unknown command={n}")));
                }
            }
            Some(names)
        }
    };
    let cmd_timeout_seconds = match kv.get("cmd.timeout_seconds") {
        None => CMD_TIMEOUT_DEFAULT_SECONDS,
        Some(v) => match v.parse::<u64>() {
            Ok(n) if (1..=CMD_TIMEOUT_MAX_SECONDS).contains(&n) => n,
            _ => {
                return Err(invalid(format!(
                    "key=cmd.timeout_seconds must be 1..={CMD_TIMEOUT_MAX_SECONDS}"
                )))
            }
        },
    };
    let sampling_greedy = match kv.get("model.sampling").map(String::as_str) {
        None | Some("model") => false,
        Some("greedy") => true,
        Some(other) => return Err(invalid(format!("key=model.sampling value={other} (model | greedy)"))),
    };
    let api_key_file = match kv.get("provider.api_key_file") {
        None => None,
        Some(p) if std::path::Path::new(p).is_absolute() => Some(p.clone()),
        Some(_) => return Err(invalid("key=provider.api_key_file path must be absolute".to_string())),
    };
    let thinking_off = match kv.get("provider.thinking").map(String::as_str) {
        None | Some("server") => false,
        Some("off") => true,
        Some(other) => return Err(invalid(format!("key=provider.thinking value={other} (off | server)"))),
    };
    let native_tools = match kv.get("provider.tool_calls").map(String::as_str) {
        None | Some("text") => false,
        Some("native") => true,
        Some(other) => return Err(invalid(format!("key=provider.tool_calls value={other} (text | native)"))),
    };
    let sign_key_file = match kv.get("sign.key_file") {
        None => None,
        Some(p) if std::path::Path::new(p).is_absolute() => Some(p.clone()),
        Some(_) => return Err(invalid("key=sign.key_file path must be absolute".to_string())),
    };
    Ok(V2 {
        write_roots,
        sign_key_file,
        native_tools,
        roots,
        root_deny,
        cmd_enable,
        cmd_timeout_seconds,
        sampling_greedy,
        api_key_file,
        thinking_off,
    })
}
