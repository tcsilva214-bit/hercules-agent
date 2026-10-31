#![recursion_limit = "512"]
//! hercules-agent — HERCULES native harness candidate.
//! Gates 02-06: CLI/config, model gateway, bounded loop, structured tools, authority broker.
//! Model output is data until it passes the exact tool protocol, schema validation, and Gate 06 authority decision.

mod agent_loop;
mod anchored;
mod apply;
mod attest;
mod answer;
mod audit;
mod authority;
mod capabilities;
mod cmd;
mod config;
mod diff;
mod errors;
mod checker;
mod evidence;
mod features;
mod gateway;
mod mcp;
mod native;
mod proposal;
mod py;
mod readers;
mod roots;
mod router;
mod session;
mod sha256;
mod tools;
mod transcript;

use errors::{AppError, ErrCat};

const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Digest of the source tree this binary was compiled from (see sha256::source_tree_digest).
const EMBEDDED_SOURCE_DIGEST: &str = env!("HERCULES_SOURCE_DIGEST");

fn usage() -> ! {
    eprintln!(
        "usage: hercules-agent <command>\n\
         commands:\n\
         \x20 --version\n\
         \x20 inspect config|provider|model --config <path>\n\
         \x20 doctor --config <path>\n\
         \x20 run --dry-start --config <path>\n\
         \x20 run --mission --config <path> --model <exact-id> --task <text>\n\
         \x20     --transcript <out.ndjson> --evidence <out.json> --final-output <out.txt>\n\
         \x20     --evidence-report <out.json> --attestation <out.json>   (config_version 2; v1 is refused)\n\
         \x20     [--fixtures <file>] [--max-iterations N] [--timeout-seconds N] [--num-predict N]\n\
         \x20     [--session-dir <base>] [--session-id <id>] [--resume] [--context-budget-bytes N]\n\
         \x20     [--mission-id <id>] [--mission-class worker|deep|scout]\n\
         \x20     [--approval-file <json>] [legacy --approve-request is rejected]\n\
         \x20     [--roots <name,...>]\n\
         \x20     [--final-block-begin <text> --final-block-end <text> [--final-block-keys a,b,.. | --final-block-spec <json>]]\n\
         \x20 evidence verify --report <evidence.json> --transcript <t.ndjson> --final <final.txt>\n\
         \x20 keygen --out <dir>   (writes signing.key and signing.pub; never overwrites)\n\
         \x20 attest verify --attestation <a.json> --pubkey <signing.pub> --transcript <t.ndjson>\n\
         \x20     --final <final.txt> --report <evidence.json> --manifest <manifest.json> [--proposal <dir>]\n\
         \x20 change apply --config <path> --proposal <dir> --approve <changeset sha256, 16+ hex>\n\
         \x20 change rollback --config <path> --proposal <dir>\n\
         \x20 change recover --config <path> --proposal <dir>   (undo an apply or rollback that was interrupted)\n\
         \x20 change verify --proposal <dir> --pubkey <signing.pub>\n\
         \x20 mcp serve --config <path> --roots <name,...> --run-dir <abs dir> --max-calls N\n\
         \x20     (MCP over stdio, 2026-07-28 and 2025-11-25; read-only tools; one signed run per process)\n\
         \x20 checker run --cases <corpus.json>\n\
         \x20 chat --config <path> --model <exact-id> --prompt <text>\n\
         \x20      [--system <text>] [--stream] [--timeout-seconds N]\n\
         \x20      [--num-predict N] [--evidence <out.json>]"
    );
    std::process::exit(ErrCat::Usage.exit_code());
}

fn flag_value(args: &[String], name: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            return it.next().cloned();
        }
    }
    None
}

fn flag_values(args: &[String], name: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == name {
            if let Some(v) = it.next() {
                out.push(v.clone());
            }
        }
    }
    out
}

fn config_arg(args: &[String]) -> Result<String, AppError> {
    flag_value(args, "--config").ok_or_else(|| {
        AppError::new(
            ErrCat::Usage,
            "--config <path> is required; no implicit config location exists",
        )
    })
}

fn write_evidence(path: &Option<String>, v: &serde_json::Value) -> Result<(), String> {
    if let Some(p) = path {
        audit::write_json_atomic(p, v)?;
    }
    Ok(())
}

/// Build 1: select the granted roots and build the cmd.run policy, with the
/// safety checks that must hold before any session exists.
fn build1_policies(
    cfg: &config::Config,
    roots_arg: Option<&str>,
    authority: &authority::AuthorityContext,
    config_path: &str,
    approval_file: Option<&str>,
) -> Result<(roots::RootPolicy, cmd::CmdPolicy), AppError> {
    let usage = |d: String| AppError::new(ErrCat::Usage, d);
    let mut selected: Vec<roots::Root> = Vec::new();
    if let Some(list) = roots_arg {
        for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            if selected.iter().any(|r| r.name == name) {
                return Err(usage(format!("--roots names {name} twice")));
            }
            let Some((_, path)) = cfg.roots.iter().find(|(n, _)| n == name) else {
                let known: Vec<&str> = cfg.roots.iter().map(|(n, _)| n.as_str()).collect();
                return Err(usage(format!(
                    "--roots: {name} is not declared in the config (declared: {})",
                    if known.is_empty() { "none".to_string() } else { known.join(", ") }
                )));
            };
            selected.push(roots::Root { name: name.to_string(), path: path.clone() });
        }
    }
    let policy = roots::RootPolicy::new(selected, cfg.root_deny.clone());
    if let Some(sb) = authority.sandbox_root.as_deref() {
        for r in policy.roots() {
            if sb.starts_with(&r.path) || r.path.starts_with(sb) {
                return Err(usage(format!(
                    "root {} ({}) and the sandbox ({}) must not contain each other",
                    r.name,
                    r.path.display(),
                    sb.display()
                )));
            }
        }
    }
    for (what, p) in [("config file", Some(config_path)), ("approval file", approval_file), ("signing key", cfg.sign_key_file.as_deref())] {
        let Some(p) = p else { continue };
        if let Ok(c) = std::fs::canonicalize(p) {
            if policy.contains(&c) {
                return Err(usage(format!(
                    "the {what} {} is inside a granted root; move it or narrow --roots",
                    c.display()
                )));
            }
        }
    }
    let cmd = cmd::CmdPolicy::from_config(cfg.cmd_enable.as_deref(), cfg.cmd_timeout_seconds)
        .map_err(|e| AppError::new(ErrCat::ConfigInvalidValue, format!("cmd.enable: {e}")))?;
    Ok((policy, cmd))
}

/// Gate 7: `mcp serve`. Startup refusals go to stderr before any message is read; after that stdout carries
/// only MCP messages. One process is one run, closed and signed when stdin ends or on SIGTERM/SIGINT.
fn mcp_serve(args: &[String]) -> ! {
    gateway::install_signal_handlers();
    let path = config_arg(args).unwrap_or_else(|e| e.exit());
    let cfg = config::load(&path).unwrap_or_else(|e| e.exit());
    if cfg.config_version < 2 {
        AppError::new(ErrCat::ConfigVersion, "mcp serve needs config_version = 2: every run is signed").exit();
    }
    features::set_build1(true);
    let signing_key = match cfg.sign_key_file.as_deref().map(attest::read_signing_key) {
        Some(Ok(k)) => k,
        Some(Err(e)) => AppError::new(ErrCat::ConfigInvalidValue, format!("key=sign.key_file {e}")).exit(),
        None => AppError::new(ErrCat::ConfigMalformed, "missing_key=sign.key_file").exit(),
    };
    let keyid = attest::keyid(&signing_key.verifying_key());
    let usage_err = |d: String| -> ! { AppError::new(ErrCat::Usage, d).exit() };
    let roots_arg = flag_value(args, "--roots").unwrap_or_else(|| usage_err("mcp serve needs --roots <name,...>".into()));
    let run_dir = flag_value(args, "--run-dir").unwrap_or_else(|| usage_err("mcp serve needs --run-dir <absolute dir>".into()));
    let max_calls: u64 = match flag_value(args, "--max-calls").map(|v| v.parse::<u64>()) {
        Some(Ok(n)) if n >= 1 => n,
        _ => usage_err("mcp serve needs --max-calls N (N >= 1)".into()),
    };
    if !std::path::Path::new(&run_dir).is_absolute() {
        usage_err("--run-dir must be an absolute path".into());
    }
    let run_dir_c = std::fs::canonicalize(&run_dir).unwrap_or_else(|e| usage_err(format!("--run-dir {run_dir}: {e}")));
    if !run_dir_c.is_dir() {
        usage_err(format!("--run-dir {run_dir} is not a directory"));
    }
    let mut authority = authority::AuthorityContext::new(None, None, None).unwrap_or_else(|e| usage_err(format!("authority context invalid: {e}")));
    match build1_policies(&cfg, Some(&roots_arg), &authority, &path, None) {
        Ok((roots, cmd)) => {
            authority.roots = roots;
            authority.cmd = cmd;
        }
        Err(e) => e.exit(),
    }
    if authority.roots.is_empty() {
        usage_err("--roots must name at least one declared root".into());
    }
    if authority.roots.contains(&run_dir_c) {
        usage_err(format!("--run-dir {} is inside a granted root; the run's own files must not be readable through it", run_dir_c.display()));
    }
    let config_sha256 = audit::sha256_file(&path).unwrap_or_else(|e| AppError::new(ErrCat::Internal, format!("configuration SHA256 failed: {e}")).exit());
    let current_exe = std::env::current_exe().unwrap_or_else(|e| AppError::new(ErrCat::Internal, format!("current executable identity failed: {e}")).exit());
    let binary_digest = audit::sha256_file(&current_exe).unwrap_or_else(|e| AppError::new(ErrCat::Internal, format!("binary SHA256 failed: {e}")).exit());

    let started_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let run_id = format!("mcp-{started_ms}-{}", std::process::id());
    let dir = run_dir_c.join(&run_id);
    // Private to the operator: a run folder holds file contents and model output.
    if let Err(e) = std::os::unix::fs::DirBuilderExt::mode(&mut std::fs::DirBuilder::new(), 0o700).create(&dir) {
        AppError::new(ErrCat::Internal, format!("run directory {}: {e}", dir.display())).exit();
    }
    let f = |name: &str| dir.join(name).display().to_string();
    let (transcript, final_path, report_path, manifest_path, attestation_path) =
        (f("transcript.ndjson"), f("final.txt"), f("evidence.json"), f("manifest.json"), f("attestation.json"));
    let mut tw = transcript::TranscriptWriter::new(&transcript, &run_id)
        .unwrap_or_else(|e| AppError::new(ErrCat::Internal, format!("transcript create failed: {e}")).exit());
    let mut server = mcp::Server::new(&authority, max_calls);
    tw.emit(
        "mcp.run_start",
        None,
        serde_json::json!({
            "run_id": run_id,
            "harness": {"name": env!("CARGO_PKG_NAME"), "version": VERSION},
            "source_digest": EMBEDDED_SOURCE_DIGEST,
            "binary_digest": binary_digest,
            "config_digest": config_sha256,
            "protocol_versions": [mcp::MODERN, mcp::LEGACY],
            "tools": server.tool_names(),
            "authority": authority.summary_json(),
            "max_calls": max_calls,
            "keyid": keyid
        }),
    );
    eprintln!("HERCULES_AGENT_MCP_SERVING run_dir={} tools={} keyid={keyid}", dir.display(), server.tool_names().join(","));

    let stop = mcp::serve(&mut server, &mut tw);

    // Close the run like a mission: end event, transcript sync, empty final answer, report, manifest, signature.
    let stop_reason = stop.label();
    let write_failure = match &stop {
        mcp::Stop::WriteFailed(d) => Some(d.clone()),
        _ => None,
    };
    tw.emit(
        "mcp.run_end",
        None,
        serde_json::json!({"stop_reason": stop_reason, "calls": server.calls, "refused_requests": server.refused,
            "budget_refused": server.budget_refused, "era": server.era.map(|e| match e { mcp::Era::Modern => mcp::MODERN, mcp::Era::Legacy => mcp::LEGACY }),
            "detail": write_failure}),
    );
    let transcript_close_error = tw.finish().err();
    drop(tw);
    let ended_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let mut errors: Vec<String> = write_failure.into_iter().chain(transcript_close_error).collect();
    if let Err(e) = audit::write_text_atomic(&final_path, "") {
        errors.push(format!("final: {e}"));
    }
    let report = evidence::derive(&transcript, "", &authority.roots, stop_reason);
    match &report {
        Ok(v) => {
            if let Err(e) = audit::write_json_atomic(&report_path, v) {
                errors.push(format!("evidence report: {e}"));
            }
        }
        Err(e) => errors.push(format!("evidence report: {e}")),
    }
    let exit_code = if !errors.is_empty() {
        72
    } else if matches!(stop, mcp::Stop::Signal) {
        ErrCat::Cancelled.exit_code()
    } else if matches!(stop, mcp::Stop::InputBudget) {
        ErrCat::Usage.exit_code()
    } else {
        0
    };
    let manifest = serde_json::json!({
        "schema": "hercules_mcp_run_manifest_v1",
        "kind": "mcp_server",
        "run_id": run_id,
        "harness": {"name": env!("CARGO_PKG_NAME"), "version": VERSION},
        "source_digest": EMBEDDED_SOURCE_DIGEST,
        "binary_digest": binary_digest,
        "config_digest": config_sha256,
        "protocol_era": server.era.map(|e| match e { mcp::Era::Modern => mcp::MODERN, mcp::Era::Legacy => mcp::LEGACY }),
        "clients_claimed": server.clients_claimed,
        "tools": server.tool_names(),
        "authority": authority.summary_json(),
        "max_calls": max_calls,
        "calls": server.calls,
        "refused_requests": server.refused,
        "budget_refused": server.budget_refused,
        "grounding": report.as_ref().ok().and_then(|v| v.get("grounding").cloned()),
        "stop_reason": stop_reason,
        "exit_code": exit_code,
        "errors": errors,
        "transcript_path": transcript,
        "final_output_path": final_path,
        "evidence_report_path": report_path,
        "attestation": {"attestation_path": attestation_path, "keyid": keyid, "payload_type": attest::PAYLOAD_TYPE},
        "started_at": attest::rfc3339_ms(started_ms),
        "ended_at": attest::rfc3339_ms(ended_ms)
    });
    if let Err(e) = audit::write_json_atomic(&manifest_path, &manifest) {
        eprintln!("HERCULES_AGENT_ERROR evidence_write_failed err={e}");
        std::process::exit(72);
    }
    let facts = attest::transcript_facts(&transcript);
    let (t_sha, t_events, t_head) = match &facts {
        Ok(f) => (serde_json::json!(f.sha256), serde_json::json!(f.events), serde_json::json!(f.head)),
        Err(_) => (serde_json::Value::Null, serde_json::Value::Null, serde_json::Value::Null),
    };
    let statement = serde_json::json!({
        "schema": attest::STATEMENT_SCHEMA,
        "kind": "mcp_server",
        "harness": {"name": env!("CARGO_PKG_NAME"), "version": VERSION},
        "session_id": run_id,
        "run_id": run_id,
        "mission_id": null,
        "transcript": {"sha256": t_sha, "events": t_events, "head": t_head},
        "final_content_sha256": attest::file_sha256(Some(&final_path)),
        "evidence_report_sha256": attest::file_sha256(Some(&report_path)),
        "manifest_sha256": attest::file_sha256(Some(&manifest_path)),
        "source_digest": EMBEDDED_SOURCE_DIGEST,
        "binary_digest": binary_digest,
        "config_digest": config_sha256,
        "model_requested": null,
        "model_actual": null,
        "roots_granted": authority.roots.summary_json(),
        "stop_reason": stop_reason,
        "exit_code": exit_code,
        "started_at": attest::rfc3339_ms(started_ms),
        "ended_at": attest::rfc3339_ms(ended_ms)
    });
    if let Err(e) = audit::write_text_atomic(&attestation_path, &attest::sign_envelope(&signing_key, &statement)) {
        eprintln!("HERCULES_AGENT_ERROR attestation_write_failed err={e}");
        std::process::exit(73);
    }
    eprintln!(
        "HERCULES_AGENT_MCP_CLOSED stop_reason={stop_reason} calls={} refused={} run_dir={} signed_keyid={keyid}",
        server.calls,
        server.refused + server.budget_refused,
        dir.display()
    );
    std::process::exit(exit_code);
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        usage();
    }
    match args[0].as_str() {
        "--version" => {
            println!("hercules-agent {VERSION} (source {EMBEDDED_SOURCE_DIGEST})");
        }
        "evidence" => {
            // Re-derive an evidence report from its transcript and final answer and
            // compare it field by field with the stored report.
            if args.get(1).map(String::as_str) != Some("verify") {
                usage();
            }
            let need = |f: &str| flag_value(&args, f).unwrap_or_else(|| AppError::new(ErrCat::Usage, format!("evidence verify needs {f}")).exit());
            let (rp, tp, fp) = (need("--report"), need("--transcript"), need("--final"));
            let report: serde_json::Value = match std::fs::read_to_string(&rp).map_err(|e| e.to_string()).and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string())) {
                Ok(v) => v,
                Err(e) => AppError::new(ErrCat::Usage, format!("--report: {e}")).exit(),
            };
            let final_content = match std::fs::read_to_string(&fp) {
                Ok(t) => t,
                Err(e) => AppError::new(ErrCat::Usage, format!("--final: {e}")).exit(),
            };
            match evidence::verify(&report, &tp, &final_content) {
                Ok(d) if d.is_empty() => println!("EVIDENCE_VERIFY MATCH grounding={}", report["grounding"].as_str().unwrap_or("?")),
                Ok(d) => {
                    println!("EVIDENCE_VERIFY MISMATCH fields={}", d.join(","));
                    std::process::exit(1);
                }
                Err(e) => {
                    println!("EVIDENCE_VERIFY ERROR {e}");
                    std::process::exit(1);
                }
            }
        }
        "keygen" => {
            // Signed runs: make the Ed25519 key pair a v2 config names in sign.key_file.
            let out = flag_value(&args, "--out").unwrap_or_else(|| AppError::new(ErrCat::Usage, "keygen needs --out <dir>").exit());
            match attest::keygen(&out) {
                Ok(kid) => {
                    let dir = out.trim_end_matches('/');
                    println!("KEYGEN OK keyid={kid}");
                    println!("private key: {dir}/{} (mode 0600; set sign.key_file to this path)", attest::KEY_FILE_NAME);
                    println!("public key:  {dir}/{} (give this to whoever verifies your runs)", attest::PUB_FILE_NAME);
                }
                Err(e) => AppError::new(ErrCat::Usage, format!("keygen: {e}")).exit(),
            }
        }
        "attest" => {
            // Signed runs: check a run's signature, chain, digests and evidence report. No network.
            if args.get(1).map(String::as_str) != Some("verify") {
                usage();
            }
            let need = |f: &str| flag_value(&args, f).unwrap_or_else(|| AppError::new(ErrCat::Usage, format!("attest verify needs {f}")).exit());
            let (a, k, t, f, r) = (need("--attestation"), need("--pubkey"), need("--transcript"), need("--final"), need("--report"));
            let m = need("--manifest");
            let pr = flag_value(&args, "--proposal");
            let (line, code) = attest::verify(&attest::VerifyArgs {
                attestation: &a,
                pubkey: &k,
                transcript: &t,
                final_path: &f,
                report: &r,
                manifest: &m,
                proposal: pr.as_deref(),
            });
            println!("{line}");
            std::process::exit(code);
        }
        "change" => {
            // Gate 10: operator-run apply / rollback / recover / verify of a write-lane proposal.
            let sub = args.get(1).map(String::as_str).unwrap_or("");
            let need = |f: &str| flag_value(&args, f).unwrap_or_else(|| AppError::new(ErrCat::Usage, format!("change {sub} needs {f}")).exit());
            let dir = std::path::PathBuf::from(need("--proposal"));
            match sub {
                "verify" => {
                    let pk = attest::read_public_key(&need("--pubkey")).unwrap_or_else(|e| AppError::new(ErrCat::Usage, e).exit());
                    let (lines, ok) = apply::verify(&dir, &pk);
                    for l in lines {
                        println!("{l}");
                    }
                    std::process::exit(if ok { 0 } else { 1 });
                }
                "apply" | "rollback" | "recover" => {
                    let cpath = config_arg(&args).unwrap_or_else(|e| e.exit());
                    let cfg = config::load(&cpath).unwrap_or_else(|e| e.exit());
                    features::set_build1(true);
                    let sk = match cfg.sign_key_file.as_deref().map(attest::read_signing_key) {
                        Some(Ok(k)) => k,
                        Some(Err(e)) => AppError::new(ErrCat::ConfigInvalidValue, format!("key=sign.key_file {e}")).exit(),
                        None => AppError::new(ErrCat::ConfigMalformed, "missing_key=sign.key_file").exit(),
                    };
                    let wr: Vec<roots::Root> = cfg
                        .roots
                        .iter()
                        .filter(|(n, _)| cfg.write_roots.contains(n))
                        .map(|(n, p)| roots::Root { name: n.clone(), path: p.clone() })
                        .collect();
                    let r = match sub {
                        "apply" => apply::apply(&dir, &sk, &wr, &cfg.root_deny, &need("--approve")),
                        "rollback" => apply::rollback(&dir, &sk, &wr, &cfg.root_deny),
                        _ => apply::recover(&dir, &sk, &wr, &cfg.root_deny),
                    };
                    match r {
                        Ok(line) => println!("{line}"),
                        Err(e) => {
                            println!("CHANGE_{} REFUSED {e}", sub.to_ascii_uppercase());
                            std::process::exit(1);
                        }
                    }
                }
                _ => usage(),
            }
        }
        "mcp" => {
            if args.get(1).map(String::as_str) != Some("serve") {
                usage();
            }
            mcp_serve(&args);
        }
        "checker" => {
            // Build 3: run the finding checker on a shared-corpus file (tests/checker/), so the
            // runtime and the bridge can be compared case by case. Reads one file; no model, no network.
            if args.get(1).map(String::as_str) != Some("run") {
                usage();
            }
            let path = flag_value(&args, "--cases").unwrap_or_else(|| AppError::new(ErrCat::Usage, "checker run needs --cases").exit());
            let doc: serde_json::Value = match std::fs::read_to_string(&path).map_err(|e| e.to_string()).and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string())) {
                Ok(v) => v,
                Err(e) => AppError::new(ErrCat::Usage, format!("--cases: {e}")).exit(),
            };
            println!("{}", checker::run_cases(&doc));
        }
        "inspect" => {
            if args.len() < 2 {
                usage();
            }
            let path = match config_arg(&args) {
                Ok(p) => p,
                Err(e) => e.exit(),
            };
            let cfg = match config::load(&path) {
                Ok(c) => c,
                Err(e) => e.exit(),
            };
            match args[1].as_str() {
                "config" => {
                    println!("config_version={}", cfg.config_version);
                    println!("provider.kind={}", cfg.provider_kind);
                    println!("provider.endpoint={}", cfg.provider_endpoint);
                    println!(
                        "provider.api_key={}",
                        if cfg.provider_api_key.is_some() {
                            "***REDACTED***"
                        } else {
                            "(unset)"
                        }
                    );
                    if let Some(f) = &cfg.provider_api_key_file {
                        println!("provider.api_key_file={f} (contents never printed)");
                    }
                    if let Some(f) = &cfg.sign_key_file {
                        println!("sign.key_file={f} (contents never printed)");
                    }
                    if cfg.provider_kind == "openai" {
                        println!("provider.thinking={}", if cfg.provider_thinking_off { "off" } else { "server" });
                    }
                    if cfg.provider_native_tools {
                        println!("provider.tool_calls=native");
                    }
                    println!("model.default={}", cfg.model_default);
                    println!("model.context_length={}", cfg.model_context_length);
                    println!("agent.max_iterations={}", cfg.agent_max_iterations);
                    println!(
                        "agent.request_timeout_seconds={}",
                        cfg.agent_request_timeout_seconds
                    );
                    if cfg.config_version >= 2 {
                        for (n, p) in &cfg.roots {
                            println!("root.{n}=read:{}", p.display());
                        }
                        println!("root.deny={}", cfg.root_deny.join(", "));
                        println!(
                            "cmd.enable={}",
                            cfg.cmd_enable
                                .clone()
                                .unwrap_or_else(|| cmd::NATIVE_DEFAULT.iter().map(|s| s.to_string()).collect())
                                .join(", ")
                        );
                        println!("cmd.timeout_seconds={}", cfg.cmd_timeout_seconds);
                    }
                }
                "provider" => {
                    println!("provider.kind={}", cfg.provider_kind);
                    println!("provider.endpoint={}", cfg.provider_endpoint);
                    println!("contacted=false (inspection never contacts the provider)");
                }
                "model" => {
                    println!("model.default={}", cfg.model_default);
                    println!("model.context_length={}", cfg.model_context_length);
                    println!("binding=static (no alias, no fallback, no discovery)");
                }
                _ => usage(),
            }
        }
        "doctor" => {
            let path = match config_arg(&args) {
                Ok(p) => p,
                Err(e) => e.exit(),
            };
            match config::load(&path) {
                Ok(cfg) => {
                    println!("DOCTOR config=OK path={path}");
                    println!(
                        "DOCTOR provider.kind={} endpoint={}",
                        cfg.provider_kind, cfg.provider_endpoint
                    );
                    println!("DOCTOR network_checks=SKIPPED (doctor never contacts the provider)");
                    println!("DOCTOR_RESULT=OK");
                }
                Err(e) => e.exit(),
            }
        }
        "run" => {
            if args.len() < 2 {
                usage();
            }
            match args[1].as_str() {
                "--dry-start" => {
                    let path = match config_arg(&args) {
                        Ok(p) => p,
                        Err(e) => e.exit(),
                    };
                    match config::load(&path) {
                        Ok(cfg) => {
                            println!("DRY_START init=OK config_version={}", cfg.config_version);
                            println!("DRY_START model.default={}", cfg.model_default);
                            if cfg.provider_api_key_file.is_some() {
                                match cfg.api_key() {
                                    Ok(_) => println!("DRY_START provider.api_key_file=readable"),
                                    Err(e) => e.exit(),
                                }
                            }
                            if let Some(kf) = &cfg.sign_key_file {
                                match attest::read_signing_key(kf) {
                                    Ok(sk) => println!("DRY_START sign.key_file=readable keyid={}", attest::keyid(&sk.verifying_key())),
                                    Err(e) => AppError::new(ErrCat::ConfigInvalidValue, format!("key=sign.key_file {e}")).exit(),
                                }
                            }
                            println!("DRY_START provider_contacted=false tools_present=true real_capabilities_enabled=false");
                            println!("DRY_START shutdown=OK");
                        }
                        Err(e) => e.exit(),
                    }
                }
                "--mission" => {
                    gateway::install_signal_handlers();
                    let path = match config_arg(&args) {
                        Ok(p) => p,
                        Err(e) => e.exit(),
                    };
                    let cfg = match config::load(&path) {
                        Ok(c) => c,
                        Err(e) => e.exit(),
                    };
                    let build1 = cfg.config_version >= 2;
                    // Signed runs (decided 2026-10-30): no unsigned missions, so a v1 config (which cannot name a
                    // signing key) is refused before anything runs.
                    if !build1 {
                        AppError::new(
                            ErrCat::ConfigVersion,
                            "run --mission needs config_version = 2: every mission is signed, and a v1 config cannot name sign.key_file",
                        )
                        .exit();
                    }
                    features::set_build1(build1);
                    // Build 3.6: native tool calling (config v2, openai only; config.rs refuses anything else).
                    features::set_native(build1 && cfg.provider_native_tools);
                    // Signed runs: the key is read now, so a missing, unreadable or too-open key stops the run
                    // before the model is contacted.
                    let signing_key = match cfg.sign_key_file.as_deref().map(attest::read_signing_key) {
                        Some(Ok(k)) => k,
                        Some(Err(e)) => AppError::new(ErrCat::ConfigInvalidValue, format!("key=sign.key_file {e}")).exit(),
                        None => AppError::new(ErrCat::ConfigMalformed, "missing_key=sign.key_file").exit(),
                    };
                    let signing_keyid = attest::keyid(&signing_key.verifying_key());
                    let attestation = flag_value(&args, "--attestation");
                    for (flag, v) in [
                        ("--attestation", &attestation),
                        ("--evidence", &flag_value(&args, "--evidence")),
                        ("--final-output", &flag_value(&args, "--final-output")),
                        ("--evidence-report", &flag_value(&args, "--evidence-report")),
                    ] {
                        if v.is_none() {
                            AppError::new(ErrCat::Usage, format!("{flag} <path> is required: a signed run binds the transcript, final answer, evidence report and manifest")).exit();
                        }
                    }
                    let api_key = match cfg.api_key() {
                        Ok(k) => k,
                        Err(e) => e.exit(),
                    };
                    let roots_arg = flag_value(&args, "--roots");
                    let evidence_report = flag_value(&args, "--evidence-report");
                    if !build1 && (roots_arg.is_some() || evidence_report.is_some()) {
                        AppError::new(
                            ErrCat::Usage,
                            "--roots and --evidence-report require config_version = 2",
                        )
                        .exit();
                    }
                    let model = match flag_value(&args, "--model") {
                        Some(m) if !m.is_empty() => m,
                        _ => AppError::new(
                            ErrCat::Usage,
                            "--model <exact-id> is required; the loop never selects a model",
                        )
                        .exit(),
                    };
                    let task = match flag_value(&args, "--task") {
                        Some(t) => t,
                        None => AppError::new(ErrCat::Usage, "--task <text> is required").exit(),
                    };
                    let transcript = match flag_value(&args, "--transcript") {
                        Some(t) => t,
                        None => {
                            AppError::new(ErrCat::Usage, "--transcript <path> is required").exit()
                        }
                    };
                    let fixtures: Vec<String> = match flag_value(&args, "--fixtures") {
                        Some(f) => match std::fs::read_to_string(&f) {
                            Ok(s) => s
                                .lines()
                                .filter(|l| !l.trim().is_empty())
                                .map(|l| l.to_string())
                                .collect(),
                            Err(e) => {
                                AppError::new(ErrCat::Usage, format!("fixtures unreadable: {e}"))
                                    .exit()
                            }
                        },
                        None => Vec::new(),
                    };
                    let max_iterations: u64 = match flag_value(&args, "--max-iterations") {
                        Some(v) => match v.parse() {
                            Ok(n) if n >= 1 => n,
                            _ => {
                                AppError::new(ErrCat::Usage, "--max-iterations must be >=1").exit()
                            }
                        },
                        None => cfg.agent_max_iterations,
                    };
                    let timeout_s: u64 = match flag_value(&args, "--timeout-seconds") {
                        Some(t) => match t.parse() {
                            Ok(v) => v,
                            Err(_) => {
                                AppError::new(ErrCat::Usage, "--timeout-seconds must be an integer")
                                    .exit()
                            }
                        },
                        None => cfg.agent_request_timeout_seconds,
                    };
                    let num_predict: i64 = match flag_value(&args, "--num-predict") {
                        Some(t) => match t.parse() {
                            Ok(v) => v,
                            Err(_) => {
                                AppError::new(ErrCat::Usage, "--num-predict must be an integer")
                                    .exit()
                            }
                        },
                        None => 2048,
                    };
                    let evidence = flag_value(&args, "--evidence");
                    let final_output = flag_value(&args, "--final-output");
                    let mission_id_arg = flag_value(&args, "--mission-id");
                    let mission_class_arg = flag_value(&args, "--mission-class");
                    let sandbox_root = flag_value(&args, "--sandbox-root");
                    let session_dir = flag_value(&args, "--session-dir");
                    let session_id = flag_value(&args, "--session-id");
                    let resume = args.iter().any(|a| a == "--resume");
                    let legacy_approvals = flag_values(&args, "--approve-request");
                    if !legacy_approvals.is_empty() {
                        AppError::new(
                            ErrCat::Usage,
                            "--approve-request is disabled; use --approval-file",
                        )
                        .exit();
                    }
                    let approval_file = flag_value(&args, "--approval-file");
                    let final_contract = agent_loop::FinalContract {
                        block_begin: flag_value(&args, "--final-block-begin"),
                        block_end: flag_value(&args, "--final-block-end"),
                        block_keys: flag_value(&args, "--final-block-keys")
                            .map(|v| v.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()).collect())
                            .unwrap_or_default(),
                        block_spec: serde_json::Map::new(),
                    };
                    let mut final_contract = final_contract;
                    if let Some(spec) = flag_value(&args, "--final-block-spec") {
                        let parsed: serde_json::Map<String, serde_json::Value> = match serde_json::from_str::<serde_json::Value>(&spec) {
                            Ok(serde_json::Value::Object(m)) => m,
                            _ => AppError::new(ErrCat::Usage, "--final-block-spec must be a JSON object").exit(),
                        };
                        if let Err(e) = agent_loop::check_block_spec(&parsed) {
                            AppError::new(ErrCat::Usage, format!("--final-block-spec {e}")).exit();
                        }
                        if !final_contract.block_keys.is_empty() {
                            AppError::new(ErrCat::Usage, "use --final-block-spec or --final-block-keys, not both").exit();
                        }
                        final_contract.block_keys = parsed.keys().cloned().collect();
                        final_contract.block_spec = parsed;
                    }
                    let any_contract_flag = final_contract.block_begin.is_some()
                        || final_contract.block_end.is_some()
                        || !final_contract.block_keys.is_empty();
                    if any_contract_flag && !build1 {
                        AppError::new(ErrCat::Usage, "--final-block-* require config_version = 2").exit();
                    }
                    if final_contract.block_begin.is_some() != final_contract.block_end.is_some()
                        || (!final_contract.block_keys.is_empty() && final_contract.block_begin.is_none())
                    {
                        AppError::new(
                            ErrCat::Usage,
                            "--final-block-begin and --final-block-end go together; --final-block-keys needs both",
                        )
                        .exit();
                    }
                    let mut authority = match authority::AuthorityContext::new(
                        sandbox_root.as_deref(),
                        approval_file.as_deref(),
                        session_id.as_deref(),
                    ) {
                        Ok(a) => a,
                        Err(e) => {
                            AppError::new(ErrCat::Usage, format!("authority context invalid: {e}"))
                                .exit()
                        }
                    };
                    if build1 {
                        match build1_policies(&cfg, roots_arg.as_deref(), &authority, &path, approval_file.as_deref()) {
                            Ok((roots, cmd)) => {
                                authority.roots = roots;
                                authority.cmd = cmd;
                            }
                            Err(e) => e.exit(),
                        }
                    }
                    // Gate 10: the write lane. --write-roots names roots declared `write:` and granted by --roots;
                    // the model's writes go into a proposal under --proposal-dir, never into the roots.
                    let write_roots: Vec<roots::Root> = match flag_value(&args, "--write-roots") {
                        None => Vec::new(),
                        Some(list) => {
                            let mut out: Vec<roots::Root> = Vec::new();
                            for name in list.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                                if !cfg.write_roots.iter().any(|w| w == name) {
                                    AppError::new(ErrCat::Usage, format!("--write-roots: {name} is not declared write: in the config")).exit();
                                }
                                match authority.roots.roots().iter().find(|r| r.name == name) {
                                    Some(r) if !out.iter().any(|o| o.name == name) => out.push(r.clone()),
                                    Some(_) => AppError::new(ErrCat::Usage, format!("--write-roots names {name} twice")).exit(),
                                    None => AppError::new(ErrCat::Usage, format!("--write-roots: {name} must also be granted with --roots")).exit(),
                                }
                            }
                            if out.is_empty() {
                                AppError::new(ErrCat::Usage, "--write-roots needs at least one root name").exit();
                            }
                            out
                        }
                    };
                    let proposal_base: Option<std::path::PathBuf> = match (write_roots.is_empty(), flag_value(&args, "--proposal-dir")) {
                        (true, None) => None,
                        (true, Some(_)) => AppError::new(ErrCat::Usage, "--proposal-dir is only for runs with --write-roots").exit(),
                        (false, None) => AppError::new(ErrCat::Usage, "--write-roots needs --proposal-dir <absolute dir>").exit(),
                        (false, Some(d)) => {
                            if !std::path::Path::new(&d).is_absolute() {
                                AppError::new(ErrCat::Usage, "--proposal-dir must be an absolute path").exit();
                            }
                            let c = std::fs::canonicalize(&d).unwrap_or_else(|e| AppError::new(ErrCat::Usage, format!("--proposal-dir {d}: {e}")).exit());
                            if !c.is_dir() {
                                AppError::new(ErrCat::Usage, format!("--proposal-dir {d} is not a directory")).exit();
                            }
                            for r in authority.roots.roots() {
                                if c.starts_with(&r.path) || r.path.starts_with(&c) {
                                    AppError::new(ErrCat::Usage, format!("--proposal-dir and root {} must not contain each other", r.name)).exit();
                                }
                            }
                            Some(c)
                        }
                    };
                    features::set_write_lane(!write_roots.is_empty());
                    // v1: 4 bytes per token of the whole window. v2 (Build 1): the window less
                    // room for one full response, at 3 bytes per token, because source code
                    // tokenizes densely and a prompt that fills the window leaves the model no
                    // room to answer (it stops with done_reason=length after a few lines).
                    let default_context_budget = if build1 {
                        let window = cfg.model_context_length;
                        let reserve = if num_predict > 0 { (num_predict as u64).min(window / 4) } else { window / 4 };
                        window.saturating_sub(reserve).saturating_mul(3)
                    } else {
                        cfg.model_context_length.saturating_mul(4)
                    };
                    let context_budget_bytes: u64 =
                        match flag_value(&args, "--context-budget-bytes") {
                            Some(v) => match v.parse::<u64>() {
                                Ok(n) if n >= 256 => n,
                                _ => AppError::new(
                                    ErrCat::Usage,
                                    "--context-budget-bytes must be an integer >=256",
                                )
                                .exit(),
                            },
                            None => default_context_budget,
                        };

                    let config_sha256 = match audit::sha256_file(&path) {
                        Ok(v) => v,
                        Err(e) => AppError::new(
                            ErrCat::Internal,
                            format!("configuration SHA256 failed: {e}"),
                        )
                        .exit(),
                    };
                    let config_digest = match session::file_digest(&path) {
                        Ok(v) => v,
                        Err(e) => AppError::new(
                            ErrCat::Internal,
                            format!("configuration digest failed: {e}"),
                        )
                        .exit(),
                    };
                    let candidate_version = format!("hercules-agent {}", env!("CARGO_PKG_VERSION"));

                    let mut session = if resume {
                        let base = match session_dir.as_deref() {
                            Some(v) => v,
                            None => AppError::new(
                                ErrCat::Usage,
                                "--resume requires --session-dir <base>",
                            )
                            .exit(),
                        };
                        let sid = match session_id.as_deref() {
                            Some(v) => v,
                            None => {
                                AppError::new(ErrCat::Usage, "--resume requires --session-id <id>")
                                    .exit()
                            }
                        };
                        match session::SessionRuntime::resume(
                            base,
                            sid,
                            &model,
                            &task,
                            &candidate_version,
                            &config_digest,
                            max_iterations,
                        ) {
                            Ok(s) => s,
                            Err(e) => AppError::new(
                                ErrCat::Internal,
                                format!("session resume failed: {e}"),
                            )
                            .exit(),
                        }
                    } else {
                        match session::SessionRuntime::fresh(
                            session_dir.as_deref(),
                            session_id.as_deref(),
                            &model,
                            &task,
                            context_budget_bytes,
                            &candidate_version,
                            &config_digest,
                            max_iterations,
                        ) {
                            Ok(s) => s,
                            Err(e) => AppError::new(
                                ErrCat::Internal,
                                format!("session create failed: {e}"),
                            )
                            .exit(),
                        }
                    };

                    // Build 3: the task's answer contract decides whether the answer tools are offered.
                    let answer_contract = answer::contract_status(&task, &final_contract);
                    let write_lane_guide = if write_roots.is_empty() {
                        String::new()
                    } else {
                        proposal::guide_for(&write_roots, build1 && features::native())
                    };
                    let system_prompt = if build1 && features::native() {
                        format!(
                            "{}{}{}",
                            native::system_prompt(matches!(answer_contract, answer::ContractStatus::Active(_))),
                            native::guide(&authority.roots, &authority.cmd),
                            answer::guide(&answer_contract)
                        ) + &write_lane_guide
                    } else if build1 {
                        format!(
                            "{}{}{}",
                            agent_loop::system_prompt_v2(),
                            agent_loop::build1_guide(&authority.roots, &authority.cmd),
                            answer::guide(&answer_contract)
                        ) + &write_lane_guide
                    } else {
                        agent_loop::SYSTEM_PROMPT.to_string()
                    };
                    if let Err(e) = session.initialize_messages(&system_prompt) {
                        AppError::new(
                            ErrCat::Internal,
                            format!("session initialization failed: {e}"),
                        )
                        .exit();
                    }

                    let session_summary_pre = session.summary_json();
                    let active_session_id = match session_summary_pre
                        .get("session_id")
                        .and_then(serde_json::Value::as_str)
                    {
                        Some(v) if !v.is_empty() => v.to_string(),
                        _ => AppError::new(ErrCat::Internal, "session summary missing session_id")
                            .exit(),
                    };

                    let proposal_handle: Option<std::sync::Arc<proposal::Proposal>> = proposal_base.as_ref().map(|base| {
                        match proposal::Proposal::open(base, &active_session_id, write_roots.clone(), resume) {
                            Ok(p) => std::sync::Arc::new(p),
                            Err(e) => AppError::new(ErrCat::Usage, format!("proposal: {e}")).exit(),
                        }
                    });
                    authority.proposal = proposal_handle.clone();

                    let mission_id = mission_id_arg
                        .clone()
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| active_session_id.clone());
                    let mission_class = mission_class_arg
                        .clone()
                        .unwrap_or_else(|| "unspecified".to_string());

                    // Build 2: "daily" = the supervisor's daily-driver seat (Qwen3.8 27B on oMLX).
                    if mission_class != "unspecified"
                        && !matches!(mission_class.as_str(), "worker" | "deep" | "scout" | "daily")
                    {
                        AppError::new(ErrCat::Usage, "--mission-class must be worker|deep|scout|daily")
                            .exit();
                    }

                    let current_exe = match std::env::current_exe() {
                        Ok(v) => v,
                        Err(e) => AppError::new(
                            ErrCat::Internal,
                            format!("current executable identity failed: {e}"),
                        )
                        .exit(),
                    };
                    let binary_digest = match audit::sha256_file(&current_exe) {
                        Ok(v) => v,
                        Err(e) => AppError::new(
                            ErrCat::Internal,
                            format!("candidate binary SHA256 failed: {e}"),
                        )
                        .exit(),
                    };
                    // Build 1: the binary carries the digest of the source it was
                    // compiled from. When HERCULES_SOURCE_OF_RECORD names an on-disk
                    // source tree, that tree is hashed too and must match; the result
                    // is recorded as contract check B1_SOURCE_OF_RECORD_MATCH.
                    // No compile-time path is embedded (reproducible builds).
                    let source_digest = EMBEDDED_SOURCE_DIGEST.to_string();
                    let source_of_record = std::env::var("HERCULES_SOURCE_OF_RECORD").ok();
                    let source_of_record_digest = match source_of_record.as_deref() {
                        None => None,
                        Some(root) => match audit::sha256_source_tree(root) {
                            Ok(v) => Some(v),
                            Err(e) => AppError::new(
                                ErrCat::Internal,
                                format!("source of record SHA256 failed: {e}"),
                            )
                            .exit(),
                        },
                    };
                    let source_of_record_ok = source_of_record_digest
                        .as_deref()
                        .map(|d| d == source_digest)
                        .unwrap_or(true);

                    let mut tw = if resume {
                        match transcript::TranscriptWriter::resume(&transcript, &active_session_id)
                        {
                            Ok(t) => t,
                            Err(e) => AppError::new(
                                ErrCat::Internal,
                                format!("transcript resume failed: {e}"),
                            )
                            .exit(),
                        }
                    } else {
                        match transcript::TranscriptWriter::new(&transcript, &active_session_id) {
                            Ok(t) => t,
                            Err(e) => AppError::new(
                                ErrCat::Internal,
                                format!("transcript create failed: {e}"),
                            )
                            .exit(),
                        }
                    };

                    eprintln!("HERCULES_AGENT_SESSION {}", session.summary_json());

                    let policy_digest = audit::sha256_text(&authority.summary_json().to_string());
                    let authority_cmd_enabled = !authority.cmd.enabled().is_empty();
                    let granted_roots = authority.roots.clone();

                    let largs = agent_loop::LoopArgs {
                        mission_id: mission_id.clone(),
                        mission_class: mission_class.clone(),
                        harness_version: candidate_version.clone(),
                        source_digest: source_digest.clone(),
                        binary_digest: binary_digest.clone(),
                        config_digest: config_sha256.clone(),
                        provider_kind: cfg.provider_kind.clone(),
                        api_key: api_key.clone(),
                        thinking_off: cfg.provider_thinking_off,
                        endpoint: cfg.provider_endpoint.clone(),
                        model: model.clone(),
                        task,
                        fixtures,
                        max_iterations,
                        call_timeout: std::time::Duration::from_secs(timeout_s),
                        num_predict,
                        authority,
                        final_contract,
                        context_soft_bytes: if build1 { context_budget_bytes.saturating_mul(3) / 4 } else { 0 },
                        sampling_greedy: cfg.sampling_greedy,
                        native: features::native(),
                        cmd_enabled: authority_cmd_enabled,
                        answer_contract,
                    };
                    let out = agent_loop::run_mission(&largs, &mut tw, &mut session);

                    let transcript_close_error = tw.finish().err();
                    drop(tw);

                    let final_output_write_error = match final_output.as_deref() {
                        Some(p) => audit::write_text_atomic(p, &out.final_content).err(),
                        None => None,
                    };

                    // Build 1: harness-derived evidence report, written on every stop reason.
                    let (evidence_report_value, evidence_report_error) = if build1 {
                        match evidence::derive(&transcript, &out.final_content, &granted_roots, &out.stop_reason) {
                            Ok(v) => {
                                let err = evidence_report
                                    .as_deref()
                                    .and_then(|p| audit::write_json_atomic(p, &v).err());
                                (Some(v), err)
                            }
                            Err(e) => (None, Some(e)),
                        }
                    } else {
                        (None, None)
                    };
                    let grounding = evidence_report_value
                        .as_ref()
                        .and_then(|v| v.get("grounding").cloned())
                        .unwrap_or(serde_json::Value::Null);
                    let evidence_report_sha256 = evidence_report_value
                        .as_ref()
                        .map(|v| audit::sha256_text(&v.to_string()));

                    let transcript_summary_result = audit::summarize_transcript(&transcript);
                    let transcript_summary_error =
                        transcript_summary_result.as_ref().err().cloned();
                    let transcript_summary = transcript_summary_result.unwrap_or_else(|e| {
                        serde_json::json!({
                            "summary_error": e,
                            "sequence_ok": false,
                            "session_id_consistent": false,
                            "model_actual": null,
                            "tool_requests": [],
                            "authority_decisions": [],
                            "tool_results": [],
                            "errors": [],
                            "retries": [],
                            "recovery_events": [],
                            "router_decisions": [],
                            "escalation_events": [],
                            "start_time": 0,
                            "end_time": 0,
                            "elapsed": 0,
                            "final_answer": null
                        })
                    });

                    let transcript_sha256 = audit::sha256_file(&transcript).ok();
                    let final_result_digest = audit::sha256_text(&out.final_content);
                    let session_summary = session.summary_json();

                    let seq_ok = transcript_summary
                        .get("sequence_ok")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    let sid_ok = transcript_summary
                        .get("session_id_consistent")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false);
                    let actual_model = transcript_summary
                        .get("model_actual")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let model_identity_ok =
                        out.stop_reason != "FINAL" || actual_model.as_str() == Some(model.as_str());

                    let mission_class_valid =
                        matches!(mission_class.as_str(), "worker" | "deep" | "scout" | "daily");
                    let metadata_complete = !mission_id.is_empty()
                        && mission_class_valid
                        && evidence.is_some()
                        && final_output.is_some();

                    let io_complete = transcript_close_error.is_none()
                        && transcript_summary_error.is_none()
                        && final_output_write_error.is_none()
                        && evidence_report_error.is_none()
                        && transcript_sha256.is_some();
                    let evidence_complete = io_complete && seq_ok && sid_ok;
                    let gate09_contract_complete = evidence_complete
                        && metadata_complete
                        && model_identity_ok
                        && source_of_record_ok;
                    let promotable = gate09_contract_complete && out.stop_reason == "FINAL";

                    let mut errors = transcript_summary
                        .get("errors")
                        .and_then(serde_json::Value::as_array)
                        .cloned()
                        .unwrap_or_default();
                    if let Some(detail) = &out.error_detail {
                        errors.push(serde_json::json!({
                            "source": "runtime",
                            "detail": detail
                        }));
                    }
                    if let Some(detail) = &transcript_close_error {
                        errors.push(serde_json::json!({
                            "source": "transcript_writer",
                            "detail": detail
                        }));
                    }
                    if let Some(detail) = &transcript_summary_error {
                        errors.push(serde_json::json!({
                            "source": "transcript_reconstruction",
                            "detail": detail
                        }));
                    }
                    if let Some(detail) = &final_output_write_error {
                        errors.push(serde_json::json!({
                            "source": "final_output_writer",
                            "detail": detail
                        }));
                    }
                    if let Some(detail) = &evidence_report_error {
                        errors.push(serde_json::json!({
                            "source": "evidence_report",
                            "detail": detail
                        }));
                    }

                    let status = if !evidence_complete {
                        "CONTRACT_FAIL"
                    } else if out.stop_reason == "FINAL" && !metadata_complete {
                        "NON_PROMOTABLE_INCOMPLETE_METADATA"
                    } else if out.stop_reason == "FINAL" && !model_identity_ok {
                        "CONTRACT_FAIL"
                    } else if out.stop_reason == "FINAL" {
                        "PASS"
                    } else {
                        "NON_SUCCESS_EVIDENCED"
                    };

                    let manifest_stop_reason = if evidence_complete && model_identity_ok {
                        out.stop_reason.clone()
                    } else {
                        "CONTRACT_FAIL".to_string()
                    };
                    let final_exit_code = if evidence_complete && model_identity_ok {
                        out.exit_code
                    } else {
                        71
                    };

                    let start_ms = transcript_summary
                        .get("start_time")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    let elapsed_ms = transcript_summary
                        .get("elapsed")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0);
                    let run_id = format!("{}-{}", active_session_id, start_ms);
                    // Gate 10: the changeset (base and new hashes, a unified diff), bound by the signed statement.
                    let (changeset_sha256, changeset_error) = match &proposal_handle {
                        None => (None, None),
                        Some(p) => match p.finish(&granted_roots, &run_id, &active_session_id) {
                            Ok(d) => (d, None),
                            Err(e) => (None, Some(e)),
                        },
                    };

                    let routing = session_summary
                        .get("routing")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let router_role = routing
                        .get("resolved_role")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);
                    let escalation_history = routing
                        .get("escalations")
                        .cloned()
                        .unwrap_or_else(|| serde_json::json!([]));
                    let routing_baseline_digest = routing
                        .get("route_table_digest")
                        .cloned()
                        .unwrap_or(serde_json::Value::Null);

                    let contract_checks = serde_json::json!([
                        {
                            "check_id":"G09_SEQ_MONOTONIC",
                            "pass":seq_ok,
                            "detail":"NDJSON seq values are contiguous from 1 for a fresh run or preserve monotonic continuation on resume"
                        },
                        {
                            "check_id":"G09_SESSION_ID_EVERY_EVENT",
                            "pass":sid_ok,
                            "detail":"every parsed audit event carries one consistent session_id"
                        },
                        {
                            "check_id":"G09_TRANSCRIPT_IO_COMPLETE",
                            "pass":transcript_close_error.is_none(),
                            "detail":transcript_close_error
                        },
                        {
                            "check_id":"G09_TRANSCRIPT_RECONSTRUCTABLE",
                            "pass":transcript_summary_error.is_none(),
                            "detail":transcript_summary_error
                        },
                        {
                            "check_id":"G09_FINAL_OUTPUT_IO_COMPLETE",
                            "pass":final_output_write_error.is_none(),
                            "detail":final_output_write_error
                        },
                        {
                            "check_id":"G09_MISSION_CLASS_EXPLICIT",
                            "pass":mission_class_valid,
                            "detail":mission_class
                        },
                        {
                            "check_id":"G09_EVIDENCE_PATH_PRESENT",
                            "pass":evidence.is_some(),
                            "detail":evidence
                        },
                        {
                            "check_id":"G09_FINAL_OUTPUT_PATH_PRESENT",
                            "pass":final_output.is_some(),
                            "detail":final_output
                        },
                        {
                            "check_id":"G09_MODEL_IDENTITY",
                            "pass":model_identity_ok,
                            "detail":{"requested":model,"actual":actual_model}
                        },
                        {
                            "check_id":"B1_SOURCE_OF_RECORD_MATCH",
                            "pass":source_of_record_ok,
                            "detail":{"embedded":source_digest,"source_of_record":source_of_record_digest}
                        }
                    ]);

                    let ev = serde_json::json!({
                        "schema": "hercules_native_evidence_v1",
                        "schema_version": 1,
                        "legacy_schema": "nah_gate07_mission_v1",
                        "run_id": run_id,
                        "session_id": active_session_id,
                        "mission_id": mission_id,
                        "mission_class": mission_class,
                        "harness_id": "native-candidate",
                        "harness_name": "hercules-agent",
                        "harness_version": candidate_version,
                        "source_digest": source_digest,
                        "source_of_record_digest": source_of_record_digest,
                        "binary_digest": binary_digest,
                        "config_digest": config_sha256,
                        "provider": cfg.provider_kind,
                        "endpoint": cfg.provider_endpoint,
                        "requested_model": model,
                        "model_requested": model,
                        "actual_model": actual_model,
                        "model_actual": actual_model,
                        "router_role": router_role,
                        "escalation_history": escalation_history,
                        "tool_requests": transcript_summary
                            .get("tool_requests")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                        "authority_decisions": transcript_summary
                            .get("authority_decisions")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                        "tool_results": transcript_summary
                            .get("tool_results")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                        "errors": errors,
                        "retries": transcript_summary
                            .get("retries")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                        "checkpoints": [{
                            "checkpoint_seq": session_summary
                                .get("checkpoint_seq")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null),
                            "checkpoint_path": session_summary
                                .get("checkpoint_path")
                                .cloned()
                                .unwrap_or(serde_json::Value::Null)
                        }],
                        "recovery_events": transcript_summary
                            .get("recovery_events")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                        "router_decisions": transcript_summary
                            .get("router_decisions")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                        "escalation_events": transcript_summary
                            .get("escalation_events")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!([])),
                        "time_basis": "unix_epoch_ms_utc",
                        "start_time": transcript_summary
                            .get("start_time")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "end_time": transcript_summary
                            .get("end_time")
                            .cloned()
                            .unwrap_or(serde_json::Value::Null),
                        "elapsed": elapsed_ms,
                        "duration_seconds": elapsed_ms / 1000,
                        "status": status,
                        "stop_reason": manifest_stop_reason,
                        "runtime_stop_reason": out.stop_reason,
                        "exit_code": final_exit_code,
                        "turn_count": out.turn_count,
                        "tool_execution_count": out.tools_dispatched_total,
                        "tools_dispatched_total": out.tools_dispatched_total,
                        "unsupported_total": out.unsupported_total,
                        "malformed_total": out.malformed_total,
                        "tool_rejections_total": out.tool_rejections_total,
                        "real_capability_executions": out.real_capability_executions,
                        "final_answer": audit::redact_value(
                            &serde_json::json!(out.final_content)
                        ),
                        "final_content": audit::redact_value(
                            &serde_json::json!(out.final_content)
                        ),
                        "final_result_digest": final_result_digest,
                        "transcript_path": transcript,
                        "transcript_sha256": transcript_sha256,
                        "transcript_digest": transcript_sha256,
                        "final_output_path": final_output,
                        "final_output_sha256": final_result_digest,
                        "policy_digest": policy_digest,
                        "routing_baseline_digest": routing_baseline_digest,
                        "session": session_summary,
                        "error_detail": out.error_detail,
                        "max_iterations": max_iterations,
                        "contract_checks": contract_checks,
                        "evidence_complete": evidence_complete,
                        "gate09_contract_complete": gate09_contract_complete,
                        "promotable": promotable,
                        "unresolved": []
                    });

                    let mut ev = ev;
                    if build1 {
                        ev["build1"] = serde_json::json!({
                            "grounding": grounding,
                            "evidence_report_path": evidence_report,
                            "evidence_report_sha256": evidence_report_sha256,
                            "evidence_report_error": evidence_report_error,
                            "read_roots": granted_roots.summary_json(),
                            "model_options": gateway::model_options(&cfg.provider_kind, num_predict, cfg.sampling_greedy, cfg.provider_thinking_off),
                            "context_budget_bytes": context_budget_bytes
                        });
                        if let Some(p) = &proposal_handle {
                            ev["proposal"] = serde_json::json!({
                                "proposal_dir": p.dir.display().to_string(),
                                "write_roots": write_roots.iter().map(|r| serde_json::json!({"name": r.name, "path": r.path.display().to_string()})).collect::<Vec<_>>(),
                                "changeset_sha256": changeset_sha256,
                                "changeset_error": changeset_error,
                                "applied": false,
                                "note": "nothing in the roots changed; `change apply` applies the reviewed changeset"
                            });
                        }
                        ev["attestation"] = serde_json::json!({
                            "attestation_path": attestation,
                            "keyid": signing_keyid,
                            "payload_type": attest::PAYLOAD_TYPE
                        });
                    }
                    if let Err(err) = write_evidence(&evidence, &ev) {
                        eprintln!("HERCULES_AGENT_ERROR evidence_write_failed err={err}");
                        std::process::exit(72);
                    }

                    // Signed runs: one statement binds the transcript chain head to every file the run wrote,
                    // signed whatever the stop reason. Digests are of the files as they are on disk.
                    let facts = attest::transcript_facts(&transcript);
                    let (t_sha, t_events, t_head) = match &facts {
                        Ok(f) => (serde_json::json!(f.sha256), serde_json::json!(f.events), serde_json::json!(f.head)),
                        Err(_) => (serde_json::Value::Null, serde_json::Value::Null, serde_json::Value::Null),
                    };
                    let end_ms = transcript_summary.get("end_time").and_then(serde_json::Value::as_u64).unwrap_or(0);
                    let statement = serde_json::json!({
                        "schema": attest::STATEMENT_SCHEMA,
                        "kind": "mission",
                        "harness": {"name": env!("CARGO_PKG_NAME"), "version": VERSION},
                        "session_id": active_session_id,
                        "run_id": run_id,
                        "mission_id": mission_id,
                        "transcript": {"sha256": t_sha, "events": t_events, "head": t_head},
                        "final_content_sha256": attest::file_sha256(final_output.as_deref()),
                        "evidence_report_sha256": attest::file_sha256(evidence_report.as_deref()),
                        "manifest_sha256": attest::file_sha256(evidence.as_deref()),
                        "source_digest": source_digest,
                        "binary_digest": binary_digest,
                        "config_digest": config_sha256,
                        "model_requested": model,
                        "model_actual": actual_model,
                        "roots_granted": granted_roots.summary_json(),
                        "stop_reason": manifest_stop_reason,
                        "exit_code": final_exit_code,
                        "changeset_sha256": changeset_sha256,
                        "started_at": attest::rfc3339_ms(start_ms),
                        "ended_at": attest::rfc3339_ms(end_ms)
                    });
                    let envelope = attest::sign_envelope(&signing_key, &statement);
                    let attestation_path = attestation.as_deref().unwrap_or("");
                    if let Err(err) = audit::write_text_atomic(attestation_path, &envelope) {
                        eprintln!("HERCULES_AGENT_ERROR attestation_write_failed err={err}");
                        std::process::exit(73);
                    }
                    // Gate 10: where this run's signed files are, so `change apply` can verify the run first.
                    if let Some(p) = &proposal_handle {
                        let abs = |x: &Option<String>| x.as_deref().and_then(|v| std::fs::canonicalize(v).ok()).map(|v| v.display().to_string());
                        let run = serde_json::json!({
                            "run_id": run_id, "session_id": active_session_id, "changeset_sha256": changeset_sha256,
                            "transcript": std::fs::canonicalize(&transcript).ok().map(|v| v.display().to_string()),
                            "final": abs(&final_output), "report": abs(&evidence_report), "manifest": abs(&evidence), "attestation": abs(&attestation)
                        });
                        if let Err(e) = proposal::atomic_write(&p.dir.join("run.json"), format!("{run}\n").as_bytes(), 0o644) {
                            eprintln!("HERCULES_AGENT_ERROR proposal_run_record_failed err={e}");
                            std::process::exit(73);
                        }
                        match &changeset_sha256 {
                            Some(d) => eprintln!("HERCULES_AGENT_PROPOSAL changeset={d} dir={} (review changeset.diff; nothing is applied)", p.dir.display()),
                            None => eprintln!("HERCULES_AGENT_PROPOSAL changeset=none dir={}{}", p.dir.display(), changeset_error.as_deref().map(|e| format!(" error={e}")).unwrap_or_default()),
                        }
                    }

                    if !out.final_content.is_empty() {
                        println!("{}", out.final_content);
                    }
                    eprintln!(
                        "HERCULES_AGENT_MISSION stop_reason={} turns={} unsupported={} malformed={} gate09_contract_complete={} promotable={}{} signed_keyid={}",
                        ev["stop_reason"].as_str().unwrap_or("CONTRACT_FAIL"),
                        out.turn_count,
                        out.unsupported_total,
                        out.malformed_total,
                        gate09_contract_complete,
                        promotable,
                        if build1 { format!(" grounding={}", grounding.as_str().unwrap_or("UNKNOWN")) } else { String::new() },
                        signing_keyid
                    );
                    std::process::exit(final_exit_code);
                }
                _ => usage(),
            }
        }
        "chat" => {
            gateway::install_signal_handlers();
            let cfg_path = match config_arg(&args) {
                Ok(p) => p,
                Err(e) => e.exit(),
            };
            let cfg = match config::load(&cfg_path) {
                Ok(c) => c,
                Err(e) => e.exit(),
            };
            let model = match flag_value(&args, "--model") {
                Some(m) if !m.is_empty() => m,
                _ => AppError::new(
                    ErrCat::Usage,
                    "--model <exact-id> is required; the gateway never selects a model",
                )
                .exit(),
            };
            let prompt = match flag_value(&args, "--prompt") {
                Some(p) => p,
                None => AppError::new(ErrCat::Usage, "--prompt <text> is required").exit(),
            };
            let system = flag_value(&args, "--system");
            let stream = args.iter().any(|a| a == "--stream");
            let timeout_s: u64 = match flag_value(&args, "--timeout-seconds") {
                Some(t) => match t.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        AppError::new(ErrCat::Usage, "--timeout-seconds must be an integer").exit()
                    }
                },
                None => cfg.agent_request_timeout_seconds,
            };
            let num_predict: i64 = match flag_value(&args, "--num-predict") {
                Some(t) => match t.parse() {
                    Ok(v) => v,
                    Err(_) => {
                        AppError::new(ErrCat::Usage, "--num-predict must be an integer").exit()
                    }
                },
                None => 512,
            };
            let evidence = flag_value(&args, "--evidence");

            let mut messages: Vec<(String, String)> = Vec::new();
            if let Some(sys) = system {
                messages.push(("system".to_string(), sys));
            }
            messages.push(("user".to_string(), prompt));

            let api_key = match cfg.api_key() {
                Ok(k) => k,
                Err(e) => e.exit(),
            };
            let cargs = gateway::ChatArgs {
                provider: cfg.provider_kind.clone(),
                api_key,
                thinking_off: cfg.provider_thinking_off,
                endpoint: cfg.provider_endpoint.clone(),
                model: model.clone(),
                messages,
                stream,
                timeout: std::time::Duration::from_secs(timeout_s),
                num_predict,
                greedy: cfg.sampling_greedy,
                native: false,
                tools: None,
            };
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);

            match gateway::chat(&cargs) {
                Ok(r) => {
                    let ev = serde_json::json!({
                        "schema": "nah_gate03_call_v1",
                        "unix_ts": ts,
                        "endpoint": cfg.provider_endpoint,
                        "path": gateway::chat_path(&cfg.provider_kind),
                        "model_requested": model,
                        "model_actual": r.model_actual,
                        "stream": stream,
                        "http_status": r.http_status,
                        "stop_reason": "FINAL",
                        "done_reason": r.done_reason,
                        "duration_ms": r.duration_ms as u64,
                        "thinking_present": r.thinking_present,
                        "chunk_count": r.chunk_count,
                        "content": r.content,
                        "raw_lines": r.raw_lines,
                        "retry_policy": "none"
                    });
                    if let Err(err) = write_evidence(&evidence, &ev) {
                        AppError::new(ErrCat::Internal, format!("evidence write failed: {err}"))
                            .exit();
                    }
                    println!("{}", r.content);
                    eprintln!(
                        "HERCULES_AGENT_CHAT model={} status=FINAL done_reason={} duration_ms={} chunks={}",
                        r.model_actual, r.done_reason, r.duration_ms, r.chunk_count
                    );
                }
                Err(e) => {
                    let stop = match e.cat {
                        ErrCat::Timeout => "TIMEOUT".to_string(),
                        ErrCat::Cancelled => "CANCELLED".to_string(),
                        other => format!("ERROR:{}", other.label()),
                    };
                    let ev = serde_json::json!({
                        "schema": "nah_gate03_call_v1",
                        "unix_ts": ts,
                        "endpoint": cfg.provider_endpoint,
                        "path": gateway::chat_path(&cfg.provider_kind),
                        "model_requested": model,
                        "model_actual": null,
                        "stream": stream,
                        "stop_reason": stop,
                        "error_detail": e.detail,
                        "retry_policy": "none"
                    });
                    if let Err(err) = write_evidence(&evidence, &ev) {
                        AppError::new(ErrCat::Internal, format!("evidence write failed: {err}"))
                            .exit();
                    }
                    e.exit();
                }
            }
        }
        "route" => {
            if args.len() < 2 {
                usage();
            }
            let route_table_path = match flag_value(&args, "--route-table") {
                Some(v) => v,
                None => AppError::new(ErrCat::Usage, "--route-table <json> is required").exit(),
            };
            let table = match router::RouteTable::load(&route_table_path) {
                Ok(v) => v,
                Err(e) => AppError::new(ErrCat::Usage, format!("route table invalid: {e}")).exit(),
            };
            match args[1].as_str() {
                "resolve" => {
                    let namespace = match flag_value(&args, "--namespace") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--namespace <...> is required").exit()
                        }
                    };
                    let key = match flag_value(&args, "--key") {
                        Some(v) => v,
                        None => AppError::new(ErrCat::Usage, "--key <name> is required").exit(),
                    };
                    let available_path = flag_value(&args, "--available-models");
                    let available = match router::load_available_models(available_path.as_deref()) {
                        Ok(v) => v,
                        Err(e) => AppError::new(ErrCat::Usage, e).exit(),
                    };
                    let allow_fallback = args.iter().any(|a| a == "--allow-frozen-fallback");
                    match table.resolve(&namespace, &key, available.as_ref(), allow_fallback) {
                        Ok(v) => println!("{:#}", v),
                        Err(e) => {
                            AppError::new(ErrCat::Usage, format!("route resolution failed: {e}"))
                                .exit()
                        }
                    }
                }
                "escalate" => {
                    let from_tier = match flag_value(&args, "--from-tier") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--from-tier <tier> is required").exit()
                        }
                    };
                    let trigger = match flag_value(&args, "--trigger") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--trigger <trigger> is required").exit()
                        }
                    };
                    let depth: u64 = match flag_value(&args, "--depth") {
                        Some(v) => match v.parse() {
                            Ok(n) => n,
                            Err(_) => {
                                AppError::new(ErrCat::Usage, "--depth must be an integer").exit()
                            }
                        },
                        None => 0,
                    };
                    let available_path = flag_value(&args, "--available-models");
                    let available = match router::load_available_models(available_path.as_deref()) {
                        Ok(v) => v,
                        Err(e) => AppError::new(ErrCat::Usage, e).exit(),
                    };
                    match table.escalate(&from_tier, &trigger, depth, available.as_ref()) {
                        Ok(v) => println!("{:#}", v),
                        Err(e) => {
                            AppError::new(ErrCat::Usage, format!("route escalation failed: {e}"))
                                .exit()
                        }
                    }
                }
                "bind-checkpoint" => {
                    let checkpoint = match flag_value(&args, "--checkpoint") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--checkpoint <path> is required").exit()
                        }
                    };
                    let namespace = match flag_value(&args, "--namespace") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--namespace <...> is required").exit()
                        }
                    };
                    let key = match flag_value(&args, "--key") {
                        Some(v) => v,
                        None => AppError::new(ErrCat::Usage, "--key <name> is required").exit(),
                    };
                    let authority_path = match flag_value(&args, "--authority-summary") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--authority-summary <json> is required")
                                .exit()
                        }
                    };
                    let authority = match router::load_json_file(&authority_path) {
                        Ok(v) => v,
                        Err(e) => AppError::new(ErrCat::Usage, e).exit(),
                    };
                    match router::bind_checkpoint(&table, &checkpoint, &namespace, &key, &authority)
                    {
                        Ok(v) => println!("{:#}", v),
                        Err(e) => {
                            AppError::new(ErrCat::Usage, format!("route bind failed: {e}")).exit()
                        }
                    }
                }
                "escalate-checkpoint" => {
                    let checkpoint = match flag_value(&args, "--checkpoint") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--checkpoint <path> is required").exit()
                        }
                    };
                    let trigger = match flag_value(&args, "--trigger") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--trigger <trigger> is required").exit()
                        }
                    };
                    let authority_path = match flag_value(&args, "--authority-summary") {
                        Some(v) => v,
                        None => {
                            AppError::new(ErrCat::Usage, "--authority-summary <json> is required")
                                .exit()
                        }
                    };
                    let authority = match router::load_json_file(&authority_path) {
                        Ok(v) => v,
                        Err(e) => AppError::new(ErrCat::Usage, e).exit(),
                    };
                    let available_path = flag_value(&args, "--available-models");
                    let available = match router::load_available_models(available_path.as_deref()) {
                        Ok(v) => v,
                        Err(e) => AppError::new(ErrCat::Usage, e).exit(),
                    };
                    match router::escalate_checkpoint(
                        &table,
                        &checkpoint,
                        &trigger,
                        &authority,
                        available.as_ref(),
                    ) {
                        Ok(v) => println!("{:#}", v),
                        Err(e) => AppError::new(
                            ErrCat::Usage,
                            format!("checkpoint escalation failed: {e}"),
                        )
                        .exit(),
                    }
                }
                _ => usage(),
            }
        }
        "tools" => {
            if args.len() < 2 {
                usage();
            }
            match args[1].as_str() {
                "registry" => {
                    println!("{:#}", tools::registry_json());
                }
                "simulate" => {
                    let transcript_path = match flag_value(&args, "--transcript") {
                        Some(t) => t,
                        None => {
                            AppError::new(ErrCat::Usage, "--transcript <path> is required").exit()
                        }
                    };
                    gateway::install_signal_handlers();
                    let sandbox_root = flag_value(&args, "--sandbox-root");
                    let legacy_approvals = flag_values(&args, "--approve-request");
                    if !legacy_approvals.is_empty() {
                        AppError::new(
                            ErrCat::Usage,
                            "--approve-request is disabled; use --approval-file",
                        )
                        .exit();
                    }
                    let approval_file = flag_value(&args, "--approval-file");
                    let authority_session_id = flag_value(&args, "--session-id")
                        .unwrap_or_else(|| "tools-simulate".into());
                    let authority = match authority::AuthorityContext::new(
                        sandbox_root.as_deref(),
                        approval_file.as_deref(),
                        Some(&authority_session_id),
                    ) {
                        Ok(a) => a,
                        Err(e) => {
                            AppError::new(ErrCat::Usage, format!("authority context invalid: {e}"))
                                .exit()
                        }
                    };
                    let mut files: Vec<String> = Vec::new();
                    let mut it = args.iter();
                    while let Some(a) = it.next() {
                        if a == "--response-file" {
                            if let Some(f) = it.next() {
                                files.push(f.clone());
                            }
                        }
                    }
                    if files.is_empty() {
                        AppError::new(ErrCat::Usage, "at least one --response-file is required")
                            .exit();
                    }
                    let mut tw = match transcript::TranscriptWriter::new(
                        &transcript_path,
                        &format!("tools-simulate-{}", std::process::id()),
                    ) {
                        Ok(t) => t,
                        Err(e) => AppError::new(
                            ErrCat::Internal,
                            format!("transcript create failed: {e}"),
                        )
                        .exit(),
                    };
                    tw.emit("session_start", None, serde_json::json!({"mode": "tools_simulate", "real_capabilities_present": true, "authority": authority.summary_json()}));
                    let mut executed: std::collections::HashSet<String> =
                        std::collections::HashSet::new();
                    let mut summaries: Vec<serde_json::Value> = Vec::new();
                    for (i, f) in files.iter().enumerate() {
                        let turn = (i + 1) as u64;
                        let content = match std::fs::read_to_string(f) {
                            Ok(c) => c,
                            Err(e) => AppError::new(
                                ErrCat::Usage,
                                format!("response file unreadable: {f}: {e}"),
                            )
                            .exit(),
                        };
                        tw.emit(
                            "turn.input",
                            Some(turn),
                            serde_json::json!({"content": format!("simulated response file: {f}")}),
                        );
                        tw.emit(
                            "turn.model_response",
                            Some(turn),
                            serde_json::json!({"content": content, "simulated": true}),
                        );
                        let s = match tools::handle(
                            &content,
                            &mut executed,
                            &mut tw,
                            turn,
                            &authority,
                        ) {
                            tools::ToolTurn::NotTool => serde_json::json!({
                                "file": f, "classification": "not_tool", "dispatched": false, "rejected": false
                            }),
                            tools::ToolTurn::Handled(tr) => serde_json::json!({
                                "file": f, "classification": "tool_turn",
                                "dispatched": tr.dispatched, "rejected": tr.rejected,
                                "tool": tr.tool, "rejection_code": tr.rejection_code,
                                "result_status": tr.result_status,
                                "observation": tr.observation
                            }),
                        };
                        summaries.push(s);
                    }
                    tw.emit(
                        "session_stop",
                        None,
                        serde_json::json!({"mode": "tools_simulate", "turns": files.len()}),
                    );
                    println!("{:#}", serde_json::json!({"simulate": summaries}));
                }
                _ => usage(),
            }
        }
        _ => usage(),
    }
}
