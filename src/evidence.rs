//! Build 1, item 3: evidence-derived reports.
//!
//! The report is a pure function of the run's transcript (the audit record) and its
//! final answer. It never trusts what the model says it inspected: paths_inspected
//! and read_failures come from the harness's own receipts, and any absolute path the
//! answer mentions without a successful read is listed in paths_mentioned_not_read.
//! Because it is derived from the transcript, anyone can re-derive and verify it.

use crate::roots::RootPolicy;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;

const READ_TOOLS: [&str; 4] = ["fs.read", "fs.list", "fs.stat", "cmd.run"];


fn events(transcript: &str) -> Result<Vec<Value>, String> {
    let raw = std::fs::read_to_string(transcript).map_err(|e| format!("transcript read failed: {e}"))?;
    let mut out = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = serde_json::from_str(line).map_err(|e| format!("transcript line {} malformed: {e}", i + 1))?;
        out.push(v);
    }
    Ok(out)
}

/// Absolute-path-looking tokens in free text: "/a/b.py:12," -> "/a/b.py".
pub fn mentioned_paths(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for tok in text.split(|c: char| c.is_whitespace() || "\"'`,()[]{}<>;|=".contains(c)) {
        // Strip sentence punctuation and Markdown emphasis around the token.
        // A leading "~/" is a home-relative path, not emphasis: keep it as written.
        let home_rel = tok.trim_start_matches(|c: char| "*_".contains(c)).starts_with("~/");
        let tok = if home_rel {
            tok.trim_start_matches(|c: char| "*_".contains(c)).trim_end_matches(|c: char| "*_~".contains(c))
        } else {
            tok.trim_matches(|c: char| "*_~".contains(c))
        };
        let mut t = tok.trim_end_matches(|c: char| ".:;!?*_~".contains(c)).to_string();
        // Strip a trailing ":<line>" or ":<line>:<col>" reference.
        loop {
            match t.rsplit_once(':') {
                Some((head, tail)) if !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit()) => t = head.to_string(),
                _ => break,
            }
        }
        let t = t.trim_end_matches('/').to_string();
        let abs = if t.starts_with("~/") { &t[1..] } else { &t[..] };
        if !abs.starts_with('/') || abs.starts_with("//") || abs.len() < 3 || !abs[1..].contains(|c: char| c == '/' || c == '.') {
            continue;
        }
        if !out.contains(&t) {
            out.push(t);
        }
    }
    out
}

struct Inspected {
    root: Value,
    kinds: Vec<String>,
    receipts: Vec<String>,
    shown_sha256: Vec<String>,
    raw_paths: Vec<String>,
}

fn arg_paths(tool: &str, args: &Value) -> Vec<String> {
    if tool == "cmd.run" {
        args["argv"]
            .as_array()
            .map(|a| a.iter().skip(1).filter_map(Value::as_str).filter(|s| s.starts_with('/')).map(str::to_string).collect())
            .unwrap_or_default()
    } else {
        args["path"].as_str().map(|p| vec![p.to_string()]).unwrap_or_default()
    }
}

pub fn derive(
    transcript: &str,
    final_content: &str,
    roots: &RootPolicy,
    stop_reason: &str,
) -> Result<Value, String> {
    let evs = events(transcript)?;
    let mut inspected: BTreeMap<String, Inspected> = BTreeMap::new();
    let mut commands = Vec::new();
    let mut failures = Vec::new();
    let mut rejected_requests = Vec::new();
    let mut attempted = 0usize;
    let mut succeeded = 0usize;
    // Gate 10: proposed writes, from the receipts (never from what the model says it changed).
    let mut proposed: BTreeMap<String, Value> = BTreeMap::new();
    let mut write_refusals: Vec<Value> = Vec::new();
    let mut any_write = false;

    for e in &evs {
        let data = &e["data"];
        match e["event"].as_str() {
            Some("turn.tool_validation") if data["ok"] == json!(false) => {
                rejected_requests.push(json!({"turn": e["turn"], "code": data["code"], "detail": data["detail"]}));
            }
            Some("turn.tool_result") => {
                let Some(r) = data.get("receipt") else { continue };
                let tool = r["tool"].as_str().unwrap_or("");
                if matches!(tool, "fs.write" | "fs.replace") {
                    any_write = true;
                    let rid = r["request_id"].as_str().unwrap_or("").to_string();
                    if r["status"] == json!("ok") {
                        for t in r["targets"].as_array().cloned().unwrap_or_default() {
                            let p = t["path"].as_str().unwrap_or("").to_string();
                            let e = proposed.entry(p.clone()).or_insert_with(|| {
                                json!({"path": p, "root": t["root"], "base_sha256": t["base_sha256"], "receipts": []})
                            });
                            e["after_sha256"] = t["after_sha256"].clone();
                            e["bytes"] = t["bytes"].clone();
                            if let Some(a) = e["receipts"].as_array_mut() {
                                a.push(json!(rid));
                            }
                        }
                    } else {
                        let err = &data["envelope"]["error"];
                        write_refusals.push(json!({"tool": tool, "path": r["args"]["path"], "code": r.get("code").cloned().filter(|v| !v.is_null()).unwrap_or_else(|| err["code"].clone()), "receipt": rid}));
                    }
                    continue;
                }
                if !READ_TOOLS.contains(&tool) {
                    continue;
                }
                attempted += 1;
                let rid = r["request_id"].as_str().unwrap_or("").to_string();
                let status = r["status"].as_str().unwrap_or("");
                if status == "ok" {
                    succeeded += 1;
                    let raw_paths = arg_paths(tool, &r["args"]);
                    for t in r["targets"].as_array().cloned().unwrap_or_default() {
                        let p = t["path"].as_str().unwrap_or("").to_string();
                        let entry = inspected.entry(p).or_insert_with(|| Inspected {
                            root: t["root"].clone(),
                            kinds: Vec::new(),
                            receipts: Vec::new(),
                            shown_sha256: Vec::new(),
                            raw_paths: Vec::new(),
                        });
                        let k = t["kind"].as_str().unwrap_or("").to_string();
                        if !entry.kinds.contains(&k) {
                            entry.kinds.push(k);
                        }
                        entry.receipts.push(rid.clone());
                        if let Some(h) = t["shown_sha256"].as_str() {
                            entry.shown_sha256.push(h.to_string());
                        }
                        for rp in &raw_paths {
                            if !entry.raw_paths.contains(rp) {
                                entry.raw_paths.push(rp.clone());
                            }
                        }
                    }
                    if tool == "cmd.run" {
                        let result = &data["envelope"]["result"];
                        commands.push(json!({"argv": r["args"]["argv"], "exit_code": result["exit_code"], "native": result["native"], "receipt": rid}));
                    }
                } else {
                    let err = &data["envelope"]["error"];
                    let code = r.get("code").cloned().filter(|v| !v.is_null()).unwrap_or_else(|| err["code"].clone());
                    let detail = r.get("detail").cloned().filter(|v| !v.is_null()).unwrap_or_else(|| {
                        err.get("detail").cloned().filter(|v| !v.is_null()).unwrap_or_else(|| err["message"].clone())
                    });
                    failures.push(json!({
                        "tool": tool,
                        "paths": arg_paths(tool, &r["args"]),
                        "argv": r["args"].get("argv").cloned().unwrap_or(Value::Null),
                        "code": code,
                        "detail": detail,
                        "receipt": rid
                    }));
                }
            }
            _ => {}
        }
    }

    // Which mentioned paths are covered by a successful read or listing?
    // An exact match always counts. A path *under* a listed/searched directory counts
    // only if it was not itself refused and is not on the deny list (a recursive grep
    // or listing skips those, so it never saw them).
    let failed_paths: Vec<String> = failures
        .iter()
        .flat_map(|f| f["paths"].as_array().cloned().unwrap_or_default())
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    let denied_lexically = |m: &str| -> bool {
        let p = Path::new(m);
        roots
            .roots()
            .iter()
            .any(|r| p.starts_with(&r.path) && roots.deny_reason(p, r).is_some())
    };
    let covered = |m: &str| -> bool {
        let exact = inspected
            .iter()
            .any(|(canon, ins)| m == canon || ins.raw_paths.iter().any(|rp| m == rp.trim_end_matches('/')));
        if exact {
            return true;
        }
        // A directory the run looked inside: some inspected path lies under it.
        if !m.starts_with('~') && inspected.keys().any(|canon| Path::new(canon).starts_with(m) && canon.as_str() != m) {
            return true;
        }
        if failed_paths.iter().any(|f| f == m) || denied_lexically(m) {
            return false;
        }
        inspected.iter().any(|(canon, ins)| {
            let dir_like = ins.kinds.iter().any(|k| k == "directory" || k == "git_repository");
            dir_like
                && (Path::new(m).starts_with(canon)
                    || ins.raw_paths.iter().any(|rp| Path::new(m).starts_with(rp.trim_end_matches('/'))))
        })
    };
    let mentioned_not_read: Vec<String> = mentioned_paths(final_content).into_iter().filter(|m| !covered(m)).collect();

    // A failed request is recovered when every path it named was read successfully
    // (exact path) in this run, e.g. a grep refused for its pattern grammar and then
    // re-run in an accepted form. Recovered failures stay listed but do not lower grounding.
    let exactly_read = |m: &str| -> bool {
        inspected
            .iter()
            .any(|(canon, ins)| m == canon || ins.raw_paths.iter().any(|rp| m == rp.trim_end_matches('/')))
    };
    for f in failures.iter_mut() {
        let paths: Vec<String> = f["paths"].as_array().cloned().unwrap_or_default().iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
        let recovered = !paths.is_empty() && paths.iter().all(|p| exactly_read(p.trim_end_matches('/')));
        f["recovered"] = json!(recovered);
    }
    let unrecovered = failures.iter().filter(|f| f["recovered"] != json!(true)).count();

    let grounding = if roots.is_empty() && attempted == 0 {
        "NOT_APPLICABLE"
    } else if succeeded == 0 {
        "NO_EVIDENCE"
    } else if unrecovered > 0 || !mentioned_not_read.is_empty() {
        "PARTIAL"
    } else {
        "EVIDENCED"
    };

    let paths_inspected: Vec<Value> = inspected
        .into_iter()
        .map(|(p, i)| json!({"path": p, "root": i.root, "kinds": i.kinds, "receipts": i.receipts, "shown_sha256": i.shown_sha256}))
        .collect();

    let mut report = json!({
        "schema": "hercules_evidence_report_v1",
        "grounding": grounding,
        "stop_reason": stop_reason,
        "roots_granted": roots.roots().iter().map(|r| json!({"name": r.name, "path": r.path.display().to_string()})).collect::<Vec<_>>(),
        "root_deny_extra": roots.deny_extra(),
        "reads_attempted": attempted,
        "reads_succeeded": succeeded,
        "paths_inspected": paths_inspected,
        "commands_run": commands,
        "read_failures": failures,
        "rejected_requests": rejected_requests,
        "paths_mentioned_not_read": mentioned_not_read,
        "final_content_sha256": crate::audit::sha256_text(final_content),
        "transcript_sha256": crate::audit::sha256_file(transcript).ok(),
        "derivation": "pure function of the transcript receipts and the final answer; no model input"
    });
    if any_write {
        report["files_proposed"] = json!(proposed.into_values().collect::<Vec<_>>());
        report["write_refusals"] = json!(write_refusals);
    }
    Ok(report)
}

/// Re-derive a report from its transcript and final answer and compare it with the
/// report as stored. Roots and the extra deny patterns come from the report itself; the
/// transcript and final answer are checked against the hashes it records.
pub fn verify(report: &Value, transcript: &str, final_content: &str) -> Result<Vec<String>, String> {
    let roots: Vec<crate::roots::Root> = report["roots_granted"]
        .as_array()
        .ok_or("report has no roots_granted")?
        .iter()
        .map(|r| crate::roots::Root {
            name: r["name"].as_str().unwrap_or("").to_string(),
            path: std::path::PathBuf::from(r["path"].as_str().unwrap_or("")),
        })
        .collect();
    let deny: Vec<String> = report["root_deny_extra"]
        .as_array()
        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
        .unwrap_or_default();
    let policy = RootPolicy::new(roots, deny);
    let stop = report["stop_reason"].as_str().ok_or("report has no stop_reason")?;
    let fresh = derive(transcript, final_content, &policy, stop)?;
    let mut diffs = Vec::new();
    let (Some(a), Some(b)) = (report.as_object(), fresh.as_object()) else {
        return Err("report is not a JSON object".into());
    };
    for k in a.keys().chain(b.keys().filter(|k| !a.contains_key(*k))) {
        if a.get(k) != b.get(k) {
            diffs.push(k.clone());
        }
    }
    Ok(diffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roots::{Root, RootPolicy};

    fn write_transcript(lines: &[Value]) -> String {
        let p = std::env::temp_dir().join(format!(
            "hercules-evidence-{}-{}.ndjson",
            std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
        ));
        let body: String = lines.iter().map(|l| format!("{l}\n")).collect();
        std::fs::write(&p, body).unwrap();
        p.display().to_string()
    }

    fn ok_read(rid: &str, raw: &str, canon: &str, kind: &str) -> Value {
        json!({"event":"turn.tool_result","turn":1,"data":{"envelope":{"status":"ok","result":{}},
            "receipt":{"request_id":rid,"tool":"fs.read","args":{"path":raw},"status":"ok",
            "targets":[{"path":canon,"root":"r","kind":kind,"shown_sha256":"ab"}]}}})
    }

    fn denied(rid: &str, raw: &str) -> Value {
        json!({"event":"turn.tool_result","turn":1,"data":{"envelope":{"status":"rejected","error":{"code":"ROOT_POLICY","detail":"outside"}},
            "receipt":{"request_id":rid,"tool":"fs.read","args":{"path":raw},"status":"rejected","code":"ROOT_POLICY","detail":"outside","targets":[]}}})
    }

    fn roots() -> RootPolicy {
        RootPolicy::new(vec![Root { name: "r".into(), path: "/data/repo".into() }], vec![])
    }

    #[test]
    fn mentioned_paths_parse() {
        let m = mentioned_paths("Read /data/repo/a.py:12, and \"/data/repo/b.rs\". Also 1/2 and / and //x and https://x.y/z.");
        assert_eq!(m, vec!["/data/repo/a.py", "/data/repo/b.rs"]);
        let m = mentioned_paths("Listed **/Library/LaunchDaemons** and _/usr/local/libexec_.");
        assert_eq!(m, vec!["/Library/LaunchDaemons", "/usr/local/libexec"]);
    }

    #[test]
    fn not_applicable_for_contract_tests() {
        let t = write_transcript(&[json!({"event":"session_start","data":{}})]);
        let r = derive(&t, "DISPOSITION=SOUND", &RootPolicy::default(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "NOT_APPLICABLE");
    }

    #[test]
    fn no_evidence_theoretical_analysis_case() {
        // The Aug 21 deep-review shape: every read refused, confident answer anyway.
        let t = write_transcript(&[denied("r1", "/data/repo/ask.py"), denied("r2", "/data/repo/memory_write_gate.py")]);
        let answer = "Lost updates will occur. paths_inspected: /data/repo/ask.py (Theoretical Analysis)";
        let r = derive(&t, answer, &roots(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "NO_EVIDENCE");
        assert_eq!(r["read_failures"].as_array().unwrap().len(), 2);
        assert_eq!(r["paths_mentioned_not_read"], json!(["/data/repo/ask.py"]));
    }

    #[test]
    fn no_evidence_when_roots_granted_but_nothing_read() {
        let t = write_transcript(&[]);
        let r = derive(&t, "all fine", &roots(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "NO_EVIDENCE");
    }

    #[test]
    fn evidenced_and_partial() {
        let t = write_transcript(&[ok_read("r1", "/data/repo/a.py", "/data/repo/a.py", "file")]);
        let r = derive(&t, "Checked /data/repo/a.py:3.", &roots(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "EVIDENCED");
        assert_eq!(r["paths_inspected"][0]["receipts"], json!(["r1"]));
        let r = derive(&t, "Checked /data/repo/a.py and /data/repo/b.py", &roots(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "PARTIAL");
        assert_eq!(r["paths_mentioned_not_read"], json!(["/data/repo/b.py"]));
        let t = write_transcript(&[ok_read("r1", "/data/repo/a.py", "/data/repo/a.py", "file"), denied("r2", "/etc/passwd")]);
        let r = derive(&t, "ok", &roots(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "PARTIAL");
    }

    #[test]
    fn recovered_failure_does_not_lower_grounding() {
        // A request refused for its form, then the same file read successfully.
        let t = write_transcript(&[denied("r1", "/data/repo/a.py"), ok_read("r2", "/data/repo/a.py", "/data/repo/a.py", "file")]);
        let r = derive(&t, "Checked /data/repo/a.py.", &roots(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "EVIDENCED");
        assert_eq!(r["read_failures"][0]["recovered"], json!(true));
        // A failure on a path never read stays unrecovered.
        let t = write_transcript(&[ok_read("r1", "/data/repo/a.py", "/data/repo/a.py", "file"), denied("r2", "/data/repo/b.py")]);
        let r = derive(&t, "ok", &roots(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "PARTIAL");
        assert_eq!(r["read_failures"][0]["recovered"], json!(false));
    }

    #[test]
    fn directory_containing_a_read_counts_as_inspected() {
        let t = write_transcript(&[ok_read("r1", "/data/repo/sub/a.py", "/data/repo/sub/a.py", "file")]);
        let r = derive(&t, "Hashed files in /data/repo and /data/repo/sub/a.py; /data/other unseen", &roots(), "FINAL").unwrap();
        assert_eq!(r["paths_mentioned_not_read"], json!(["/data/other"]));
    }

    #[test]
    fn home_relative_mentions_kept_whole() {
        assert_eq!(mentioned_paths("OVERFLOW = \"~/example-repo/memory/x.json\" and ~~/a/b.py~~"), vec!["~/example-repo/memory/x.json", "/a/b.py"]);
    }

    #[test]
    fn directory_coverage_excludes_denied_and_refused() {
        let t = write_transcript(&[
            ok_read("r1", "/data/repo", "/data/repo", "directory"),
            denied("r2", "/data/repo/secret.txt"),
        ]);
        let r = derive(&t, "Saw /data/repo/a.py, /data/repo/.env and /data/repo/secret.txt", &roots(), "FINAL").unwrap();
        assert_eq!(r["paths_mentioned_not_read"], json!(["/data/repo/.env", "/data/repo/secret.txt"]));
    }

    #[test]
    fn directory_targets_cover_children_and_raw_paths_count() {
        let t = write_transcript(&[ok_read("r1", "/tmp/link/repo", "/private/tmp/link/repo", "directory")]);
        let r = derive(&t, "Found /tmp/link/repo/src/x.rs", &roots(), "FINAL").unwrap();
        assert_eq!(r["grounding"], "EVIDENCED", "{r}");
    }
}
