//! Build 3: the answer contract ("HERCULES answer contract v2").
//!
//! A task the bridge writes for Build 3 carries one line
//!     HERCULES_ANSWER_CONTRACT: {"example": [[key, value], ...], "example_source": ..., "for_operator": ...,
//!                                "evidence": ..., "sources": {"S1": "staged/<sha256>.snapshot", ...}}
//! With it the session gets two tools:
//!   * evidence.check {"finding": {...}}: the bridge's verdict on one finding (checker.rs), from the
//!     approved copies staged in the session sandbox; verified, contradicted, or not checkable.
//!   * answer.submit {"answer": {...}}: the answer object, checked exactly as the bridge will check it.
//!     Accepted: the session ends (FINAL) and the harness writes the final text itself, the canonical
//!     answer JSON followed by the report block built from its own receipts. Refused: the bridge's
//!     reasons, and the model fixes them (3 submits per session). After the third refused submit the
//!     session still ends with that answer, so the bridge records the rejection and its lane retry runs.
//! A final answer written as text instead (CONTROL: FINAL) goes through the same check as a submit.
//! Without the line, or when the line or the report contract cannot be honoured, the session runs
//! exactly as Build 2 does; the transcript records why (answer_contract event).

use crate::agent_loop::FinalContract;
use crate::authority::AuthorityContext;
use crate::checker::{self, AnswerContract};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const CONTRACT_PREFIX: &str = "HERCULES_ANSWER_CONTRACT:";
pub const MAX_SUBMITS: u64 = 3;
pub const MAX_CHECKS: u64 = 40;
pub const TOOL_SUBMIT: &str = "answer.submit";
pub const TOOL_CHECK: &str = "evidence.check";
/// Build 3.4: how many places where an answer object may start salvage parses in one response.
pub const SALVAGE_PARSE_ATTEMPTS: usize = 2000;
pub const REPORT_KEYS: [&str; 6] = ["source", "task", "paths_inspected", "observations", "read_failures", "repo_mutated"];
const READ_TOOLS: [&str; 4] = ["fs.read", "fs.list", "fs.stat", "cmd.run"];

#[derive(Clone, Debug)]
pub enum ContractStatus {
    Absent,
    Active(AnswerContract),
    Disabled(String),
}

impl ContractStatus {
    pub fn json(&self) -> Value {
        match self {
            ContractStatus::Absent => json!({"status": "absent"}),
            ContractStatus::Disabled(why) => json!({"status": "disabled", "reason": why}),
            ContractStatus::Active(c) => json!({
                "status": "active", "evidence": c.evidence, "for_operator": c.for_operator,
                "example_keys": c.example.as_ref().map(|e| e.iter().map(|(k, _)| k.clone()).collect::<Vec<_>>()),
                "sources": c.sources, "max_submits": MAX_SUBMITS, "max_checks": MAX_CHECKS
            }),
        }
    }
}

fn is_source_id(s: &str) -> bool {
    let b = s.as_bytes();
    (b.len() == 2 || b.len() == 3) && b[0] == b'S' && b[1..].iter().all(u8::is_ascii_digit)
}

fn is_staged_path(s: &str) -> bool {
    match s.strip_prefix("staged/").and_then(|r| r.strip_suffix(".snapshot")) {
        Some(h) => h.len() == 64 && h.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        None => false,
    }
}

/// Read the task's answer contract. Only config v2 (Build 1 and later) has one.
pub fn contract_status(task: &str, fc: &FinalContract) -> ContractStatus {
    if !crate::features::build1() {
        return ContractStatus::Absent;
    }
    contract_status_v2(task, fc)
}

fn contract_status_v2(task: &str, fc: &FinalContract) -> ContractStatus {
    let lines: Vec<&str> = task.lines().filter_map(|l| l.trim_start().strip_prefix(CONTRACT_PREFIX)).collect();
    match lines.len() {
        0 => return ContractStatus::Absent,
        1 => {}
        n => return ContractStatus::Disabled(format!("the task has {n} {CONTRACT_PREFIX} lines; exactly one is accepted")),
    }
    let v: Value = match serde_json::from_str(lines[0].trim()) {
        Ok(v) => v,
        Err(e) => return ContractStatus::Disabled(format!("the contract line is not valid JSON ({e})")),
    };
    let c = match checker::contract_from(&v) {
        Ok(c) => c,
        Err(e) => return ContractStatus::Disabled(e),
    };
    for (k, p) in &c.sources {
        if !is_source_id(k) || !is_staged_path(p) {
            return ContractStatus::Disabled(format!("source {k} -> {p} is not of the form S<n> -> staged/<sha256>.snapshot"));
        }
    }
    if c.evidence && c.sources.is_empty() {
        return ContractStatus::Disabled("an evidence contract needs its approved sources".into());
    }
    if task.lines().any(|l| l.trim().starts_with("REQUIRED_FINAL_CONTAINS:")) {
        return ContractStatus::Disabled("the task also requires literal text in the final answer (REQUIRED_FINAL_CONTAINS)".into());
    }
    if let Err(why) = report_values(fc) {
        return ContractStatus::Disabled(format!("the harness cannot write the report block: {why}"));
    }
    ContractStatus::Active(c)
}

/// The fixed values of the report block (source, task), from the supervisor's --final-block-spec.
fn report_values(fc: &FinalContract) -> Result<(String, String), String> {
    if fc.block_begin.is_none() || fc.block_end.is_none() {
        return Err("no report markers were given".into());
    }
    let mut keys: Vec<&str> = fc.block_keys.iter().map(String::as_str).collect();
    keys.sort();
    let mut want = REPORT_KEYS.to_vec();
    want.sort();
    if keys != want {
        return Err(format!("the report keys are [{}], not the six the harness writes", fc.block_keys.join(", ")));
    }
    let eq = |k: &str| -> Option<String> {
        fc.block_spec.get(k).and_then(|s| s.get("equals")).and_then(Value::as_str).map(String::from)
    };
    let source = eq("source").ok_or("the spec gives no fixed value for source")?;
    let task = eq("task").ok_or("the spec gives no fixed value for task")?;
    for (k, want) in [("paths_inspected", "array"), ("observations", "array"), ("read_failures", "array")] {
        if let Some(s) = fc.block_spec.get(k) {
            if s.as_str() != Some(want) {
                return Err(format!("the spec wants {k} as {s}"));
            }
        }
    }
    if let Some(s) = fc.block_spec.get("repo_mutated") {
        if s.get("equals") != Some(&Value::Bool(false)) && s.as_str() != Some("boolean") {
            return Err(format!("the spec wants repo_mutated as {s}"));
        }
    }
    Ok((source, task))
}

/// The system-prompt lines for the two tools (empty unless the contract is active).
pub fn guide(status: &ContractStatus) -> String {
    let ContractStatus::Active(c) = status else { return String::new() };
    if crate::features::native() {
        return guide_native(c);
    }
    let mut s = String::from("\n\nANSWER TOOLS (this task has an answer contract; they work only on your answer and the approved files):\n");
    if c.evidence {
        s.push_str(&format!(
            "- evidence.check {{\"finding\": {{...}}}}: checks ONE finding, in the task's finding format, exactly as the bridge will check it against the approved files. It returns \"verified\", \"contradicted\" (with what the file actually says: fix the finding) or \"not checkable\" (the bridge cannot prove it in this format; it may still be submitted and goes to the review marked NOT verified). Up to {MAX_CHECKS} checks per session. Check each finding before you submit.\n"
        ));
    }
    s.push_str(&format!(
        "- answer.submit {{\"answer\": {{...}}}}: hands in your answer object, the JSON object the task asks for. The harness checks it as the bridge will. If it is accepted the session ends there and the harness writes the final text and the report block itself. If not, you get the bridge's reasons: fix them and submit again ({MAX_SUBMITS} submits in all; after the last one the session ends with that answer).\n\
Deliver your answer with answer.submit instead of writing the answer JSON and the report block as text. Put the whole TOOL_REQUEST on one line. evidence.check calls may share a response with read calls (up to 4 calls in all); answer.submit always goes in a response of its own.\n\
Example: TOOL_REQUEST: {{\"tool\":\"answer.submit\",\"args\":{{\"answer\":{{\"summary\":\"...\",\"findings\":[...]}}}},\"request_id\":\"submit-1\"}}"
    ));
    s
}

/// Build 3.6: the answer tools' guide for native tool calling (no TOOL_REQUEST wording).
fn guide_native(c: &AnswerContract) -> String {
    let mut s = String::from("\n\nANSWER TOOLS (this task has an answer contract; they work only on your answer and the approved files):\n");
    if c.evidence {
        s.push_str(&format!(
            "- evidence_check {{\"finding\": {{...}}}}: checks ONE finding, in the task's finding format, exactly as the bridge will check it against the approved files. It returns \"verified\", \"contradicted\" (with what the file actually says: fix the finding) or \"not checkable\" (the bridge cannot prove it in this format; it may still be submitted and goes to the review marked NOT verified). Up to {MAX_CHECKS} checks per session. Check each finding before you submit.\n"
        ));
    }
    s.push_str(&format!(
        "- answer_submit {{\"answer\": {{...}}}}: hands in your answer object, the JSON object the task asks for. The harness checks it as the bridge will. If it is accepted the session ends there and the harness writes the final text and the report block itself. If not, you get the bridge's reasons: fix them and submit again ({MAX_SUBMITS} submits in all; after the last one the session ends with that answer).\n\
Deliver your answer with answer_submit instead of writing the answer JSON and the report block as text. evidence_check calls may share a response with read calls (up to 4 calls in all); answer_submit always goes in a response of its own."
    ));
    s
}

/// Build 3.6: a tool name that means answer.submit for the salvage only: answer.submit, answer_submit, or either
/// after a `__` or `.` prefix (Arena T08 r3, Oct 9: `mcp__hercules_native__answer_submit`). Never used to dispatch.
pub fn salvage_names_submit(name: &str) -> bool {
    if name == TOOL_SUBMIT || name == "answer_submit" {
        return true;
    }
    ["__answer_submit", ".answer_submit", "__answer.submit", ".answer.submit"].iter().any(|s| name.ends_with(s))
}

/// Build 3.6 (salvage only): the answers in `{"name": <answer.submit under any prefix>, "arguments": {..}}` objects
/// anywhere in a response (bounded: the first 64 places a `{"name"` starts). The arguments may be an object or its
/// JSON text; the answer is arguments.answer, else the arguments less a request_id.
fn native_markup_answers(content: &str) -> Vec<(Value, &'static str)> {
    let mut out = Vec::new();
    let mut from = 0;
    for _ in 0..64 {
        let Some(off) = content[from..].find("{\"name\"") else { break };
        let start = from + off;
        from = start + 1;
        let mut it = serde_json::Deserializer::from_str(&content[start..]).into_iter::<Value>();
        let Some(Ok(v)) = it.next() else { continue };
        if !v["name"].as_str().map(salvage_names_submit).unwrap_or(false) {
            continue;
        }
        let args = match &v["arguments"] {
            Value::String(s) => match serde_json::from_str::<Value>(s) {
                Ok(a) => a,
                Err(_) => continue,
            },
            a => a.clone(),
        };
        let Some(obj) = args.as_object() else { continue };
        let answer = match obj.get("answer") {
            Some(a) => a.clone(),
            None => {
                let mut o = obj.clone();
                o.remove("request_id");
                Value::Object(o)
            }
        };
        if answer.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
            out.push((answer, "an answer.submit call in native markup"));
        }
    }
    out
}

/// Build 3.6 (salvage only): the arguments object in a native call's raw arguments text: as it is, or with up to
/// MAX_BRACE_REPAIR closing braces too many removed or (when `allow_add`) missing ones added at the end, as the
/// 3.5 salvage repairs a text call. Checked by the contract afterwards; never used to dispatch.
fn raw_args_object(raw: &str, allow_add: bool) -> Option<Value> {
    if let Ok(v) = serde_json::from_str::<Value>(raw) {
        return v.is_object().then_some(v);
    }
    let mut it = serde_json::Deserializer::from_str(raw).into_iter::<Value>();
    if let Some(Ok(v)) = it.next() {
        let rest: Vec<char> = raw[it.byte_offset()..].chars().filter(|c| !c.is_whitespace()).collect();
        if (1..=crate::tools::MAX_BRACE_REPAIR).contains(&rest.len()) && rest.iter().all(|&c| c == '}') && v.is_object() {
            return Some(v);
        }
        return None;
    }
    if !allow_add {
        return None;
    }
    (1..=crate::tools::MAX_BRACE_REPAIR)
        .find_map(|n| serde_json::from_str::<Value>(&format!("{}{}", raw.trim_end(), "}".repeat(n))).ok())
        .filter(Value::is_object)
}

pub enum Submit {
    Accepted { final_text: String },
    Refused { problems: Vec<String>, attempts_left: u64 },
    Exhausted { final_text: String, problems: Vec<String> },
}

pub struct AnswerState {
    pub contract: AnswerContract,
    fc: FinalContract,
    texts: Option<Result<BTreeMap<String, String>, String>>,
    pub checks_used: u64,
    pub submits_used: u64,
    inspected: Vec<String>,
    failures: Vec<String>,
    /// Said with the last submit's result (e.g. findings not checked because a copy was unreadable).
    pub last_note: Option<String>,
}

impl AnswerState {
    pub fn new(contract: AnswerContract, fc: FinalContract, checks_used: u64, submits_used: u64) -> AnswerState {
        AnswerState { contract, fc, texts: None, checks_used, submits_used, inspected: Vec::new(), failures: Vec::new(), last_note: None }
    }

    /// The approved copies, read once from the sandbox; each must hash to the name it is staged under.
    fn texts(&mut self, auth: &AuthorityContext) -> Result<BTreeMap<String, String>, String> {
        if self.texts.is_none() {
            let mut out = BTreeMap::new();
            let mut err = None;
            for (sid, rel) in &self.contract.sources {
                match crate::readers::read_bytes(auth, rel) {
                    Ok((_, bytes)) => {
                        let want = &rel["staged/".len()..rel.len() - ".snapshot".len()];
                        if crate::audit::sha256_bytes(&bytes) != want {
                            err = Some(format!("the staged copy of {sid} does not match its SHA-256"));
                            break;
                        }
                        out.insert(sid.clone(), String::from_utf8_lossy(&bytes).into_owned());
                    }
                    Err(e) => {
                        err = Some(format!("the staged copy of {sid} could not be read: {} {}", e.code, e.detail));
                        break;
                    }
                }
            }
            self.texts = Some(match err {
                Some(e) => Err(e),
                None => Ok(out),
            });
        }
        self.texts.clone().unwrap()
    }

    /// Note a read receipt for the report block (paths read, read failures).
    pub fn record_receipt(&mut self, receipt: &Value) {
        let tool = receipt["tool"].as_str().unwrap_or("");
        if !READ_TOOLS.contains(&tool) {
            return;
        }
        let mut paths: Vec<String> = Vec::new();
        if let Some(p) = receipt["args"]["path"].as_str() {
            paths.push(p.to_string());
        } else {
            for t in receipt["targets"].as_array().cloned().unwrap_or_default() {
                if let Some(p) = t["path"].as_str() {
                    paths.push(p.to_string());
                }
            }
        }
        if receipt["status"] == "ok" {
            for p in paths {
                if !self.inspected.contains(&p) {
                    self.inspected.push(p);
                }
            }
        } else {
            let code = receipt["code"].as_str().unwrap_or(receipt["status"].as_str().unwrap_or("failed"));
            let what = if paths.is_empty() { tool.to_string() } else { paths.join(", ") };
            self.failures.push(format!("{what}: {code}"));
        }
    }

    /// evidence.check. Err = rejected (code, detail).
    pub fn check(&mut self, args: &Value, auth: &AuthorityContext) -> Result<Value, (String, String)> {
        if !self.contract.evidence {
            return Err(("EVIDENCE_CHECK_UNAVAILABLE".into(), "this task's findings are not checked against the files; answer with answer.submit".into()));
        }
        if self.checks_used >= MAX_CHECKS {
            return Err(("EVIDENCE_CHECK_LIMIT".into(), format!("all {MAX_CHECKS} checks of this session are used; submit your answer with answer.submit")));
        }
        let texts = self.texts(auth).map_err(|e| ("APPROVED_COPY_UNAVAILABLE".to_string(), e))?;
        self.checks_used += 1;
        let v = checker::check_one(&args["finding"], &texts);
        Ok(json!({"verdict": v.verdict, "detail": v.detail, "checks_left": MAX_CHECKS - self.checks_used}))
    }

    /// answer.submit, or a final answer written as text (`implicit`). Err = rejected (code, detail).
    pub fn submit(&mut self, answer: Value, auth: &AuthorityContext) -> Result<Submit, (String, String)> {
        if self.submits_used >= MAX_SUBMITS {
            return Err(("ANSWER_SUBMIT_LIMIT".into(), "all submits of this session are used".into()));
        }
        self.submits_used += 1;
        let mut answer = answer;
        let mut contract = self.contract.clone();
        let mut note = None;
        let texts = if contract.evidence {
            match self.texts(auth) {
                Ok(t) => t,
                Err(e) => {
                    contract.evidence = false;
                    note = Some(format!("findings not checked: {e}"));
                    BTreeMap::new()
                }
            }
        } else {
            BTreeMap::new()
        };
        let problems = checker::submit_problems(&mut answer, &contract, &texts);
        // The bridge checks findings against its own copies; when the session's could not be read the
        // answer is not blocked on them, and the result says so.
        self.last_note = note;
        if problems.is_empty() {
            return Ok(Submit::Accepted { final_text: self.render_final(&answer) });
        }
        let left = MAX_SUBMITS - self.submits_used;
        if left == 0 {
            return Ok(Submit::Exhausted { final_text: self.render_final(&answer), problems });
        }
        Ok(Submit::Refused { problems, attempts_left: left })
    }

    /// Build 3.4: every reason the bridge would refuse this answer, as answer.submit checks it, without using a
    /// submit (a stopped session's salvaged answer is checked this way). The answer is normalized as a submit
    /// normalizes it.
    /// Also returns the note answer.submit would give with it (findings not checked because an approved copy
    /// could not be read).
    pub fn problems_of(&mut self, answer: &mut Value, auth: &AuthorityContext) -> (Vec<String>, Option<String>) {
        let mut contract = self.contract.clone();
        let mut note = None;
        let texts = if contract.evidence {
            match self.texts(auth) {
                Ok(t) => t,
                Err(e) => {
                    contract.evidence = false;
                    note = Some(format!("findings not checked: {e}"));
                    BTreeMap::new()
                }
            }
        } else {
            BTreeMap::new()
        };
        (checker::submit_problems(answer, &contract, &texts), note)
    }

    /// Build 3.4: the answer objects in one assistant response: the object written as text (the bridge's pick),
    /// then the answer inside each answer.submit call in it, run or not (refused, cut off from its envelope's
    /// request_id, closed). Only JSON objects; a call whose JSON does not parse gives nothing.
    /// Build 3.5: a call is read with its closing braces repaired (`tools::repair_braces`; braces are added only
    /// when `allow_add`, never for a response cut at the output limit).
    pub fn answers_in_response(&self, content: &str, allow_add: bool) -> Vec<(Value, &'static str)> {
        let mut out = Vec::new();
        // Bounded: a stopped session's every response is read, and a response full of "{" must not cost seconds.
        let text = self.answer_in_text_limited(content, SALVAGE_PARSE_ATTEMPTS);
        if text.is_object() {
            out.push((text, "an answer object written as text"));
        }
        let add = if allow_add { crate::tools::BraceAdd::ForSalvage } else { crate::tools::BraceAdd::Never };
        for (raw, _) in crate::tools::extract_requests_repaired(content, add) {
            let Ok(v) = serde_json::from_str::<Value>(&raw) else { continue };
            // Build 3.6: also a submit under a prefixed name (native markup; salvage only).
            if !v["tool"].as_str().map(salvage_names_submit).unwrap_or(false) {
                continue;
            }
            // Build 3.6: a native call whose arguments were not JSON is stored with the raw text as "args"; the
            // salvage reads it with the same brace repair as a text call.
            let parsed_raw: Option<Value> = match &v["args"] {
                Value::String(s) => raw_args_object(s, allow_add),
                _ => None,
            };
            let Some(args) = parsed_raw.as_ref().or(Some(&v["args"])).and_then(Value::as_object) else { continue };
            let answer = if let Some(a) = args.get("answer") {
                a.clone()
            } else {
                // The answer's keys straight in args (validate takes them as the answer), less a nested request_id.
                let mut o = args.clone();
                if o.get("request_id").map(Value::is_string).unwrap_or(false) {
                    o.remove("request_id");
                }
                Value::Object(o)
            };
            if answer.as_object().map(|o| !o.is_empty()).unwrap_or(false) {
                out.push((answer, "an answer.submit call that was not accepted"));
            }
        }
        // Build 3.6 (Arena T08 r3, Oct 9): an answer inside native markup that the call reader does not take as a call
        // (`<tool_call>\n[Tool Call]\n\n{"name": "mcp__hercules_native__answer_submit", "arguments": {"answer": {..}}}`).
        // Salvage only: a JSON object with a "name" that means answer.submit and its "arguments".
        for (answer, kind) in native_markup_answers(content) {
            if !out.iter().any(|(a, _)| *a == answer) {
                out.push((answer, kind));
            }
        }
        out
    }

    /// The final text the harness writes: the answer JSON, then the report block from its receipts.
    pub fn render_final(&self, answer: &Value) -> String {
        let (source, task) = report_values(&self.fc).unwrap_or_default();
        let observations: Vec<String> = match answer.get("findings") {
            Some(Value::Array(fs)) if !fs.is_empty() => fs
                .iter()
                .map(|f| match f.get("claim") {
                    Some(Value::String(c)) => checker::short(c, 200),
                    _ => checker::short(&crate::py::str_of(f), 200),
                })
                .collect(),
            _ => match answer.get("summary") {
                Some(Value::String(s)) if !s.trim().is_empty() => vec![checker::short(s, 200)],
                _ => vec![],
            },
        };
        let block = json!({
            "source": source, "task": task, "paths_inspected": self.inspected,
            "observations": observations, "read_failures": self.failures, "repo_mutated": false
        });
        let body = serde_json::to_string_pretty(answer).unwrap_or_else(|_| answer.to_string());
        format!(
            "{body}\n\n<<<{}>>>\n{}\n<<<{}>>>",
            self.fc.block_begin.as_deref().unwrap_or(""),
            serde_json::to_string_pretty(&block).unwrap(),
            self.fc.block_end.as_deref().unwrap_or("")
        )
    }

    /// The answer object in a final answer written as text: the last JSON object with the answer's
    /// keys that is not report-shaped (the bridge's pick_answer), before the report block.
    pub fn answer_in_text(&self, text: &str) -> Value {
        self.answer_in_text_limited(text, usize::MAX)
    }

    /// `answer_in_text`, trying at most `attempts` places where an object may start (Build 3.4). A "{" that is not
    /// followed (after JSON whitespace) by '"' or '}' cannot start an object and is skipped without parsing, and
    /// a plain parse is tried before the one that escapes raw control characters; both give the same objects as
    /// before.
    pub fn answer_in_text_limited(&self, text: &str, attempts: usize) -> Value {
        let begin = self.fc.block_begin.as_deref().unwrap_or("\u{0}");
        let cut = text.lines().map(|l| l.len() + 1).scan(0usize, |acc, n| {
            let start = *acc;
            *acc += n;
            Some(start)
        });
        let starts: Vec<usize> = cut.collect();
        let lines: Vec<&str> = text.lines().collect();
        let body = match lines.iter().rposition(|l| l.contains(begin)) {
            Some(i) => &text[..starts[i].min(text.len())],
            None => text,
        };
        let want: Vec<String> = match &self.contract.example {
            Some(ex) => ex.iter().map(|(k, _)| k.clone()).collect(),
            None => vec!["summary".into(), "findings".into()],
        };
        let mut found = Value::Null;
        let mut i = 0;
        let mut tried = 0usize;
        while let Some(off) = body[i..].find('{') {
            let j = i + off;
            let opens = body[j + 1..].trim_start_matches([' ', '\t', '\n', '\r']).starts_with(['"', '}']);
            if !opens {
                i = j + 1;
                if i >= body.len() {
                    break;
                }
                continue;
            }
            tried += 1;
            if tried > attempts {
                break;
            }
            // A plain parse first; only when it fails, the parse that escapes raw control characters in strings.
            let mut plain = serde_json::Deserializer::from_str(&body[j..]).into_iter::<Value>();
            let parsed: Option<(Value, usize)> = match plain.next() {
                Some(Ok(v)) => Some((v, plain.byte_offset())),
                _ => {
                    let slice = escape_raw_controls(&body[j..]);
                    let mut it = serde_json::Deserializer::from_str(&slice).into_iter::<Value>();
                    match it.next() {
                        // Advance past the object in the original text (escaping only grows the slice,
                        // and only inside strings, so the end is found by re-parsing the original).
                        Some(Ok(v)) => Some((v, original_end(&body[j..], it.byte_offset(), &slice))),
                        _ => None,
                    }
                }
            };
            match parsed {
                Some((v, orig_end)) => {
                    if let Value::Object(o) = &v {
                        let report_shaped = o.keys().all(|k| REPORT_KEYS.contains(&k.as_str()));
                        if !report_shaped && o.keys().any(|k| want.contains(k)) {
                            found = v.clone();
                        }
                    }
                    i = j + orig_end.max(1);
                }
                None => i = j + 1,
            }
            if i >= body.len() {
                break;
            }
        }
        found
    }
}

/// Inside JSON strings, raw control characters become escapes (Python's json.loads(strict=False)
/// accepts them; serde_json does not). Text outside strings is unchanged.
fn escape_raw_controls(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_str = false;
    let mut esc = false;
    for c in s.chars() {
        if in_str {
            if esc {
                esc = false;
                out.push(c);
                continue;
            }
            match c {
                '\\' => {
                    esc = true;
                    out.push(c);
                }
                '"' => {
                    in_str = false;
                    out.push(c);
                }
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        } else {
            if c == '"' {
                in_str = true;
            }
            out.push(c);
        }
    }
    out
}

/// Map a byte offset in the escaped slice back to the original text.
fn original_end(orig: &str, escaped_end: usize, escaped: &str) -> usize {
    if escaped.len() == orig.len() {
        return escaped_end;
    }
    let mut oi = 0;
    let mut ei = 0;
    let mut in_str = false;
    let mut esc = false;
    for c in orig.chars() {
        if ei >= escaped_end {
            break;
        }
        let grown = if in_str && !esc && (c as u32) < 0x20 { 6 } else { c.len_utf8() };
        if in_str {
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if c == '"' {
            in_str = true;
        }
        oi += c.len_utf8();
        ei += grown;
    }
    oi
}

/// Is this response a single answer.submit request (allowed even after tools close)?
pub fn is_submit_request(content: &str) -> bool {
    let reqs = crate::tools::extract_requests(content);
    reqs.len() == 1 && names_submit(&reqs[0])
}

/// Build 3.5: a call is an answer.submit when it parses (closing braces repaired) with that tool name, or, when
/// its JSON broke further on (inside the answer), when it begins with {"tool":"answer.submit". Arena T14 r1
/// (Oct 9): a submit with one brace wrong was taken for a closed tool request, and the model was told that
/// answer.submit was still open instead of where its JSON broke; it sent the same broken submit again.
pub fn names_submit(raw: &str) -> bool {
    let fixed = crate::tools::repair_braces(raw, crate::tools::BraceAdd::ForSalvage).map(|(f, _)| f).unwrap_or_else(|| raw.to_string());
    if let Ok(v) = serde_json::from_str::<Value>(&fixed) {
        return v["tool"].as_str() == Some(TOOL_SUBMIT);
    }
    let head: String = raw.chars().filter(|c| !c.is_whitespace()).take(40).collect();
    head.starts_with(&format!("{{\"tool\":\"{TOOL_SUBMIT}\","))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fc() -> FinalContract {
        let spec: serde_json::Map<String, Value> = serde_json::from_value(json!({
            "source": {"equals": "host-driver"}, "task": {"equals": "CORR-1.txt"}, "paths_inspected": "array",
            "observations": "array", "read_failures": "array", "repo_mutated": {"equals": false}})).unwrap();
        FinalContract {
            block_begin: Some("REPORT_BEGIN:ab12".into()),
            block_end: Some("REPORT_END:ab12".into()),
            block_keys: spec.keys().cloned().collect(),
            block_spec: spec,
        }
    }

    #[test]
    fn a_broken_submit_is_still_a_submit() {
        crate::features::set_build1(true);
        let good = r#"TOOL_REQUEST: {"tool":"answer.submit","args":{"answer":{"summary":"s"}},"request_id":"s1"}"#;
        assert!(is_submit_request(good));
        assert!(is_submit_request(&format!("{good}}}"))); // one } too many
        assert!(is_submit_request(r#"TOOL_REQUEST: {"tool":"answer.submit","args":{"answer":{"summary":"s"},"request_id":"s1"}"#)); // one short
        // broken inside the answer: still a submit, so it is validated (BAD_JSON, with where) and not closed
        assert!(is_submit_request(r#"TOOL_REQUEST: { "tool" : "answer.submit", "args":{"answer":{"findings":[{"a":1}}},{"b":2}]}},"request_id":"s1"}"#));
        assert!(!is_submit_request(r#"TOOL_REQUEST: {"tool":"answer.submitted","args":{"answer":{"x":1}}}}}"#));
        assert!(!is_submit_request(r#"TOOL_REQUEST: {"tool":"fs.read","args":{"path":"answer.submit"},"request_id":"r1"}"#));
        assert!(!is_submit_request(r#"TOOL_REQUEST: {"args":{"tool":"answer.submit"}"#));
    }

    #[test]
    fn contract_line_rules() {
        let line = r#"HERCULES_ANSWER_CONTRACT: {"example": [["summary", ""], ["findings", []]], "evidence": true, "sources": {"S1": "staged/0000000000000000000000000000000000000000000000000000000000000000.snapshot"}}"#;
        assert!(matches!(contract_status_v2(&format!("task\n    {line}\n"), &fc()), ContractStatus::Active(_)));
        assert!(matches!(contract_status_v2("task", &fc()), ContractStatus::Absent));
        assert!(matches!(contract_status_v2(&format!("{line}\n{line}"), &fc()), ContractStatus::Disabled(_)));
        assert!(matches!(contract_status_v2(&line.replace("staged/0", "../0"), &fc()), ContractStatus::Disabled(_)));
        assert!(matches!(contract_status_v2(line, &FinalContract::default()), ContractStatus::Disabled(_)));
        assert!(matches!(contract_status_v2(&format!("{line}\nREQUIRED_FINAL_CONTAINS: X"), &fc()), ContractStatus::Disabled(_)));
    }

    #[test]
    fn final_text_meets_the_report_contract_and_parses_back() {
        let c = AnswerContract { example: None, ..Default::default() };
        let mut st = AnswerState::new(c, fc(), 0, 0);
        st.record_receipt(&json!({"tool": "fs.read", "args": {"path": "staged/x.snapshot"}, "status": "ok", "targets": []}));
        st.record_receipt(&json!({"tool": "cmd.run", "args": {"argv": ["grep"]}, "status": "rejected", "code": "CMD_POLICY", "targets": []}));
        let answer = json!({"summary": "Two roles.\nSecond line", "findings": [{"claim": "a", "evidence": "x\ny", "source": "S1"}]});
        let text = st.render_final(&answer);
        assert_eq!(crate::agent_loop::block_problem_pub(&text, &fc()), None, "{text}");
        assert_eq!(st.answer_in_text(&text), answer);
        assert!(text.contains("\"staged/x.snapshot\"") && text.contains("grep: CMD_POLICY") == false && text.contains("cmd.run: CMD_POLICY"));
    }

    #[test]
    fn answer_in_text_takes_the_last_answer_and_skips_report_copies() {
        let st = AnswerState::new(AnswerContract::default(), fc(), 0, 0);
        let t = "Here {\"summary\": \"old\"} then\n{\"summary\": \"new\", \"findings\": [\"raw\nnewline\"]}\n{\"source\": \"host-driver\", \"task\": \"t\", \"paths_inspected\": [], \"observations\": [], \"read_failures\": [], \"repo_mutated\": false}\n<<<REPORT_BEGIN:ab12>>>\n{\"summary\": \"in block\"}\n<<<REPORT_END:ab12>>>";
        assert_eq!(st.answer_in_text(t), json!({"summary": "new", "findings": ["raw\nnewline"]}));
        assert_eq!(st.answer_in_text("no json"), Value::Null);
    }
}
