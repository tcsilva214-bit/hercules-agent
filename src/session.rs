//! Gate 07 durable session, checkpoint, context-budget, and crash-recovery engine.
//! A request that reached EXECUTION_STARTED is never blindly replayed after restart.

use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SESSION_SCHEMA_VERSION: u64 = 2;

#[derive(Clone, Debug)]
pub struct LoopSnapshot {
    pub messages: Vec<(String, String)>,
    pub consumed_ids: HashSet<String>,
    pub turn: u64,
    pub consecutive_unsupported: u64,
    pub consecutive_malformed: u64,
    pub consecutive_tool_rejections: u64,
    pub unsupported_total: u64,
    pub malformed_total: u64,
    pub tools_dispatched_total: u64,
    pub tool_rejections_total: u64,
    pub real_capability_executions: u64,
    pub final_content: String,
}

#[derive(Debug)]
pub struct SessionRuntime {
    root: Option<PathBuf>,
    state: Value,
    resumed: bool,
    recovery_notes: Vec<String>,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 96
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
}

fn generated_id() -> String {
    format!("nah-session-{}-{}", now_ms(), std::process::id())
}

fn fnv1a64(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

pub fn file_digest(path: &str) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|e| format!("configuration digest read failed {path}: {e}"))?;
    Ok(format!("fnv1a64:{}", fnv1a64(&bytes)))
}

fn counter(v: &Value, key: &str) -> u64 {
    v.get("counters")
        .and_then(|c| c.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

impl SessionRuntime {
    #[allow(clippy::too_many_arguments)]
    pub fn fresh(
        base_dir: Option<&str>,
        requested_id: Option<&str>,
        model: &str,
        task: &str,
        context_budget_bytes: u64,
        candidate_version: &str,
        config_digest: &str,
        max_iterations: u64,
    ) -> Result<Self, String> {
        if context_budget_bytes < 256 {
            return Err("context budget must be >=256 bytes".into());
        }

        let id = requested_id
            .map(ToString::to_string)
            .unwrap_or_else(generated_id);
        if !valid_id(&id) {
            return Err(format!("invalid session id: {id}"));
        }

        let root = match base_dir {
            None => None,
            Some(base) => {
                let p = Path::new(base).join(&id);
                fs::create_dir_all(&p)
                    .map_err(|e| format!("session directory create failed {}: {e}", p.display()))?;
                if p.join("checkpoint.json").exists() {
                    return Err(format!(
                        "checkpoint already exists for fresh session: {}",
                        p.display()
                    ));
                }
                Some(p)
            }
        };

        let created_ms = now_ms();
        let state = json!({
            "schema_version": SESSION_SCHEMA_VERSION,
            "session_id": id,
            "immutable_creation": {
                "created_ms": created_ms,
                "candidate_version": candidate_version,
                "config_digest": config_digest,
                "initial_model": model,
                "initial_task": task
            },
            "mission": {
                "id": id,
                "class": "UNSPECIFIED_V1"
            },
            "model": model,
            "task": task,
            "context_budget": {"unit": "utf8_bytes", "hard_limit": context_budget_bytes},
            "context_policy": {
                "compaction_mode": if crate::features::build1() { "elide_old_tool_results_v2" } else { "disabled_fail_closed_v1" },
                "compaction_events": [],
                "critical_context_preservation": "system_and_authority_context_never_evicted"
            },
            "messages": [],
            "turn_models": [],
            "consumed_request_ids": [],
            "actions": {},
            "turn": 0,
            "limits": {
                "initial_max_iterations": max_iterations,
                "resume_max_iterations_history": []
            },
            "counters": {
                "consecutive_unsupported": 0,
                "consecutive_malformed": 0,
                "consecutive_tool_rejections": 0,
                "unsupported_total": 0,
                "malformed_total": 0,
                "tools_dispatched_total": 0,
                "tool_rejections_total": 0,
                "real_capability_executions": 0
            },
            "termination": {
                "stop_reason": null,
                "cancelled": false,
                "timeout": false,
                "error": null
            },
            "final_content": "",
            "stop_reason": null,
            "terminal": false,
            "resume_epoch": 0,
            "resume_history": [],
            "checkpoint_seq": 0,
            "created_ms": created_ms,
            "updated_ms": created_ms
        });

        let mut s = SessionRuntime {
            root,
            state,
            resumed: false,
            recovery_notes: Vec::new(),
        };
        s.persist()?;
        Ok(s)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn resume(
        base_dir: &str,
        id: &str,
        model: &str,
        task: &str,
        candidate_version: &str,
        config_digest: &str,
        max_iterations: u64,
    ) -> Result<Self, String> {
        if !valid_id(id) {
            return Err(format!("invalid session id: {id}"));
        }
        let root = Path::new(base_dir).join(id);
        let checkpoint = root.join("checkpoint.json");
        let raw = fs::read_to_string(&checkpoint)
            .map_err(|e| format!("checkpoint read failed {}: {e}", checkpoint.display()))?;
        let env: Value = serde_json::from_str(&raw)
            .map_err(|e| format!("checkpoint envelope malformed: {e}"))?;

        let checksum = env
            .get("checksum_fnv1a64")
            .and_then(Value::as_str)
            .ok_or_else(|| "checkpoint checksum missing".to_string())?;
        let payload = env
            .get("payload_json")
            .and_then(Value::as_str)
            .ok_or_else(|| "checkpoint payload missing".to_string())?;

        let actual = fnv1a64(payload.as_bytes());
        if actual != checksum {
            return Err(format!(
                "checkpoint checksum mismatch expected={checksum} actual={actual}"
            ));
        }

        let mut state: Value = serde_json::from_str(payload)
            .map_err(|e| format!("checkpoint payload malformed: {e}"))?;

        if state.get("schema_version").and_then(Value::as_u64) != Some(SESSION_SCHEMA_VERSION) {
            return Err("checkpoint schema unsupported".into());
        }
        if state.get("session_id").and_then(Value::as_str) != Some(id) {
            return Err("checkpoint session_id mismatch".into());
        }
        if state.get("model").and_then(Value::as_str) != Some(model) {
            return Err("checkpoint model mismatch".into());
        }
        if state.get("task").and_then(Value::as_str) != Some(task) {
            return Err("checkpoint task mismatch".into());
        }
        let immutable = state
            .get("immutable_creation")
            .and_then(Value::as_object)
            .ok_or_else(|| "checkpoint immutable_creation malformed".to_string())?;
        if immutable.get("candidate_version").and_then(Value::as_str) != Some(candidate_version) {
            return Err("checkpoint candidate version mismatch".into());
        }
        if immutable.get("config_digest").and_then(Value::as_str) != Some(config_digest) {
            return Err("checkpoint configuration digest mismatch".into());
        }
        if state.get("terminal").and_then(Value::as_bool) == Some(true) {
            return Err("terminal session cannot be resumed".into());
        }

        let resume_epoch = state
            .get("resume_epoch")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_add(1);
        state["resume_epoch"] = json!(resume_epoch);
        let resume_history = state
            .get_mut("resume_history")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "resume_history malformed".to_string())?;
        resume_history.push(json!({
            "epoch": resume_epoch,
            "resumed_ms": now_ms(),
            "candidate_version": candidate_version,
            "config_digest": config_digest,
            "model": model,
            "max_iterations": max_iterations
        }));
        let limit_history = state
            .get_mut("limits")
            .and_then(|v| v.get_mut("resume_max_iterations_history"))
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "resume limit history malformed".to_string())?;
        limit_history.push(json!({
            "epoch": resume_epoch,
            "max_iterations": max_iterations
        }));

        let mut recovery_notes = Vec::new();
        if let Some(actions) = state.get_mut("actions").and_then(Value::as_object_mut) {
            for (rid, rec) in actions.iter_mut() {
                let phase = rec.get("phase").and_then(Value::as_str).unwrap_or("");
                let tool = rec
                    .get("tool")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string();
                match phase {
                    "EXECUTION_STARTED" => {
                        rec["phase"] = json!("OUTCOME_UNKNOWN");
                        rec["recovered_ms"] = json!(now_ms());
                        recovery_notes.push(format!(
                            "[RECOVERY_OBSERVATION] OUTCOME_UNKNOWN request_id={rid} tool={tool}; execution may have started before interruption; request_id remains consumed and the action was NOT replayed."
                        ));
                    }
                    "REQUEST_CREATED" | "VALIDATED" | "AUTHORIZED" => {
                        rec["phase"] = json!("EXECUTION_FAILED");
                        rec["result"] = json!({
                            "status": "recovery_aborted_pre_execution",
                            "code": "RECOVERY_ABORTED_PRE_EXECUTION"
                        });
                        rec["recovered_ms"] = json!(now_ms());
                        recovery_notes.push(format!(
                            "[RECOVERY_OBSERVATION] RECOVERY_ABORTED_PRE_EXECUTION request_id={rid} tool={tool}; no replay was attempted and request_id remains consumed."
                        ));
                    }
                    _ => {}
                }
            }
        }

        if !recovery_notes.is_empty() {
            let msgs = state
                .get_mut("messages")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| "checkpoint messages malformed".to_string())?;
            for note in &recovery_notes {
                msgs.push(json!({"role":"user","content":note}));
            }
        }

        let mut s = SessionRuntime {
            root: Some(root),
            state,
            resumed: true,
            recovery_notes,
        };
        s.persist()?;
        Ok(s)
    }

    pub fn initialize_messages(&mut self, system_prompt: &str) -> Result<(), String> {
        let empty = self
            .state
            .get("messages")
            .and_then(Value::as_array)
            .map(|a| a.is_empty())
            .ok_or_else(|| "session messages malformed".to_string())?;

        if empty {
            let task = self
                .state
                .get("task")
                .and_then(Value::as_str)
                .ok_or_else(|| "session task missing".to_string())?
                .to_string();
            self.state["messages"] = json!([
                {"role":"system","content":system_prompt},
                {"role":"user","content":task}
            ]);
            self.persist()?;
        } else {
            // Build 1: the system prompt carries the granted roots and tool guide, so a
            // resume with a different grant (or binary prompt) is refused, never mixed.
            let stored = self
                .state
                .get("messages")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|m| m.get("content"))
                .and_then(Value::as_str)
                .unwrap_or("");
            if stored != system_prompt {
                return Err("system prompt differs from the checkpoint (granted roots, enabled commands or binary changed); start a new session".into());
            }
        }
        Ok(())
    }

    pub fn snapshot(&self) -> Result<LoopSnapshot, String> {
        Ok(LoopSnapshot {
            messages: self.messages()?,
            consumed_ids: self.consumed_ids()?,
            turn: self.state.get("turn").and_then(Value::as_u64).unwrap_or(0),
            consecutive_unsupported: counter(&self.state, "consecutive_unsupported"),
            consecutive_malformed: counter(&self.state, "consecutive_malformed"),
            consecutive_tool_rejections: counter(&self.state, "consecutive_tool_rejections"),
            unsupported_total: counter(&self.state, "unsupported_total"),
            malformed_total: counter(&self.state, "malformed_total"),
            tools_dispatched_total: counter(&self.state, "tools_dispatched_total"),
            tool_rejections_total: counter(&self.state, "tool_rejections_total"),
            real_capability_executions: counter(&self.state, "real_capability_executions"),
            final_content: self
                .state
                .get("final_content")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
        })
    }

    fn messages(&self) -> Result<Vec<(String, String)>, String> {
        let arr = self
            .state
            .get("messages")
            .and_then(Value::as_array)
            .ok_or_else(|| "session messages malformed".to_string())?;
        let mut out = Vec::with_capacity(arr.len());
        for m in arr {
            let role = m
                .get("role")
                .and_then(Value::as_str)
                .ok_or_else(|| "message role malformed".to_string())?;
            let content = m
                .get("content")
                .and_then(Value::as_str)
                .ok_or_else(|| "message content malformed".to_string())?;
            out.push((role.to_string(), content.to_string()));
        }
        Ok(out)
    }

    fn consumed_ids(&self) -> Result<HashSet<String>, String> {
        let arr = self
            .state
            .get("consumed_request_ids")
            .and_then(Value::as_array)
            .ok_or_else(|| "consumed_request_ids malformed".to_string())?;
        let mut out = HashSet::new();
        for v in arr {
            let s = v
                .as_str()
                .ok_or_else(|| "consumed request id malformed".to_string())?;
            out.insert(s.to_string());
        }
        Ok(out)
    }

    fn store_consumed(&mut self, ids: &HashSet<String>) {
        let mut v: Vec<String> = ids.iter().cloned().collect();
        v.sort();
        self.state["consumed_request_ids"] = json!(v);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sync_loop(
        &mut self,
        messages: &[(String, String)],
        consumed: &HashSet<String>,
        turn: u64,
        consecutive_unsupported: u64,
        consecutive_malformed: u64,
        consecutive_tool_rejections: u64,
        unsupported_total: u64,
        malformed_total: u64,
        tools_dispatched_total: u64,
        tool_rejections_total: u64,
        real_capability_executions: u64,
        final_content: &str,
    ) -> Result<(), String> {
        self.state["messages"] = json!(messages
            .iter()
            .map(|(r, c)| json!({"role":r,"content":c}))
            .collect::<Vec<_>>());
        self.store_consumed(consumed);
        self.state["turn"] = json!(turn);
        let model = self
            .state
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        if turn > 0 {
            let turns = self
                .state
                .get_mut("turn_models")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| "turn_models malformed".to_string())?;
            let already = turns
                .iter()
                .any(|v| v.get("turn").and_then(Value::as_u64) == Some(turn));
            if !already {
                turns.push(json!({"turn": turn, "model": model}));
            }
        }
        self.state["counters"] = json!({
            "consecutive_unsupported": consecutive_unsupported,
            "consecutive_malformed": consecutive_malformed,
            "consecutive_tool_rejections": consecutive_tool_rejections,
            "unsupported_total": unsupported_total,
            "malformed_total": malformed_total,
            "tools_dispatched_total": tools_dispatched_total,
            "tool_rejections_total": tool_rejections_total,
            "real_capability_executions": real_capability_executions
        });
        self.state["final_content"] = json!(final_content);
        self.persist()
    }

    pub fn record_action_phase(
        &mut self,
        request_id: &str,
        tool: &str,
        args: &Value,
        phase: &str,
        result: Option<&Value>,
    ) -> Result<(), String> {
        let current = self
            .state
            .get("actions")
            .and_then(Value::as_object)
            .and_then(|a| a.get(request_id))
            .and_then(|r| r.get("phase"))
            .and_then(Value::as_str)
            .map(ToString::to_string);

        let allowed = match (current.as_deref(), phase) {
            (None, "REQUEST_CREATED") => true,
            (Some("REQUEST_CREATED"), "VALIDATED") => true,
            (Some("VALIDATED"), "AUTHORIZED") => true,
            (Some("VALIDATED"), "RESULT_COMMITTED") => true,
            (Some("AUTHORIZED"), "EXECUTION_STARTED") => true,
            (Some("EXECUTION_STARTED"), "RESULT_COMMITTED") => true,
            (Some("EXECUTION_STARTED"), "EXECUTION_FAILED") => true,
            _ => false,
        };
        if !allowed {
            return Err(format!(
                "invalid action transition request_id={request_id} from={:?} to={phase}",
                current
            ));
        }

        if phase == "REQUEST_CREATED" {
            let mut consumed = self.consumed_ids()?;
            consumed.insert(request_id.to_string());
            self.store_consumed(&consumed);
            let actions = self
                .state
                .get_mut("actions")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| "actions map malformed".to_string())?;
            let t = now_ms();
            actions.insert(
                request_id.to_string(),
                json!({
                    "request_id": request_id,
                    "tool": tool,
                    "normalized_args": args,
                    "phase": phase,
                    "phase_history": [{"phase":"REQUEST_CREATED","at_ms":t}],
                    "validation_result": null,
                    "authority_decision": null,
                    "created_ms": t,
                    "updated_ms": t,
                    "result": null
                }),
            );
        } else {
            let actions = self
                .state
                .get_mut("actions")
                .and_then(Value::as_object_mut)
                .ok_or_else(|| "actions map malformed".to_string())?;
            let rec = actions
                .get_mut(request_id)
                .ok_or_else(|| format!("missing action record: {request_id}"))?;
            if rec.get("tool").and_then(Value::as_str) != Some(tool)
                || rec.get("normalized_args") != Some(args)
            {
                return Err(format!("action identity mismatch request_id={request_id}"));
            }
            let t = now_ms();
            rec["phase"] = json!(phase);
            rec["updated_ms"] = json!(t);
            let history = rec
                .get_mut("phase_history")
                .and_then(Value::as_array_mut)
                .ok_or_else(|| format!("action phase_history malformed: {request_id}"))?;
            history.push(json!({"phase":phase,"at_ms":t}));
            if phase == "VALIDATED" {
                rec["validation_result"] = json!({"valid":true});
            }
            if phase == "AUTHORIZED" {
                rec["authority_decision"] = json!({"allowed":true});
            }
            if phase == "RESULT_COMMITTED" && current.as_deref() == Some("VALIDATED") {
                rec["authority_decision"] = json!({
                    "allowed":false,
                    "committed_rejection": result.cloned().unwrap_or(Value::Null)
                });
            }
            if let Some(r) = result {
                rec["result"] = r.clone();
            }
        }
        self.persist()
    }

    pub fn context_bytes(&self, messages: &[(String, String)]) -> u64 {
        messages.iter().fold(0u64, |acc, (r, c)| {
            acc.saturating_add(r.len() as u64)
                .saturating_add(c.len() as u64)
                .saturating_add(16)
        })
    }

    pub fn context_budget_bytes(&self) -> u64 {
        self.state
            .get("context_budget")
            .and_then(|v| v.get("hard_limit"))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn finish(
        &mut self,
        messages: &[(String, String)],
        consumed: &HashSet<String>,
        turn: u64,
        consecutive_unsupported: u64,
        consecutive_malformed: u64,
        consecutive_tool_rejections: u64,
        unsupported_total: u64,
        malformed_total: u64,
        tools_dispatched_total: u64,
        tool_rejections_total: u64,
        real_capability_executions: u64,
        final_content: &str,
        stop_reason: &str,
    ) -> Result<(), String> {
        self.sync_loop(
            messages,
            consumed,
            turn,
            consecutive_unsupported,
            consecutive_malformed,
            consecutive_tool_rejections,
            unsupported_total,
            malformed_total,
            tools_dispatched_total,
            tool_rejections_total,
            real_capability_executions,
            final_content,
        )?;
        self.state["stop_reason"] = json!(stop_reason);
        self.state["terminal"] = json!(matches!(stop_reason, "FINAL" | "CANCELLED"));
        self.state["termination"] = json!({
            "stop_reason": stop_reason,
            "cancelled": stop_reason == "CANCELLED",
            "timeout": stop_reason == "TIMEOUT",
            "error": if stop_reason.starts_with("ERROR:") { Value::String(stop_reason.to_string()) } else { Value::Null }
        });
        self.persist()
    }

    /// Build 3: how many requests of this tool reached a committed result in this session.
    pub fn count_actions(&self, tool: &str) -> u64 {
        self.state
            .get("actions")
            .and_then(Value::as_object)
            .map(|a| {
                a.values()
                    .filter(|r| r.get("tool").and_then(Value::as_str) == Some(tool))
                    .filter(|r| r.get("phase").and_then(Value::as_str) == Some("RESULT_COMMITTED"))
                    .count() as u64
            })
            .unwrap_or(0)
    }

    pub fn is_resumed(&self) -> bool {
        self.resumed
    }
    pub fn recovery_notes(&self) -> &[String] {
        &self.recovery_notes
    }

    pub fn summary_json(&self) -> Value {
        json!({
            "schema_version": SESSION_SCHEMA_VERSION,
            "session_id": self.state.get("session_id").cloned().unwrap_or(Value::Null),
            "persistent": self.root.is_some(),
            "resumed": self.resumed,
            "checkpoint_seq": self.state.get("checkpoint_seq").cloned().unwrap_or(Value::Null),
            "checkpoint_path": self.root.as_ref().map(|p| p.join("checkpoint.json").display().to_string()),
            "context_budget": self.state.get("context_budget").cloned().unwrap_or(Value::Null),
            "candidate": self.state.get("immutable_creation").cloned().unwrap_or(Value::Null),
            "mission": self.state.get("mission").cloned().unwrap_or(Value::Null),
            "resume_epoch": self.state.get("resume_epoch").cloned().unwrap_or(Value::Null),
            "limits": self.state.get("limits").cloned().unwrap_or(Value::Null),
            "context_policy": self.state.get("context_policy").cloned().unwrap_or(Value::Null),
            "recovery_notes": &self.recovery_notes,
            "turn_models": self.state.get("turn_models").cloned().unwrap_or(Value::Null),
            "actions": self.state.get("actions").cloned().unwrap_or(Value::Null),
            "termination": self.state.get("termination").cloned().unwrap_or(Value::Null),
            "resume_history": self.state.get("resume_history").cloned().unwrap_or(Value::Null),
            "routing": self.state.get("routing").cloned().unwrap_or(Value::Null)
        })
    }

    fn persist(&mut self) -> Result<(), String> {
        let seq = self
            .state
            .get("checkpoint_seq")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .saturating_add(1);
        self.state["checkpoint_seq"] = json!(seq);
        self.state["updated_ms"] = json!(now_ms());

        let Some(root) = &self.root else {
            return Ok(());
        };

        let payload = self.state.to_string();
        let env = json!({
            "checksum_fnv1a64": fnv1a64(payload.as_bytes()),
            "payload_json": payload
        });
        let bytes = serde_json::to_vec_pretty(&env)
            .map_err(|e| format!("checkpoint serialize failed: {e}"))?;

        let final_path = root.join("checkpoint.json");
        // Exclusive, unpredictable, never through a symlink (see audit::create_temp_beside).
        let (mut f, tmp) = crate::audit::create_temp_beside(&final_path)
            .map_err(|e| format!("checkpoint {e}"))?;
        f.write_all(&bytes)
            .map_err(|e| format!("checkpoint write failed {}: {e}", tmp.display()))?;
        f.flush()
            .map_err(|e| format!("checkpoint flush failed {}: {e}", tmp.display()))?;
        f.sync_all()
            .map_err(|e| format!("checkpoint sync failed {}: {e}", tmp.display()))?;
        fs::rename(&tmp, &final_path).map_err(|e| {
            format!(
                "checkpoint atomic rename failed {} -> {}: {e}",
                tmp.display(),
                final_path.display()
            )
        })?;
        if let Ok(dirf) = fs::File::open(root) {
            let _ = dirf.sync_all();
        }
        Ok(())
    }
}
