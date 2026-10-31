//! Gate 08 native model router + bounded escalation.
//! Mission-class and host organization-tier namespaces are intentionally distinct.

use serde_json::{json, Value};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

fn fnv1a64(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{h:016x}")
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn obj<'a>(v: &'a Value, key: &str) -> Result<&'a serde_json::Map<String, Value>, String> {
    v.get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| format!("route table field {key} must be an object"))
}

fn str_field<'a>(v: &'a Value, key: &str) -> Result<&'a str, String> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("route table field {key} must be a string"))
}

fn available_contains(available: Option<&HashSet<String>>, model: &str) -> bool {
    available.map(|a| a.contains(model)).unwrap_or(true)
}

#[derive(Debug, Clone)]
pub struct RouteTable {
    raw: Value,
    digest: String,
}

impl RouteTable {
    pub fn load(path: &str) -> Result<Self, String> {
        let bytes = fs::read(path).map_err(|e| format!("route table read failed {path}: {e}"))?;
        let raw: Value = serde_json::from_slice(&bytes)
            .map_err(|e| format!("route table malformed JSON: {e}"))?;
        if raw.get("schema").and_then(Value::as_str) != Some("hercules_native_route_table_v1") {
            return Err("route table schema unsupported".into());
        }
        for key in [
            "route_table_version",
            "provider",
            "mission_classes",
            "org_tiers",
            "work_classes",
            "roles",
            "escalation",
            "provenance",
        ] {
            if raw.get(key).is_none() {
                return Err(format!("route table missing required field: {key}"));
            }
        }
        Ok(Self {
            raw,
            digest: format!("fnv1a64:{}", fnv1a64(&bytes)),
        })
    }

    pub fn version(&self) -> Result<&str, String> {
        str_field(&self.raw, "route_table_version")
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn provider(&self) -> Value {
        self.raw.get("provider").cloned().unwrap_or(Value::Null)
    }

    pub fn resolve(
        &self,
        namespace: &str,
        key: &str,
        available: Option<&HashSet<String>>,
        allow_frozen_fallback: bool,
    ) -> Result<Value, String> {
        let mut selected_model: Option<String> = None;
        let mut resolved_role: Option<String> = None;
        let mut resolved_tier: Option<String> = None;
        let mut fallback_model: Option<String> = None;
        let mut reason = "direct_frozen_route".to_string();
        let mut fallback_used = false;

        match namespace {
            "mission_class" => {
                let routes = obj(&self.raw, "mission_classes")?;
                let r = routes
                    .get(key)
                    .and_then(Value::as_object)
                    .ok_or_else(|| format!("UNKNOWN_MISSION_CLASS:{key}"))?;
                selected_model = r
                    .get("model")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                resolved_role = r
                    .get("role")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
            }
            "org_tier" => {
                let tiers = obj(&self.raw, "org_tiers")?;
                let v = tiers
                    .get(key)
                    .ok_or_else(|| format!("UNKNOWN_ORG_TIER:{key}"))?;
                if v.is_null() {
                    reason = "operator_only_route".into();
                } else {
                    selected_model = v.as_str().map(ToString::to_string);
                    resolved_tier = Some(key.to_string());
                }
            }
            "work_class" => {
                let wc = obj(&self.raw, "work_classes")?;
                let tier = wc
                    .get(key)
                    .and_then(Value::as_str)
                    .ok_or_else(|| format!("UNKNOWN_WORK_CLASS:{key}"))?
                    .to_string();
                resolved_tier = Some(tier.clone());
                if tier == "operator_only" || tier == "operator" {
                    reason = "operator_only_route".into();
                } else {
                    let tiers = obj(&self.raw, "org_tiers")?;
                    selected_model = tiers
                        .get(&tier)
                        .and_then(Value::as_str)
                        .map(ToString::to_string);
                    if selected_model.is_none() {
                        return Err(format!("MISSING_ROUTE_FOR_TIER:{tier}"));
                    }
                }
            }
            "role" => {
                let roles = obj(&self.raw, "roles")?;
                let r = roles
                    .get(key)
                    .and_then(Value::as_object)
                    .ok_or_else(|| format!("UNKNOWN_ROLE:{key}"))?;
                resolved_role = Some(key.to_string());
                resolved_tier = r
                    .get("tier")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                selected_model = r
                    .get("preferred")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                fallback_model = r
                    .get("fallback")
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
            }
            _ => return Err(format!("UNKNOWN_ROUTE_NAMESPACE:{namespace}")),
        }

        if let Some(model) = selected_model.clone() {
            if !available_contains(available, &model) {
                if namespace == "role" && allow_frozen_fallback {
                    if let Some(fb) = fallback_model.clone() {
                        if available_contains(available, &fb) {
                            selected_model = Some(fb);
                            fallback_used = true;
                            reason = "explicit_frozen_role_fallback".into();
                        } else {
                            return Err(format!(
                                "MODEL_UNAVAILABLE preferred={model} fallback={fb}"
                            ));
                        }
                    } else {
                        return Err(format!("MODEL_UNAVAILABLE required={model} fallback=none"));
                    }
                } else {
                    return Err(format!(
                        "MODEL_UNAVAILABLE required={model} silent_substitution=forbidden"
                    ));
                }
            }
        }

        Ok(json!({
            "status": if selected_model.is_some() { "ROUTED" } else { "OPERATOR_REQUIRED" },
            "namespace": namespace,
            "key": key,
            "resolved_role": resolved_role,
            "resolved_tier": resolved_tier,
            "selected_model": selected_model,
            "fallback_model": fallback_model,
            "fallback_used": fallback_used,
            "provider": self.provider(),
            "route_table_version": self.version()?,
            "route_table_digest": self.digest(),
            "reason": reason
        }))
    }

    pub fn escalate(
        &self,
        from_tier: &str,
        trigger: &str,
        depth: u64,
        available: Option<&HashSet<String>>,
    ) -> Result<Value, String> {
        let esc = obj(&self.raw, "escalation")?;
        let chain = esc
            .get("chain")
            .and_then(Value::as_array)
            .ok_or_else(|| "escalation.chain malformed".to_string())?;
        let max_transitions = esc
            .get("max_transitions")
            .and_then(Value::as_u64)
            .ok_or_else(|| "escalation.max_transitions malformed".to_string())?;

        if depth >= max_transitions {
            return Err(format!(
                "ESCALATION_LIMIT_REACHED depth={depth} max={max_transitions}"
            ));
        }

        let idx = chain
            .iter()
            .position(|v| v.as_str() == Some(from_tier))
            .ok_or_else(|| format!("UNKNOWN_ESCALATION_SOURCE:{from_tier}"))?;
        if idx + 1 >= chain.len() {
            return Err(format!("ESCALATION_TERMINAL_SOURCE:{from_tier}"));
        }

        let target_tier = chain[idx + 1]
            .as_str()
            .ok_or_else(|| "escalation target malformed".to_string())?;
        let edge = format!("{from_tier}_to_{target_tier}");
        let triggers = esc
            .get("triggers")
            .and_then(Value::as_object)
            .and_then(|m| m.get(&edge))
            .and_then(Value::as_array)
            .ok_or_else(|| format!("MISSING_ESCALATION_EDGE:{edge}"))?;

        if !triggers.iter().any(|v| v.as_str() == Some(trigger)) {
            return Err(format!(
                "ESCALATION_NOT_PERMITTED edge={edge} trigger={trigger}"
            ));
        }

        let target_model = if target_tier == "operator" {
            None
        } else {
            obj(&self.raw, "org_tiers")?
                .get(target_tier)
                .and_then(Value::as_str)
                .map(ToString::to_string)
        };

        if target_tier != "operator" && target_model.is_none() {
            return Err(format!("MISSING_ROUTE_FOR_TIER:{target_tier}"));
        }

        if let Some(model) = target_model.as_deref() {
            if !available_contains(available, model) {
                return Err(format!(
                    "MODEL_UNAVAILABLE required={model} escalation_fallback=forbidden"
                ));
            }
        }

        Ok(json!({
            "status": if target_model.is_some() { "ESCALATED" } else { "OPERATOR_REQUIRED" },
            "source_tier": from_tier,
            "target_tier": target_tier,
            "target_model": target_model,
            "trigger": trigger,
            "depth_from": depth,
            "depth_to": depth + 1,
            "route_table_version": self.version()?,
            "route_table_digest": self.digest(),
            "reason": format!("permitted frozen upward edge {edge}")
        }))
    }
}

pub fn load_available_models(path: Option<&str>) -> Result<Option<HashSet<String>>, String> {
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("available-models read failed {path}: {e}"))?;
    let v: Value =
        serde_json::from_str(&raw).map_err(|e| format!("available-models malformed JSON: {e}"))?;
    let arr = v.as_array().ok_or_else(|| {
        "available-models must be a JSON array of exact model strings".to_string()
    })?;
    let mut out = HashSet::new();
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| "available-models entry must be a string".to_string())?;
        out.insert(s.to_string());
    }
    Ok(Some(out))
}

pub fn load_json_file(path: &str) -> Result<Value, String> {
    let raw = fs::read_to_string(path).map_err(|e| format!("JSON read failed {path}: {e}"))?;
    serde_json::from_str(&raw).map_err(|e| format!("JSON malformed {path}: {e}"))
}

fn checkpoint_read(path: &str) -> Result<Value, String> {
    let raw =
        fs::read_to_string(path).map_err(|e| format!("checkpoint read failed {path}: {e}"))?;
    let env: Value =
        serde_json::from_str(&raw).map_err(|e| format!("checkpoint envelope malformed: {e}"))?;
    let checksum = env
        .get("checksum_fnv1a64")
        .and_then(Value::as_str)
        .ok_or_else(|| "checkpoint checksum missing".to_string())?;
    let payload = env
        .get("payload_json")
        .and_then(Value::as_str)
        .ok_or_else(|| "checkpoint payload missing".to_string())?;
    let actual = fnv1a64(payload.as_bytes());
    if checksum != actual {
        return Err(format!(
            "checkpoint checksum mismatch expected={checksum} actual={actual}"
        ));
    }
    let state: Value =
        serde_json::from_str(payload).map_err(|e| format!("checkpoint payload malformed: {e}"))?;
    if state.get("schema_version").and_then(Value::as_u64) != Some(2) {
        return Err("Gate 08 requires Gate 07 checkpoint schema 2".into());
    }
    Ok(state)
}

fn checkpoint_write(path: &str, state: &mut Value) -> Result<(), String> {
    let seq = state
        .get("checkpoint_seq")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        .saturating_add(1);
    state["checkpoint_seq"] = json!(seq);
    state["updated_ms"] = json!(now_ms());

    let payload = state.to_string();
    let env = json!({
        "checksum_fnv1a64": fnv1a64(payload.as_bytes()),
        "payload_json": payload
    });
    let bytes =
        serde_json::to_vec_pretty(&env).map_err(|e| format!("checkpoint serialize failed: {e}"))?;

    let p = Path::new(path);
    let parent = p
        .parent()
        .ok_or_else(|| "checkpoint path has no parent".to_string())?;
    let tmp = parent.join(format!(
        ".gate08-checkpoint.tmp-{}-{}",
        std::process::id(),
        now_ms()
    ));
    let mut f = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&tmp)
        .map_err(|e| format!("checkpoint temp open failed {}: {e}", tmp.display()))?;
    f.write_all(&bytes)
        .map_err(|e| format!("checkpoint temp write failed {}: {e}", tmp.display()))?;
    f.flush()
        .map_err(|e| format!("checkpoint temp flush failed {}: {e}", tmp.display()))?;
    f.sync_all()
        .map_err(|e| format!("checkpoint temp sync failed {}: {e}", tmp.display()))?;
    fs::rename(&tmp, p)
        .map_err(|e| format!("checkpoint atomic rename failed {}: {e}", p.display()))?;
    if let Ok(dirf) = fs::File::open(parent) {
        let _ = dirf.sync_all();
    }
    Ok(())
}

fn preservation_view(state: &Value) -> Value {
    json!({
        "immutable_creation": state.get("immutable_creation").cloned().unwrap_or(Value::Null),
        "task": state.get("task").cloned().unwrap_or(Value::Null),
        "messages": state.get("messages").cloned().unwrap_or(Value::Null),
        "consumed_request_ids": state.get("consumed_request_ids").cloned().unwrap_or(Value::Null),
        "actions": state.get("actions").cloned().unwrap_or(Value::Null),
        "counters": state.get("counters").cloned().unwrap_or(Value::Null),
        "context_budget": state.get("context_budget").cloned().unwrap_or(Value::Null),
        "context_policy": state.get("context_policy").cloned().unwrap_or(Value::Null)
    })
}

fn preservation_digest(state: &Value) -> String {
    format!(
        "fnv1a64:{}",
        fnv1a64(preservation_view(state).to_string().as_bytes())
    )
}

fn ensure_no_unreconciled_action(state: &Value) -> Result<(), String> {
    if let Some(actions) = state.get("actions").and_then(Value::as_object) {
        for (rid, rec) in actions {
            let phase = rec.get("phase").and_then(Value::as_str).unwrap_or("");
            if phase == "EXECUTION_STARTED" || phase == "OUTCOME_UNKNOWN" {
                return Err(format!(
                    "ESCALATION_BLOCKED_UNRECONCILED_ACTION request_id={rid} phase={phase}"
                ));
            }
        }
    }
    Ok(())
}

pub fn bind_checkpoint(
    table: &RouteTable,
    checkpoint_path: &str,
    namespace: &str,
    key: &str,
    authority_summary: &Value,
) -> Result<Value, String> {
    let mut state = checkpoint_read(checkpoint_path)?;
    if state.get("terminal").and_then(Value::as_bool) == Some(true) {
        return Err("cannot bind routing to terminal session".into());
    }
    let decision = table.resolve(namespace, key, None, false)?;
    let selected = decision
        .get("selected_model")
        .and_then(Value::as_str)
        .ok_or_else(|| "route does not select a model".to_string())?;
    let current = state
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| "checkpoint model missing".to_string())?;
    if selected != current {
        return Err(format!(
            "ROUTE_MODEL_MISMATCH checkpoint={current} route={selected}"
        ));
    }

    let before = preservation_digest(&state);
    state["routing"] = json!({
        "route_table_version": table.version()?,
        "route_table_digest": table.digest(),
        "namespace": namespace,
        "key": key,
        "resolved_role": decision.get("resolved_role").cloned().unwrap_or(Value::Null),
        "current_tier": decision.get("resolved_tier").cloned().unwrap_or(Value::Null),
        "current_model": selected,
        "initial_decision": decision,
        "authority_summary": authority_summary,
        "escalation_depth": 0,
        "escalations": []
    });
    if namespace == "mission_class" {
        state["mission"]["class"] = json!(key);
    }
    checkpoint_write(checkpoint_path, &mut state)?;
    let after_state = checkpoint_read(checkpoint_path)?;
    let after = preservation_digest(&after_state);
    if before != after {
        return Err(format!(
            "ROUTE_BIND_PRESERVATION_FAILURE before={before} after={after}"
        ));
    }
    Ok(json!({
        "status":"BOUND",
        "checkpoint":checkpoint_path,
        "route_table_version":table.version()?,
        "route_table_digest":table.digest(),
        "preservation_before":before,
        "preservation_after":after,
        "preserved":true
    }))
}

pub fn escalate_checkpoint(
    table: &RouteTable,
    checkpoint_path: &str,
    trigger: &str,
    authority_summary: &Value,
    available: Option<&HashSet<String>>,
) -> Result<Value, String> {
    let mut state = checkpoint_read(checkpoint_path)?;
    if state.get("terminal").and_then(Value::as_bool) == Some(true) {
        return Err("cannot escalate terminal session".into());
    }
    ensure_no_unreconciled_action(&state)?;

    let routing = state
        .get("routing")
        .and_then(Value::as_object)
        .ok_or_else(|| "checkpoint has no Gate 08 routing binding".to_string())?;

    if routing.get("route_table_version").and_then(Value::as_str) != Some(table.version()?) {
        return Err("checkpoint route-table version mismatch".into());
    }
    if routing.get("route_table_digest").and_then(Value::as_str) != Some(table.digest()) {
        return Err("checkpoint route-table digest mismatch".into());
    }
    if routing.get("authority_summary") != Some(authority_summary) {
        return Err("AUTHORITY_CONTEXT_CHANGED_ACROSS_ESCALATION".into());
    }

    let namespace = routing
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| "checkpoint routing namespace missing".to_string())?;
    if namespace == "mission_class" {
        return Err(
            "MISSION_CLASS_NAMESPACE_HAS_NO_IMPLICIT_ORG_ESCALATION; use an org-tier/work-class/role route"
                .into(),
        );
    }

    let from_tier = routing
        .get("current_tier")
        .and_then(Value::as_str)
        .ok_or_else(|| "checkpoint current_tier missing".to_string())?
        .to_string();
    let depth = routing
        .get("escalation_depth")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let source_model = state
        .get("model")
        .and_then(Value::as_str)
        .ok_or_else(|| "checkpoint model missing".to_string())?
        .to_string();
    let turn_boundary = state.get("turn").and_then(Value::as_u64).unwrap_or(0);

    let decision = table.escalate(&from_tier, trigger, depth, available)?;
    let target_tier = decision
        .get("target_tier")
        .and_then(Value::as_str)
        .ok_or_else(|| "escalation target tier missing".to_string())?
        .to_string();
    let target_model = decision
        .get("target_model")
        .and_then(Value::as_str)
        .map(ToString::to_string);

    let before = preservation_digest(&state);

    {
        let routing = state
            .get_mut("routing")
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "checkpoint routing object malformed".to_string())?;
        let list = routing
            .get_mut("escalations")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| "checkpoint escalations list malformed".to_string())?;
        list.push(json!({
            "turn_boundary": turn_boundary,
            "trigger": trigger,
            "source_tier": from_tier,
            "target_tier": target_tier,
            "source_model": source_model,
            "target_model": target_model,
            "reason": decision.get("reason").cloned().unwrap_or(Value::Null),
            "authority_unchanged": true,
            "depth_from": depth,
            "depth_to": depth + 1
        }));
        routing["current_tier"] = json!(target_tier);
        routing["current_model"] = target_model
            .as_ref()
            .map(|m| json!(m))
            .unwrap_or(Value::Null);
        routing["escalation_depth"] = json!(depth + 1);
    }

    if let Some(model) = target_model.as_deref() {
        state["model"] = json!(model);
    }

    checkpoint_write(checkpoint_path, &mut state)?;
    let after_state = checkpoint_read(checkpoint_path)?;
    let after = preservation_digest(&after_state);
    if before != after {
        return Err(format!(
            "ESCALATION_PRESERVATION_FAILURE before={before} after={after}"
        ));
    }

    Ok(json!({
        "status": decision.get("status").cloned().unwrap_or(Value::Null),
        "checkpoint": checkpoint_path,
        "source_tier": from_tier,
        "target_tier": target_tier,
        "source_model": source_model,
        "target_model": target_model,
        "trigger": trigger,
        "turn_boundary": turn_boundary,
        "depth_from": depth,
        "depth_to": depth + 1,
        "route_table_version": table.version()?,
        "route_table_digest": table.digest(),
        "authority_unchanged": true,
        "preservation_before": before,
        "preservation_after": after,
        "preserved": true
    }))
}
