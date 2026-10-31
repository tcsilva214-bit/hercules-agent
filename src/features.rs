//! Build 1 feature switch.
//! Everything added in Build 1 (workspace roots, cmd.run, new tool arguments,
//! receipts, the tool guide in the system prompt) is active only when the
//! config declares `config_version = 2`. A v1 config keeps hercules-2's exact
//! validation, error codes and transcript shape, so existing gate suites stay valid.

use std::sync::OnceLock;

static BUILD1: OnceLock<bool> = OnceLock::new();

/// Set once at startup from the loaded config. Later calls are ignored.
pub fn set_build1(enabled: bool) {
    let _ = BUILD1.set(enabled);
}

/// True when the run uses a v2 config.
pub fn build1() -> bool {
    *BUILD1.get().unwrap_or(&false)
}

static NATIVE: OnceLock<bool> = OnceLock::new();

/// Build 3.6: set once at startup: `provider.tool_calls = native` (v2, openai only).
pub fn set_native(enabled: bool) {
    let _ = NATIVE.set(enabled);
}

/// True when tool calls travel as native `tools` / `message.tool_calls` (Build 3.6).
pub fn native() -> bool {
    *NATIVE.get().unwrap_or(&false)
}

static WRITE_LANE: OnceLock<bool> = OnceLock::new();

/// Gate 10: set once at startup when the run has write roots (`--write-roots`). Offers fs.write / fs.replace.
pub fn set_write_lane(enabled: bool) {
    let _ = WRITE_LANE.set(enabled);
}

pub fn write_lane() -> bool {
    *WRITE_LANE.get().unwrap_or(&false)
}
