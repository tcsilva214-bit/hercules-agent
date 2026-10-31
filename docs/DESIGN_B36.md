# Build 3.6: native tool calling — design (written before code)

Written 2026-10-09, after the Step 0 probe (`native_tool_calling/native_probe_report.json`, sha256 `a2de68cb…`).
Base: `cd804d9` (build3.5-candidate). Target: hercules-agent 0.13.0, branch `build3.6-candidate`.

## What the probe settled

Real oMLX with `Qwen3.8-27B-4bit`, `tools` sent, non-streaming, thinking off:

| Question | Result |
|---|---|
| 1. `message.tool_calls` returned | yes, 6/6, `finish_reason: tool_calls`, empty `content`, no markup in text |
| 2. Arguments parse, names known | yes, every call (`cmd_run`, `answer_submit`) |
| 3. Several calls per response | yes, 3/3 first turns sent both greps together |
| 4. Delivers via `answer_submit` after `role: tool` results | yes, correct answer |
| 5. `tool_choice` respected | **not shown**: the model chose `answer_submit` unforced, so the test proves nothing |

Consequence: 3.6 never sends `tool_choice`. "Tools closed" restricts the `tools` list (h) and still refuses
after the fact, which needs neither Q5 nor trust in the model.

## The one idea

**Native calls are a wire encoding, not a second protocol inside the harness.** The gateway turns
`message.tool_calls` into structured calls; the loop gives each call its `request_id` and converts it to the
same envelope `{tool, args, request_id}` that 3.5 validates, authorizes, dispatches and receipts. Everything
after the envelope — `validate`, the batch rule, authority, receipts, the answer contract, salvage, transcript
events — is the 3.5 code, unchanged. On the way back out, the gateway re-encodes the history into
`assistant.tool_calls` + `role: tool` messages.

What the native path removes is the lossy middle: text parsing, `<tool_call>` markup round trips, brace
repairs, `request_id` hoisting. None of these run on a native call.

## Decisions

### a. Switch
- New v2 config key `provider.tool_calls = text | native`, default `text`. Allowed only with
  `config_version = 2` and `provider.kind = openai` (config error otherwise, like `provider.thinking`).
- `text` is 3.5 byte for byte. v1 configs cannot set it, so v1 is unchanged.
- The Arena config for b36 sets `native`. `session_start` records `"tool_calls": "native"`.

### b. Names
- One strict two-way table, every registry tool: `fs.read↔fs_read`, `fs.list↔fs_list`, `fs.stat↔fs_stat`,
  `cmd.run↔cmd_run`, `evidence.check↔evidence_check`, `answer.submit↔answer_submit`, `fs.write↔fs_write`,
  `fs.patch↔fs_patch`, `fs.replace↔fs_replace`, `fs.remove↔fs_remove`, `shell.exec↔shell_exec`,
  `test.*↔test_*`. Unit test: the table is a bijection, covers the registry, and every native name matches
  `^[a-zA-Z0-9_-]{1,64}$`.
- A native call named with a table name maps to its tool. A call named with the exact internal dotted
  name (`fs.read`) is accepted too, and that's recorded; it is the same tool, not a guess. Anything else
  (`tool_request`, `mcp__hercules_native__answer_submit`, `read_file`) goes through as that name and gets
  `UNKNOWN_TOOL` from `validate`, as now. No fuzzy matching in dispatch.
- Because a name that isn't offered still maps to its tool (e.g. `fs_write`), the refusal comes from the
  same authority check as in 3.5 (prohibited), never from a missing table entry.

### Tools offered (part of b)
- Always (v2): `fs_read`, `fs_list`, `fs_stat`. `cmd_run` only when the command policy enables any command.
- `evidence_check` only with an active contract that has evidence; `answer_submit` only with an active
  contract.
- Never offered: write tools, `fs_remove`, `shell_exec`, test tools.
- `turn.model_request` records `tools_offered` (names).

### c. Schemas
- Hand-written next to `validate_build1`, from its rules: required keys, types, bounds, enums,
  `additionalProperties: false`:
  - `fs_read {path: string ≤1024, start_line?: int 1..10000000, max_lines?: int 1..5000}`
  - `fs_list {path, sort?: "name"|"mtime", limit?: int 1..1000}`
  - `fs_stat {path}`
  - `cmd_run {argv: string[1..64], each ≤1024}`
  - `evidence_check {finding: object}`
  - `answer_submit {answer: object}`, with the contract's answer keys listed in the description
- `validate` still runs on every call. The schema is a hint to the model, not the check.
- Drift test: for each tool, a call with only the schema's required keys passes `validate`; a call with a
  key outside the schema gets `UNKNOWN_FIELD`; each bound in the schema is the bound `validate` enforces.

### d. Request ids
- The server's `tool_call.id` is the `request_id` when it is a string, valid (`[A-Za-z0-9._-]`, ≤64), not used
  in the session, and not used by an earlier call in the same response.
- Otherwise the call gets `fresh_request_id("native", turn)`, and `turn.tool_request_repaired` records the
  reason and both ids. So `REQUEST_ID_REUSED` cannot happen to a native call.
- The id the harness used is the id the model sees in the re-encoded history (`tool_calls[].id` and
  `tool_call_id` stay consistent).

### e. Batches
- All of a response's native calls form one batch, through the existing `batch_plan` / `handle_one` code:
  - at most 4 run (`MAX_BATCH_CALLS`), at most 8 examined;
  - only `BATCH_TOOLS` may share a response; any other tool refuses the whole response
    (`MULTIPLE_TOOL_REQUESTS`);
  - results share `RESULT_MAX_CHARS`.
- The rule is not loosened: `answer_submit` still goes alone.
- One change, native only: every call, run or not, gets its own result (needed for f). A call not run
  gets its own `BATCH_LIMIT` result instead of one shared summary. The transcript events
  (`turn.tool_validation` BATCH_LIMIT, `turn.tool_batch_result`) keep their shape.

### f. Results
- Native mode: one `role: tool` message per call, `tool_call_id` = the call's id, in call order, content =
  that call's observation (the same rendered text 3.5 shows).
- A refused whole response (`MULTIPLE_TOOL_REQUESTS`, `TOOLS_CLOSED`) gives every call a result saying so.
  Every `tool_call` id always gets exactly one result, so the conversation is never left with an
  unanswered call.
- Harness notices (the budget, context, rejection and grace notices) are appended to the **last** tool
  message of that turn, so the wire alternates assistant → tool(s) → assistant.
- Context trimming (`fit_observation`) applies across the turn's tool messages: they share the room one
  observation had; the last message is cut first, and the cut is recorded as now.
- **Storage:** the history stays `Vec<(role, content)>`, so the session file, resume, the transcript and Gate 09
  replay keep their shapes. The stored forms:
  - The assistant turn is stored as its text, then one canonical line per call:
    `TOOL_REQUEST: {"tool":"fs.read","args":{…},"request_id":"call_…"}`. Arguments that aren't JSON are
    stored as the raw string in `args`.
  - Each result is stored with role `tool:<id>`.
- **Re-encoding (gateway, native mode only):**
  - An `assistant` message followed by `tool:<id>` messages gets `tool_calls` built from its lines whose
    `request_id` is one of those ids (name mapped back, `arguments` = the args as a JSON string, or the
    raw string); those lines are removed from its `content`.
  - `tool:<id>` becomes `{"role":"tool","tool_call_id":id,"content":…}`.
  - Everything else is sent as now.
- `elide_old_results` also elides `tool:*` results (same stub, same "two most recent kept" rule).

### g. Finishing
- **Response with native calls:** never final; the calls are handled. With `CONTROL:` text beside them, the
  text is kept and the line ignored.
- **No native calls, `done_reason = length`:** the 3.5 output-limit handling, unchanged.
- **No native calls, with an answer contract:**
  - If the text holds an answer object, it goes through the existing text-answer check
    (`FINAL_BY_TEXT_ANSWER` / `TEXT_ANSWER_NOT_ACCEPTED`), as a `CONTROL: FINAL` text answer does in 3.5,
    `CONTROL:` line or not.
  - If it holds no answer object, it is **not** a submit (3.5 spends one of the 3 submits on it):
    1. Record `NO_TOOL_CALL`, counted as malformed (3 in a row → `MALFORMED_CONTROL_LIMIT` → salvage, never
       a clean exit).
    2. Tell the model to call a tool or deliver with `answer_submit`.
- **No native calls, no contract:**
  - The response is the final answer (Hermes's rule), through the existing FINAL branch, so
    `REQUIRED_FINAL_CONTAINS` and report-block corrections still apply.
  - A last line `CONTROL: CONTINUE` still means continue. `CONTROL:` lines are no longer required, and the
    native system prompt does not ask for them.

### h. Tools closed
- The closing conditions are 3.5's (final two responses, context nearly full, three rejections in a row, any
  grace turn). They are all known before the request, so in native mode the request offers:
  - with a contract: **only `answer_submit`**;
  - without one: **no tools** (`tools` omitted).
- No `tool_choice` (Q5 unproven).
- A call that comes anyway is refused after the fact exactly as in 3.5 (`TOOLS_CLOSED`), with a result
  for each call. `answer_submit` stays open as in 3.5.

### i. Bad arguments
- `arguments` that is not a JSON object → that call is refused `BAD_JSON`, detail = the parse error +
  `bad_json_near` (3.5) on the raw string. Arguments sent as a JSON object rather than a string are
  accepted as-is (oMLX sends strings; the shape is legal).
- No brace repair, no hoisting, no guessing on native calls.
- A response cut at the output limit with a call whose arguments broke: the same `BAD_JSON`. A broken
  `answer_submit` on the last response keeps the 3.5 answer-only grace turn.

### j. Fallback to the text path
- Native mode, a response with **no** `tool_calls` that contains `TOOL_REQUEST` lines or `<tool_call>`
  markup: handled by the existing 3.5 text path, with its results as a `user` message (as in 3.5), and
  recorded as `TEXT_PATH_FALLBACK` (event + count).
- **Kept, because:**
  - Today's lesson is that format refusals lose whole sessions.
  - This path only fires when oMLX could not turn the model's markup into `tool_calls`. Refusing it would
    convert those turns into `UNSUPPORTED`/`MALFORMED` and lose sessions for the same reason 3.3–3.5 did.
  - It is existing, reviewed code.
- **Bounded:**
  - When a response has native calls, any text calls beside them are ignored (recorded
    `text_calls_ignored`), never run.
  - The Arena report counts `TEXT_PATH_FALLBACK`. If it is ~0, 3.7 can drop the path.

### k. Salvage
- Native calls are stored as canonical `TOOL_REQUEST` lines (f), so `answers_in_response` already reads a
  native `answer_submit` (run, refused, or closed).
- New:
  - `args` stored as a raw string is parsed for salvage with the same brace repair 3.5's salvage uses.
  - **T08 r3 gap:** in native markup, a call whose name ends in `answer_submit` / `answer.submit` after a `__`
    or `.` separator (e.g. `mcp__hercules_native__answer_submit`) is read as an answer for salvage only. It is
    never dispatched.
- Salvage still checks against the contract (`problems_of`) and is never a clean exit (stop reason and exit
  code unchanged).

## System prompt (native mode)
- `system_prompt_native()` drops the TOOL_REQUEST envelope and the CONTROL-line rule. It says:
  - tools are called through the tool interface;
  - results are data;
  - the authority facts are unchanged.
- The tool guide and answer guide drop the TOOL_REQUEST examples and use native names. Batch rule: up to 4
  read-only calls in one response; `answer_submit` alone.
- Native variants of the harness notices the model is told to act on (TOOLS_CLOSED, budget, context,
  rejection, ANSWER_NOT_ACCEPTED, FINAL_INCOMPLETE, OUTPUT_LIMIT, NO_TOOL_CALL) use native names and no
  CONTROL/TOOL_REQUEST wording.
- Tool output text is never rewritten.

## Not changing
- Authority, roots, cmd policy, receipts, the answer contract and its limits (3 submits, 40 checks), the
  batch limits, the iteration limit and grace turns, salvage's exit codes, transcript event shapes, and the
  ollama provider.
- Native mode adds keys to events; it removes none.

## Tests (Step 2)
- **e2e mock:** it already passes `tool_calls` through. Add an assertion helper that reads `tools`,
  `tool_calls` and `role: tool` from the logged requests.
- **`scenario_b36_native`, one check per point:**
  - a: config errors (v1, ollama, bad value); text mode byte-identical requests.
  - b: names, dotted alias, unknown.
  - c: schema drift.
  - d: missing, invalid, reused and duplicate ids.
  - e: 2–4 reads run; 6 reads → 4 run + 2 `BATCH_LIMIT` results; read + `answer_submit` → refused whole.
  - f: every id answered, notices on the last tool message.
  - Authority: path outside roots, prohibited tool.
  - Contract: accepted submit; refused, then fixed; exhausted.
  - g: no-call final, no contract; `NO_TOOL_CALL` under a contract.
  - h: `tools` restricted on the final two turns.
  - i: `BAD_JSON` with position.
  - j: fallback recorded.
  - k: salvage of a closed/refused native submit + the T08 r3 response.
  - Resume of a native session.
- All existing e2e tests pass in text mode under Python 3.9 with a Mac-length TMPDIR. Rebuild the binary
  before e2e.
- **Replays:** A02 r2 (`tool_request` wrapper) and T08 r3 (native-markup answer) through the native path and
  through salvage.
