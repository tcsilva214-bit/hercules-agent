# HERCULES

**A local agent harness that can prove what it did.**

> **Showcase snapshot.** This is Build 3.6.1 of `hercules-agent` with signed runs, an MCP server
> and a write lane, published so the work can be seen and run. It is not the official release: interfaces, config keys and output schemas may still change, and
> fixes land in the main line first. Issues and questions are welcome; no support is promised.

HERCULES runs a language model in a bounded loop on your own machine and lets it inspect files and run a
small set of read-only commands. Everything it does goes through the harness: model output is only data
until it passes the exact tool protocol, schema validation and an authority decision. Every tool call gets
a receipt. When the run ends, HERCULES writes an evidence report built only from those receipts and the
final answer. Every transcript line is chained to the one before it, and the run ends with an Ed25519
signature over one statement that binds the chain to every file the run wrote. Anyone with the public key
can check it later, offline, and detect an edit to any of them.

It is written in Rust with three dependencies (`serde_json`, `libc`, and `ed25519-dalek` for signatures)
and talks to Ollama or any OpenAI-compatible server (llama.cpp, vLLM, oMLX, ...).

## Install

For macOS (Apple silicon, Intel) and Linux (x86_64, arm64; static binaries). `install.sh` installs
`hercules-agent` into `~/.local/bin` without `sudo`, and only after two checks: `SHA256SUMS.sig` must verify
against the release key below, and the archive must match its line in `SHA256SUMS`.

**Verified install.** Check the installer itself before running it: `install.sh` is listed in the signed
`SHA256SUMS`. Paste the whole block; it stops at the first failed check and runs `install.sh` only after the
signature and the checksum both pass (in an empty folder, since it downloads three files into the current one):

```sh
(
  set -eu
  base=https://github.com/tcsilva214-bit/hercules-agent/releases/download/v0.1.0
  curl -fsSL -O "$base/install.sh" -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.sig"
  printf 'hercules-release namespaces="hercules-release" %s\n' 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGGEtzV1iGZzz9V8O8IrhVDvK47ynA6Vi/ZAUOvb4QVT' > allowed_signers
  ssh-keygen -Y verify -f allowed_signers -I hercules-release -n hercules-release -s SHA256SUMS.sig < SHA256SUMS
  want=$(awk '$2 == "install.sh" {print $1}' SHA256SUMS)
  got=$( (shasum -a 256 install.sh 2>/dev/null || sha256sum install.sh) | awk '{print $1}')
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "install.sh does not match the signed SHA256SUMS; not running it" >&2; exit 1; }
  sh install.sh
)
```

**Quick install.** One line, which trusts `install.sh` as GitHub serves it over HTTPS (the script runs before
anything is checked; it then checks everything it downloads):

```sh
curl -fsSL https://github.com/tcsilva214-bit/hercules-agent/releases/download/v0.1.0/install.sh | sh
```

The script does nothing until its last line, so a download cut off midway runs nothing and installs nothing.
A failed download can still leave the pipe's exit status at 0, though, so check for the `installed:` line it
prints at the end. With Rust installed, build from source instead:

```sh
cargo install --locked --git https://github.com/tcsilva214-bit/hercules-agent --tag v0.1.0 hercules-agent
```

Release key (SSH Ed25519), fingerprint `SHA256:xRDUi2ZT2xlMizPQIEi12VhRJsv8tJ1L9aGK06dwYRA`:

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGGEtzV1iGZzz9V8O8IrhVDvK47ynA6Vi/ZAUOvb4QVT hercules-release
```

To check an archive by hand, after the signature check above:

```sh
shasum -a 256 -c --ignore-missing SHA256SUMS
gh attestation verify hercules-agent-v0.1.0-<target>.tar.gz -R tcsilva214-bit/hercules-agent \
  --signer-workflow github.com/tcsilva214-bit/hercules-agent/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 --deny-self-hosted-runners
```

What a release proves, and what it doesn't:

- **The signature and checksum** prove the archive is the one listed in the `SHA256SUMS` the release key
  signed. `install.sh` installs nothing without both.
- **GitHub's build attestation** (checked with `gh`, as above; `install.sh` checks it too when `gh` is
  installed, and reports the result) proves this repository's release workflow built the archive from the
  tag, on a GitHub-hosted runner. `install.sh` cannot name the tag's commit (it is written before the tag
  exists); the maintainer's signing step checks every archive's attestation against that exact commit.
- **Before signing**, the maintainer rebuilds the macOS arm64 binary from the tag on their own machine, and
  it must match the released one byte for byte, or nothing is signed. The other platforms are not rebuilt
  independently; their build attestations are the evidence for them.
- **Not proved:** that the release key is the right one. It comes from this repository, like the script;
  the key's SHA-256 above, the attestations and the reproducible macOS build are there to cross-check. The
  quick install also trusts the script it runs, as described above.

The binaries are not Apple-notarized. That does not matter for an install with `curl`, but a binary
downloaded with a browser needs `xattr -d com.apple.quarantine hercules-agent`.

## See it in 30 seconds

No model needed: the demo uses a scripted stand-in model on localhost. From a clone of this repository:

```sh
cargo build --release
python3 examples/demo.py target/release/hercules-agent
```

```
tool calls and what HERCULES did with them:
  r1  fs.read  -> ok  [receipt]
  r2  cmd.run  -> ok  [receipt]
  r3  fs.read  -> rejected (DENY_LIST)  [receipt]
  r4  fs.read  -> rejected (ROOT_POLICY)  [receipt]
  r5  cmd.run  -> rejected (CMD_UNKNOWN)  [receipt]

evidence report (pure function of the transcript receipts and the final answer; no model input):
  grounding:       PARTIAL  (reads attempted 5, succeeded 2)
  ...
verify the stored report:   (0, 'EVIDENCE_VERIFY MATCH grounding=PARTIAL')
verify an edited report:    (1, 'EVIDENCE_VERIFY MISMATCH fields=paths_inspected')

signed run statement: kind=mission, 63 chained events, stop_reason=FINAL
verify the signed run:      (0, 'ATTEST_VERIFY MATCH kind=mission')
forged transcript + report:
  evidence verify:          (0, 'EVIDENCE_VERIFY MATCH grounding=PARTIAL')
  attest verify:            (1, 'ATTEST_VERIFY MISMATCH fields=transcript.sha256,transcript.chain,evidence_report_sha256')
```

The model tried to read a `.env` file, a file outside the granted root and to run `rm -rf`; each was
refused, recorded and counted. The final answer cites a file the model only saw through `grep`, so the
report says PARTIAL instead of taking the model's word for it.

The last case is why runs are signed. Someone who rewrites the transcript (here, the model's `rm -rf`
request now reads as a harmless `ls`) and updates the report's transcript hash gets past `evidence verify`,
because the report is still consistent with the edited transcript. `attest verify` catches it: the chain
breaks at the edited line, and the signed statement no longer matches the files.

## What it enforces

- **Declared read-only roots.** The config declares roots; `--roots` picks which ones a run may read.
  An absolute path is readable only if it resolves inside a granted root and no component is on the deny
  list (`.git`, `.ssh`, `.gnupg`, `.aws`, `.env*`, `.netrc`, private keys, `*.pem`, `*.key` and similar,
  plus anything in `root.deny`). Opens are race-checked: `O_NOFOLLOW`, then the path is
  re-resolved and the opened file's device and inode must match, so a swapped path component is caught.
- **No shell.** `cmd.run` takes an argv, never a command string: no pipes, redirection, globbing or
  variables. Each enabled command has a fixed grammar; most are implemented natively on the same read path
  as `fs.read`. Only `git` and `plutil` start a process.
- **Bounded loop.** An iteration cap, request timeouts, no retries, and a stop after three tool
  rejections in a row. Every response must carry the exact model identity that was requested.
- **Authority broker.** Actions that need approval are bound to operator-controlled material: session,
  request id, capability, normalized arguments, expiry, one use.
- **Receipts and transcript.** An NDJSON transcript with sequence continuity, a receipt per tool call and
  redaction of sensitive values.
- **Signed runs.** Every transcript event carries `prev_sha256`, the SHA-256 of the line before it. At the
  end of every run, whatever the stop reason, HERCULES signs one statement (DSSE v1 envelope, Ed25519)
  that binds the chain head to the final answer, the evidence report, the manifest, and the source, binary
  and config digests. There are no unsigned runs: a config without `sign.key_file` is refused, and a key
  that is missing or readable by other users stops the run before the model is contacted.
  `hercules-agent attest verify` checks the signature, every link and that events are numbered 1, 2, 3, ...
  without a gap, the digests of the transcript, the final answer, the evidence report and the manifest (all
  four files are required), then re-derives the report. It needs no network and no account, and the envelope
  is standard enough to check with other tools.
- **Evidence reports.** `paths_inspected`, `read_failures` and `paths_mentioned_not_read` come from the
  harness's receipts, never from what the model claims. `hercules-agent evidence verify` re-derives the
  report from the transcript and final answer.
- **Durable sessions.** Checkpoints, a context budget and resume; a request that already started executing
  is never blindly replayed after a crash.
- **Reproducible builds.** The digest of the source tree (every `.rs` file under `src/`, plus the build
  files) is embedded in the binary (`hercules-agent --version`). `scripts/build-release.sh` pins the compiler
  (`RELEASE_RUSTC`) and strips machine paths and debug info, so the same source and toolchain give the same
  binary from any directory; on macOS, the same Xcode version is needed as well.

## Use it with a real model

With `hercules-agent` installed (built from source, use `target/release/hercules-agent` instead):

```sh
mkdir -p ~/.hercules-keys && hercules-agent keygen --out ~/.hercules-keys
curl -fsSL -o hercules.conf https://raw.githubusercontent.com/tcsilva214-bit/hercules-agent/v0.1.0/examples/hercules.conf.example
# then set root.code and sign.key_file in hercules.conf to real absolute paths
hercules-agent inspect config --config hercules.conf
hercules-agent doctor --config hercules.conf
mkdir -p run/sandbox
hercules-agent run --mission --config hercules.conf --model qwen3:8b \
  --roots code --sandbox-root run/sandbox \
  --task "Where is the retry limit set, and what is it?" \
  --transcript run/t.ndjson --final-output run/final.txt --evidence run/manifest.json \
  --evidence-report run/evidence.json --attestation run/attestation.json
hercules-agent attest verify --attestation run/attestation.json \
  --pubkey ~/.hercules-keys/signing.pub --transcript run/t.ndjson --final run/final.txt \
  --report run/evidence.json --manifest run/manifest.json
```

If a run is killed before it closes, it has no attestation: `attest verify` then reports
`ATTEST_VERIFY INCOMPLETE unsigned chain_intact_through_seq=N` instead of a pass, and resuming the
session (`--session-dir`, `--session-id`, `--resume`) signs the whole chain.

## What a signed run proves, and what it doesn't

- **Proves:** the holder of the key produced exactly these files, and nothing in them changed after
  signing. The evidence report follows from the transcript.
- **Doesn't prove:** that the model's answer is true; that the machine wasn't compromised (the key lives on
  the same machine); or that the timestamps are right (they come from the machine's clock).

There are no silent defaults: a missing or unknown config key, or a root that does not exist, stops the run
with a specific error. `hercules-agent` with no arguments prints every command and flag.

## Proposing changes (the write lane)

A root declared `root.code = write:/abs/path` may receive proposals. In a run with `--write-roots code
--proposal-dir /abs/dir`, the model gets `fs.write` and `fs.replace`, but its writes never reach your files:
they go into a proposal folder outside every root. What the model reads through HERCULES shows its own edits
(`git` reads the originals). At the end of the run HERCULES writes a changeset: each file's base and new
SHA-256 and a unified diff, bound by the run's signature.

Your files change only when you apply the changeset you reviewed:

```sh
hercules-agent change apply --config hercules.conf --proposal /abs/dir/<session id> \
  --approve <first 16+ hex of the changeset's SHA-256>
hercules-agent change rollback --config hercules.conf --proposal /abs/dir/<session id>
hercules-agent change recover --config hercules.conf --proposal /abs/dir/<session id>   # after a crash
hercules-agent change verify --proposal /abs/dir/<session id> --pubkey ~/.hercules-keys/signing.pub
```

Apply checks the signed run, and refuses if any file's content or permissions changed since the proposal.
Before it changes anything it reads and checks every proposed file, keeps a backup and writes a journal
signed with your key. Each file is checked again just before it is replaced, and replaced atomically through
directory handles that never follow a link, so nothing outside the write root can be reached through a
swapped-in link. Then every file is read back and a signed record is written. If any step fails before that
record is written (the commit point, below), apply puts back what it wrote before it exits.

Only one change command runs at a time on a proposal, and only one change at a time is applied in a write
root or any folder inside it, even from different proposals and different configs: each command takes an
exclusive lock on the proposal and on each write root it touches, and a shared lock on every folder above
those roots, so a change in `/work` and one in `/work/app` always exclude each other. The locks are released
by the system however the command ends, and a command refuses rather than waits. Within one config, write
roots may not overlap (one inside another is refused). Rollback works the same way, and checks every
backup before it restores anything. The current deny list applies to apply, rollback and recover alike: a
file that became deny-listed after apply is not touched by any of them.

If the process is killed or the machine stops partway, some files may already be replaced. The journal and
every backup, with the directory entries that lead to them, were written to disk (`fsync`) before the first
file was replaced, so on a file system that honours `fsync` they survive a power loss. The journal then
stays, every `change` command refuses to go on, and `change recover` puts every file back. Recover acts only
on a journal signed by your key for this proposal's changeset, only on files in that changeset and only at the
absolute paths the changeset names (a config that maps a root elsewhere is refused), finds the saved copies
itself, and checks every copy before it changes anything; it leaves alone, and reports, any file that someone
else changed meanwhile.

The signed apply (or rollback) record is the commit point. If it was written before the interruption, the
transaction had finished: `change recover` only removes the leftover journal and leaves the files as they
are; use `change rollback` to undo an apply. If a saved copy is missing or damaged, or the file system fails
while recover writes, recover stops, keeps the journal and says which files it could not put back. Each file is replaced atomically; the set of files is all-or-none
through the journal and `change recover`, not by the file system.

There is no delete or rename; limits are 256 KiB per file, 50 files and 2 MiB per proposal. Not covered: a
process outside HERCULES that changes files in the root while apply runs (it is caught when the file is
checked just before its replacement, but not between that check and the rename), or that renames a whole
directory inside the root (the files then land in that same directory wherever it was moved, never through
a link).

## Use it from another agent (MCP)

`hercules-agent mcp serve` offers the same checked read tools to any MCP client (another agent, an IDE, a
chat app) over stdio: `fs_read`, `fs_list`, `fs_stat`, and `cmd_run` when commands are enabled. Each call
goes through the same validation, authority decision and receipt as a model's call in a mission, and the
text it returns is exactly the text its receipt hashes (the hash is also in the result's `_meta`). No other
tool can be called, and there are no write tools.

It speaks MCP `2026-07-28` and, for clients that still open with an `initialize` handshake, `2025-11-25`.
One server process is one run: when the client closes the server's stdin (or stops it with SIGTERM), the
run is closed and signed like a mission. Each process writes its own folder under `--run-dir`.

```json
{
  "mcpServers": {
    "hercules": {
      "command": "/absolute/path/to/hercules-agent",
      "args": ["mcp", "serve", "--config", "/absolute/path/to/hercules.conf", "--roots", "code",
               "--run-dir", "/absolute/path/to/hercules-runs", "--max-calls", "200"]
    }
  }
}
```

```sh
d=/absolute/path/to/hercules-runs/mcp-...        # one folder per server process
hercules-agent attest verify --attestation $d/attestation.json \
  --pubkey ~/.hercules-keys/signing.pub --transcript $d/transcript.ndjson --final $d/final.txt \
  --report $d/evidence.json --manifest $d/manifest.json
```

A signed MCP run proves every call the client made through HERCULES, what HERCULES decided for each one and
why, the exact text it handed back, and that none of it changed after signing. It does not prove what the
client did with the results or outside HERCULES, or who the client was (its name is self-reported). File
contents are returned as data: text in a file can still carry instructions aimed at the client, and
HERCULES cannot sanitize that.

## Tests

```sh
cargo test --release                                          # unit tests
python3 tests/e2e/e2e.py target/release/hercules-agent        # end-to-end checks against a mock model
python3 tests/install/test_install.py install.sh              # install.sh against a local mock release
```

They run on macOS and Linux and need nothing outside this repository (the installer test also uses `ssh-keygen`
and `curl`, which both systems ship). Any stable Rust builds and tests
HERCULES; an exact, reproducible release build needs the compiler pinned in `RELEASE_RUSTC` (1.97.1)
and is made with `scripts/build-release.sh`, which refuses any other version.

About the fixtures:

- `tests/parser/real_responses.json` holds real model responses that earlier builds refused; the parser
  must now handle each one exactly as listed. Paths, names and timestamps in them were replaced with
  made-up ones, and a few responses that quoted private configuration were rewritten with the same shape.
- `tests/checker/` is a synthetic corpus for the evidence checker. Its expected results were produced
  by the reference implementation the checker was ported from, and are kept byte for byte, which is why
  some model names and a `HERMES_REPORT_BEGIN` marker still appear in it.
- Replays of real recorded sessions, and the harness that compares against the installed production
  binary, are kept private: they embed private configuration.

## Status and scope

Missions are read-only unless a run names write roots, and even then nothing changes until you apply a
reviewed changeset. MCP clients get read tools only. It runs one session on one machine. Design notes
for the native tool-calling build are in [`docs/DESIGN_B36.md`](docs/DESIGN_B36.md).

## License

Copyright 2026 The HERCULES authors. Licensed under Apache-2.0: see [LICENSE](LICENSE) and
[NOTICE](NOTICE). To report a security problem, see [SECURITY.md](SECURITY.md).
