#!/usr/bin/env python3
"""HERCULES demo: one bounded, read-only mission with receipts, no real model needed.

    cargo build --release
    python3 examples/demo.py target/release/hercules-agent

A scripted stand-in model (a local HTTP server speaking the Ollama chat API) asks for tool calls.
HERCULES runs them under its rules, writes a hash-chained transcript with a receipt for every call,
builds an evidence report and signs the run. Then `hercules-agent evidence verify` re-derives the
report from the transcript and final answer, and catches an edited copy; `hercules-agent attest
verify` checks the signature and the chain, and also catches an edited transcript whose report was
regenerated to match, which evidence verify alone cannot.

Last, the write lane: the model proposes an edit, the repository stays unchanged, and `hercules-agent
change apply` applies the reviewed, signed changeset; `change rollback` puts the file back.
"""
import base64, glob, hashlib, http.server, json, os, subprocess, sys, tempfile, threading

if len(sys.argv) != 2:
    sys.exit("usage: python3 examples/demo.py <path to hercules-agent>")
BIN = os.path.realpath(sys.argv[1])
MODEL = "demo-model"


def tool(name, args, rid):
    return "TOOL_REQUEST: " + json.dumps({"tool": name, "args": args, "request_id": rid})


class ScriptedModel:
    """Answers each chat request with the next scripted response."""

    def __init__(self, responses):
        script = list(responses)

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                content = script.pop(0) if script else "Nothing further.\nCONTROL: FINAL"
                out = json.dumps({"model": body["model"], "message": {"role": "assistant", "content": content},
                                  "done": True, "done_reason": "stop"}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)
    return path


def main():
    base = os.path.realpath(tempfile.mkdtemp(prefix="hercules-demo-"))
    repo, outside, out = f"{base}/repo", f"{base}/outside", f"{base}/out"
    write(f"{repo}/README.md", "# demo repo\nThe retry limit lives in config.py.\n")
    write(f"{repo}/config.py", "RETRY_LIMIT = 3\nTIMEOUT_SECONDS = 20\n")
    write(f"{repo}/.env", "API_TOKEN=do-not-read\n")
    write(f"{outside}/private.txt", "outside the granted root\n")
    os.makedirs(out)
    os.makedirs(f"{base}/sandbox")
    # Every run is signed: make a throwaway key for the demo (the private key file is mode 0600).
    os.makedirs(f"{base}/keys")
    kg = subprocess.run([BIN, "keygen", "--out", f"{base}/keys"], capture_output=True, text=True)
    if kg.returncode != 0:
        sys.exit(kg.stderr)
    print(kg.stdout.splitlines()[0] + "\n")

    model = ScriptedModel([
        tool("fs.read", {"path": f"{repo}/README.md"}, "r1"),
        tool("cmd.run", {"argv": ["grep", "-rn", "RETRY_LIMIT", repo]}, "r2"),
        tool("fs.read", {"path": f"{repo}/.env"}, "r3"),                # secret-looking file: refused
        tool("fs.read", {"path": f"{outside}/private.txt"}, "r4"),      # outside the granted root: refused
        tool("cmd.run", {"argv": ["rm", "-rf", repo]}, "r5"),           # not an allowed command: refused
        f"The retry limit is 3, set in {repo}/config.py line 1.\nCONTROL: FINAL",
    ])
    cfg = write(f"{base}/hercules.conf",
                "config_version = 2\nprovider.kind = ollama\n"
                f"provider.endpoint = http://127.0.0.1:{model.port}\n"
                f"model.default = {MODEL}\nmodel.context_length = 32000\n"
                "agent.max_iterations = 10\nagent.request_timeout_seconds = 30\n"
                f"root.repo = read:{repo}\ncmd.enable = ls, cat, head, grep, wc\n"
                f"sign.key_file = {base}/keys/signing.key\n")

    p = subprocess.run([BIN, "run", "--mission", "--config", cfg, "--model", MODEL,
                        "--task", "Find the retry limit in this repo and say where it is set.",
                        "--roots", "repo", "--sandbox-root", f"{base}/sandbox",
                        "--transcript", f"{out}/transcript.ndjson", "--evidence", f"{out}/manifest.json",
                        "--evidence-report", f"{out}/evidence.json", "--final-output", f"{out}/final.txt",
                        "--attestation", f"{out}/attestation.json",
                        "--mission-class", "worker", "--max-iterations", "10"],
                       capture_output=True, text=True, timeout=120)
    print(f"mission exit code: {p.returncode}\n")
    if not os.path.exists(f"{out}/transcript.ndjson"):
        sys.exit(p.stderr)

    events = [json.loads(l) for l in open(f"{out}/transcript.ndjson") if l.strip()]
    print("tool calls and what HERCULES did with them:")
    for e in events:
        if e["event"] == "turn.tool_result":
            env = e["data"]["envelope"]
            what = env.get("tool", "?")
            print(f"  {env.get('request_id', '?'):3} {what:8} -> {env['status']}"
                  + (f" ({env.get('error', {}).get('code', '')})" if env["status"] != "ok" else "")
                  + ("  [receipt]" if "receipt" in e["data"] else ""))

    ev = json.load(open(f"{out}/evidence.json"))
    print(f"\nevidence report ({ev.get('derivation')}):")
    print(f"  grounding:       {ev.get('grounding')}  (reads attempted {ev.get('reads_attempted')}, "
          f"succeeded {ev.get('reads_succeeded')})")
    print(f"  paths_inspected: {[os.path.relpath(x['path'], base) + ' via ' + ','.join(x['receipts']) for x in ev.get('paths_inspected', [])]}")
    print(f"  commands_run:    {[' '.join(c['argv']) + ' via ' + c['receipt'] for c in ev.get('commands_run', [])]}")
    print(f"  transcript_sha256: {ev.get('transcript_sha256')}")
    print(f"\nfinal answer: {open(f'{out}/final.txt').read().strip()}\n")

    def verify(report):
        r = subprocess.run([BIN, "evidence", "verify", "--report", report,
                            "--transcript", f"{out}/transcript.ndjson", "--final", f"{out}/final.txt"],
                           capture_output=True, text=True)
        return r.returncode, r.stdout.strip().splitlines()[0] if r.stdout.strip() else r.stderr.strip()

    print("verify the stored report:  ", verify(f"{out}/evidence.json"))
    # Claim a file was read that never was.
    forged = dict(ev, paths_inspected=ev.get("paths_inspected", []) + [
        {"kinds": ["file"], "path": f"{outside}/private.txt", "receipts": ["r4"], "root": "repo", "shown_sha256": []}])
    write(f"{out}/forged.json", json.dumps(forged))
    print("verify an edited report:   ", verify(f"{out}/forged.json"))

    def attest(transcript, report):
        r = subprocess.run([BIN, "attest", "verify", "--attestation", f"{out}/attestation.json",
                            "--pubkey", f"{base}/keys/signing.pub", "--transcript", transcript,
                            "--final", f"{out}/final.txt", "--report", report, "--manifest", f"{out}/manifest.json"],
                           capture_output=True, text=True)
        line = r.stdout.strip().splitlines()[0] if r.stdout.strip() else r.stderr.strip()
        return r.returncode, line.split(" keyid=")[0]

    st = json.loads(base64.b64decode(json.load(open(f"{out}/attestation.json"))["payload"]))
    print(f"\nsigned run statement: kind={st['kind']}, {st['transcript']['events']} chained events, "
          f"stop_reason={st['stop_reason']}")
    print("verify the signed run:     ", attest(f"{out}/transcript.ndjson", f"{out}/evidence.json"))
    # Rewrite what the model said (its request to run rm -rf now reads as a harmless ls) and regenerate
    # the report's transcript hash to match. The report itself is untouched, so evidence verify accepts it.
    t = open(f"{out}/transcript.ndjson").read()
    forged_t = t.replace('[\\"rm\\", \\"-rf\\", ', '[\\"ls\\", ')
    write(f"{out}/forged.ndjson", forged_t)
    forged_r = dict(ev, transcript_sha256=hashlib.sha256(forged_t.encode()).hexdigest())
    write(f"{out}/forged_report.json", json.dumps(forged_r))
    r = subprocess.run([BIN, "evidence", "verify", "--report", f"{out}/forged_report.json",
                        "--transcript", f"{out}/forged.ndjson", "--final", f"{out}/final.txt"], capture_output=True, text=True)
    print("forged transcript + report:")
    print("  evidence verify:         ", (r.returncode, r.stdout.strip()))
    print("  attest verify:           ", attest(f"{out}/forged.ndjson", f"{out}/forged_report.json"))

    # Write lane: the model proposes a change; nothing in the repo changes until you apply it.
    props = f"{base}/proposals"
    os.makedirs(props)
    model2 = ScriptedModel([
        tool("fs.replace", {"path": f"{repo}/config.py", "old": "RETRY_LIMIT = 3", "new": "RETRY_LIMIT = 5"}, "w1"),
        "Proposed RETRY_LIMIT = 5 in config.py.\nCONTROL: FINAL",
    ])
    cfgw = write(f"{base}/hercules-write.conf", open(cfg).read().replace(f"127.0.0.1:{model.port}", f"127.0.0.1:{model2.port}")
                 .replace(f"root.repo = read:{repo}", f"root.repo = write:{repo}"))
    w = f"{base}/out-write"
    os.makedirs(w)
    p = subprocess.run([BIN, "run", "--mission", "--config", cfgw, "--model", MODEL, "--task", "Raise the retry limit to 5.",
                        "--roots", "repo", "--write-roots", "repo", "--proposal-dir", props, "--sandbox-root", f"{base}/sandbox",
                        "--transcript", f"{w}/transcript.ndjson", "--evidence", f"{w}/manifest.json", "--evidence-report", f"{w}/evidence.json",
                        "--final-output", f"{w}/final.txt", "--attestation", f"{w}/attestation.json", "--mission-class", "worker"],
                       capture_output=True, text=True, timeout=120)
    pdir = glob.glob(f"{props}/*")[0]
    digest = hashlib.sha256(open(f"{pdir}/changeset.json", "rb").read()).hexdigest()
    print(f"\nwrite lane: mission exit code {p.returncode}; config.py on disk still says: {open(f'{repo}/config.py').readline().strip()}")
    print("proposed changeset.diff:\n" + "".join("  " + l for l in open(f"{pdir}/changeset.diff")))
    def change(*a):
        r = subprocess.run([BIN, "change", *a], capture_output=True, text=True)
        return (r.stdout.strip() or r.stderr.strip()).splitlines()[0]
    print("apply, reviewed digest:    ", change("apply", "--config", cfgw, "--proposal", pdir, "--approve", digest[:16]),
          f"-> config.py: {open(f'{repo}/config.py').readline().strip()}")
    print("roll back:                 ", change("rollback", "--config", cfgw, "--proposal", pdir),
          f"-> config.py: {open(f'{repo}/config.py').readline().strip()}")
    print(f"\nall files: {out}")


main()
