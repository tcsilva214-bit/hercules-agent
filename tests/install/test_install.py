#!/usr/bin/env python3
"""install.sh against a local mock release. Standard library plus ssh-keygen, sh and curl; no network.

usage: python3 tests/install/test_install.py [path/to/install.sh]

Makes a throwaway release key, a release folder with an archive for this machine (holding a stand-in
binary that only prints a version line), SHA256SUMS and its signature, serves it on 127.0.0.1, and runs a
copy of install.sh pointed at it, with the throwaway key in place of the release key.
"""
import hashlib, http.server, os, platform, re, shutil, subprocess, sys, tarfile, tempfile, threading

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.abspath(sys.argv[1]) if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "install.sh")
VERSION = re.search(r'^VERSION="(v[^"]+)"', open(SCRIPT).read(), re.M).group(1)
RESULTS = []


def check(name, cond, detail=""):
    RESULTS.append(bool(cond))
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f"  -- {detail}"))


def host_target():
    s, m = platform.system(), platform.machine()
    if s == "Darwin":
        translated = subprocess.run(["sysctl", "-n", "sysctl.proc_translated"], capture_output=True, text=True).stdout.strip()
        return "aarch64-apple-darwin" if m == "arm64" or translated == "1" else "x86_64-apple-darwin"
    return {"x86_64": "x86_64-unknown-linux-musl", "amd64": "x86_64-unknown-linux-musl", "aarch64": "aarch64-unknown-linux-musl", "arm64": "aarch64-unknown-linux-musl"}[m]


def sh(*a, **kw):
    return subprocess.run(list(a), capture_output=True, text=True, **kw)


base = os.path.realpath(tempfile.mkdtemp(prefix="hercules-install-test-"))
try:
    target = host_target()
    rel = os.path.join(base, "release")
    os.makedirs(rel)
    # Two throwaway keys: the trusted one and an impostor.
    for k in ("key", "other"):
        r = sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "hercules-release", "-f", os.path.join(base, k))
        assert r.returncode == 0, r.stderr
    pub = open(os.path.join(base, "key.pub")).read().strip()

    def make_release(version_line, sign_with="key", tamper=False, sig=True, installer=None, tamper_installer=False):
        for f in os.listdir(rel):
            os.remove(os.path.join(rel, f))
        name = f"hercules-agent-{VERSION}-{target}"
        stage = os.path.join(base, "stage", name)
        shutil.rmtree(os.path.join(base, "stage"), ignore_errors=True)
        os.makedirs(stage)
        b = os.path.join(stage, "hercules-agent")
        open(b, "w").write(f"#!/bin/sh\necho '{version_line}'\n")
        os.chmod(b, 0o755)
        arc = os.path.join(rel, f"{name}.tar.gz")
        with tarfile.open(arc, "w:gz") as t:
            t.add(stage, arcname=name)
        import hashlib
        digest = hashlib.sha256(open(arc, "rb").read()).hexdigest()
        sums = f"{digest}  {name}.tar.gz\n"
        if installer is not None:
            open(os.path.join(rel, "install.sh"), "w").write(installer)
            sums += f"{hashlib.sha256(installer.encode()).hexdigest()}  install.sh\n"
        open(os.path.join(rel, "SHA256SUMS"), "w").write(sums)
        if sig:
            r = sh("ssh-keygen", "-Y", "sign", "-f", os.path.join(base, sign_with), "-n", "hercules-release", os.path.join(rel, "SHA256SUMS"))
            assert r.returncode == 0, r.stderr
        if tamper:
            with open(arc, "ab") as f:
                f.write(b"x")
        if tamper_installer:
            with open(os.path.join(rel, "install.sh"), "a") as f:
                f.write("\necho TAMPERED-INSTALLER-RAN\n")

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **kw):
            super().__init__(*a, directory=rel, **kw)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]

    text = open(SCRIPT).read()
    check("install.sh: plain POSIX sh syntax", sh("sh", "-n", SCRIPT).returncode == 0)
    code_lines = [l for l in text.splitlines() if not l.lstrip().startswith("#")]
    check("install.sh: never calls sudo (code lines)", not any(re.search(r"\bsudo\b", l) for l in code_lines))
    check("install.sh: no option to skip verification", not re.search(r"--(no|skip)-(verify|check)|insecure", text))
    test_script = os.path.join(base, "install.sh")
    t = re.sub(r'^RELEASE_BASE=.*$', f'RELEASE_BASE="http://127.0.0.1:{port}"', text, count=1, flags=re.M)
    t = re.sub(r'^RELEASE_PUBKEY=.*$', f'RELEASE_PUBKEY="{pub}"', t, count=1, flags=re.M)
    open(test_script, "w").write(t)

    # gh present but failing: the attestation line is information only.
    shims = os.path.join(base, "shims")
    os.makedirs(shims)
    open(os.path.join(shims, "gh"), "w").write("#!/bin/sh\nexit 1\n")
    os.chmod(os.path.join(shims, "gh"), 0o755)

    def run(home, *args, env_extra=None, script=test_script, path_prefix=shims):
        env = {"HOME": home, "PATH": f"{path_prefix}:{os.environ['PATH']}"}
        env.update(env_extra or {})
        os.makedirs(home, exist_ok=True)
        return sh("sh", script, *args, env=env, timeout=60)

    shells = ["sh"] + (["dash"] if shutil.which("dash") else [])
    for shell in shells:
        home = os.path.join(base, f"home-{shell}")
        make_release("hercules-agent 0.1.0 (source test)")
        env = {"HOME": home, "PATH": f"{shims}:{os.environ['PATH']}"}
        os.makedirs(home, exist_ok=True)
        r = sh(shell, test_script, env=env, timeout=60)
        dest = os.path.join(home, ".local", "bin", "hercules-agent")
        check(f"{shell}: happy path installs into ~/.local/bin", r.returncode == 0 and os.access(dest, os.X_OK)
              and "signature: OK" in r.stdout and "checksum:  OK" in r.stdout and "installed: " + dest in r.stdout, (r.returncode, r.stdout, r.stderr))
    check("gh present: attestation reported as information only", "attestation: not confirmed" in r.stdout, r.stdout)
    check("PATH hint when ~/.local/bin is not on PATH", "is not on your PATH" in r.stdout, r.stdout)
    check("next steps printed (keygen)", "hercules-agent keygen" in r.stdout, r.stdout)

    home = os.path.join(base, "home-sh")
    r = run(home)
    check("same version again: reports already installed", r.returncode == 0 and "already installed" in r.stdout, (r.returncode, r.stdout, r.stderr))
    make_release("hercules-agent 0.2.0 (source test)")
    r = run(home)
    check("a different installed version is refused without --force", r.returncode != 0 and "--force" in r.stderr
          and "0.1.0" in sh(os.path.join(home, ".local/bin/hercules-agent")).stdout, (r.returncode, r.stderr))
    r = run(home, "--force")
    check("--force replaces it", r.returncode == 0 and "0.2.0" in sh(os.path.join(home, ".local/bin/hercules-agent")).stdout, (r.returncode, r.stderr))
    r = run(home, "--yes")
    check("an unknown option is refused", r.returncode != 0 and "unknown option" in r.stderr, r.stderr)

    custom = os.path.join(base, "custom-bin")
    r = run(os.path.join(base, "home-custom"), env_extra={"HERCULES_INSTALL_DIR": custom})
    check("HERCULES_INSTALL_DIR is honoured", r.returncode == 0 and os.path.exists(os.path.join(custom, "hercules-agent"))
          and not os.path.exists(os.path.join(base, "home-custom", ".local")), (r.returncode, r.stderr))

    def refused(name, home, want, **kw):
        r = run(home, **kw)
        nothing = not os.path.exists(os.path.join(home, ".local", "bin", "hercules-agent"))
        check(name, r.returncode != 0 and want in r.stderr and nothing, (r.returncode, r.stdout, r.stderr))

    make_release("hercules-agent 0.1.0 (source test)", sign_with="other")
    refused("signed by another key: refused, nothing installed", os.path.join(base, "h1"), "does NOT verify")
    make_release("hercules-agent 0.1.0 (source test)", tamper=True)
    refused("archive changed after signing: refused, nothing installed", os.path.join(base, "h2"), "checksum mismatch")
    make_release("hercules-agent 0.1.0 (source test)", sig=False)
    refused("no SHA256SUMS.sig: refused, nothing installed", os.path.join(base, "h3"), "SHA256SUMS.sig")
    make_release("hercules-agent 0.1.0 (source test)")
    uname = os.path.join(base, "uname-shim")
    os.makedirs(uname)
    open(os.path.join(uname, "uname"), "w").write("#!/bin/sh\ncase \"$1\" in -s) echo Linux ;; -m) echo sparc64 ;; *) echo Linux ;; esac\n")
    os.chmod(os.path.join(uname, "uname"), 0o755)
    refused("unknown CPU: refused", os.path.join(base, "h4"), "unsupported", path_prefix=f"{uname}:{shims}")
    unkeyed = os.path.join(base, "install-unkeyed.sh")
    open(unkeyed, "w").write(re.sub(r'^RELEASE_PUBKEY=.*$', 'RELEASE_PUBKEY="ssh-ed25519 RELEASE_PUBKEY_NOT_SET hercules-release"', t, count=1, flags=re.M))
    refused("a copy without a release key refuses", os.path.join(base, "h5"), "no release key", script=unkeyed)
    # A partly downloaded script (curl cut off mid-transfer) does nothing: everything runs from main on the last line.
    cut = os.path.join(base, "install-cut.sh")
    open(cut, "w").write(t[: t.index("main \"$@\"")])
    r = run(os.path.join(base, "h6"), script=cut)
    check("a truncated script installs nothing and downloads nothing", not os.path.exists(os.path.join(base, "h6", ".local"))
          and "hercules-agent v" not in r.stdout, (r.returncode, r.stdout, r.stderr))
    # gh present and succeeding: the attestation check is pinned to this repo's release workflow and this tag.
    okgh = os.path.join(base, "okgh")
    os.makedirs(okgh)
    argslog = os.path.join(base, "gh-args.txt")
    open(os.path.join(okgh, "gh"), "w").write(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{argslog}'\nexit 0\n")
    os.chmod(os.path.join(okgh, "gh"), 0o755)
    r = run(os.path.join(base, "h7"), path_prefix=okgh)
    ghargs = open(argslog).read().split("\n") if os.path.exists(argslog) else []
    repo = re.search(r'^REPO="([^"]+)"', text, re.M).group(1)
    pinned = all(x in ghargs for x in ("--signer-workflow", f"github.com/{repo}/.github/workflows/release.yml", "--source-ref",
                                       f"refs/tags/{VERSION}", "--deny-self-hosted-runners", "-R", repo))
    check("gh attestation check is pinned to the release workflow and the tag", r.returncode == 0 and pinned
          and f"from tag {VERSION}" in r.stdout, (ghargs, r.stdout))
    # An install directory others can write to is refused.
    gw = os.path.join(base, "groupw")
    os.makedirs(gw)
    os.chmod(gw, 0o775)
    r = run(os.path.join(base, "h8"), env_extra={"HERCULES_INSTALL_DIR": gw})
    check("a group-writable install directory is refused", r.returncode != 0 and "not writable by group or others" in r.stderr
          and not os.path.exists(os.path.join(gw, "hercules-agent")), (r.returncode, r.stderr))
    # A link planted at the destination is refused; the file it points to is untouched.
    pd = os.path.join(base, "planted")
    os.makedirs(pd)
    victim = os.path.join(base, "victim")
    open(victim, "w").write("keep")
    os.symlink(victim, os.path.join(pd, "hercules-agent"))
    r = run(os.path.join(base, "h9"), "--force", env_extra={"HERCULES_INSTALL_DIR": pd})
    check("a link at the destination is refused and its target untouched", r.returncode != 0 and "not a regular file" in r.stderr
          and open(victim).read() == "keep", (r.returncode, r.stderr))
    # The README's verified-install block, run exactly as written (the release URL and key swapped for the mock's).
    readme = os.path.join(HERE, "..", "..", "README.md")
    m = re.search(r"\*\*Verified install\.\*\*.*?```sh\n(.*?)```", open(readme).read(), re.S) if os.path.exists(readme) else None
    check("README has a verified-install block", m is not None)
    if m:
        block = m.group(1)
        block = re.sub(r"base=\S+", f"base=http://127.0.0.1:{port}", block, count=1)
        block = block.replace(re.search(r"'(ssh-ed25519 AAAA\S+)'", block).group(1), " ".join(pub.split()[:2]))
        def verified(home, **kw):
            work = os.path.join(base, "vwork-" + os.path.basename(home))
            os.makedirs(work)
            os.makedirs(home, exist_ok=True)
            env = {"HOME": home, "PATH": f"{shims}:{os.environ['PATH']}"}
            return subprocess.run(["sh", "-c", block], cwd=work, env=env, capture_output=True, text=True, timeout=60)
        make_release("hercules-agent 0.1.0 (source test)", installer=t)
        r = verified(os.path.join(base, "h10"))
        check("README verified install: runs install.sh after both checks", r.returncode == 0 and "installed:" in r.stdout
              and os.path.exists(os.path.join(base, "h10", ".local", "bin", "hercules-agent")), (r.returncode, r.stdout[-300:], r.stderr[-300:]))
        make_release("hercules-agent 0.1.0 (source test)", installer=t, tamper_installer=True)
        r = verified(os.path.join(base, "h11"))
        check("README verified install: a changed install.sh is never run", r.returncode != 0 and "TAMPERED-INSTALLER-RAN" not in r.stdout
              and "not running it" in r.stderr and not os.path.exists(os.path.join(base, "h11", ".local")), (r.returncode, r.stdout[-300:], r.stderr[-300:]))
        make_release("hercules-agent 0.1.0 (source test)", installer=t, sign_with="other")
        r = verified(os.path.join(base, "h12"))
        check("README verified install: a bad signature stops it before install.sh", r.returncode != 0 and "installed:" not in r.stdout
              and not os.path.exists(os.path.join(base, "h12", ".local")), (r.returncode, r.stdout[-300:], r.stderr[-300:]))
    check("install.sh carries a real release key", not re.search(r'^RELEASE_PUBKEY=".*NOT_SET', text, re.M) and re.search(r'^RELEASE_PUBKEY="ssh-ed25519 AAAA\S+ hercules-release"$', text, re.M))
    srv.shutdown()
finally:
    shutil.rmtree(base, ignore_errors=True)

print(f"\nINSTALL {sum(RESULTS)}/{len(RESULTS)} passed")
sys.exit(0 if all(RESULTS) else 1)
