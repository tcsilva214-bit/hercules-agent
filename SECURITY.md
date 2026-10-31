# Security

HERCULES is a harness whose job is to keep a model inside fixed limits, so security reports are welcome.

## Reporting

Please report privately through GitHub: on this repository, open the **Security** tab and choose
**Report a vulnerability**. Do not open a public issue for a security problem.

Include the build (`hercules-agent --version` prints the version and source digest), your platform, the
config (with any key file paths and endpoints removed) and the smallest transcript or steps that show the
problem.

## In scope

- Reading a path outside the granted roots, or a deny-listed path, by any route (symlinks, `..`, races,
  command arguments, relative paths, resume).
- Running anything `cmd.run` should refuse: a command that is not enabled, arguments outside a command's
  grammar, or any shell behavior.
- Model output being acted on without passing the tool protocol, validation and the authority decision.
- An approval used for a different session, request, capability, argument set, after expiry, or twice.
- Forging or editing a signed run's transcript, receipt, final answer, evidence report, manifest or
  attestation in a way `attest verify` does not report as a MISMATCH; a signature accepted under a key
  that did not make it; a mission that finishes without writing its attestation (a crash aside).
- The signing key's contents appearing anywhere HERCULES writes, or a model being able to read it.
- A secret (an API key, a key file's content) appearing in a transcript, report, error or `inspect` output.
- The write lane: a proposal reaching a file without `change apply`; apply writing anything outside the
  approved changeset or outside the write roots (including through a link), or going ahead after a file
  drifted from its base; rollback overwriting a file that changed after apply; an interrupted apply or
  rollback that `change recover` cannot put back; two change commands changing the same proposal or the same
  write root at once; recover acting on a journal not signed by the operator's key.
- Releases: `install.sh` installing an archive whose signature or checksum does not verify; a release
  signed although its macOS arm64 binary does not reproduce, or an archive lacks a valid build attestation.
- A crash or hang a model response or an MCP client message can trigger.
- An MCP client reaching any tool other than the offered read tools, reading outside the granted roots, or
  getting text that differs from what its receipt hashes.

## Out of scope

- What a model says in its final answer (HERCULES reports how well it is grounded; it does not make it
  true).
- Problems that need an attacker who can already edit the operator's config, key files or the binary.
  A signature proves that the holder of the key made the files; someone holding the key can sign anything.

## Supported versions

This repository is a labeled showcase snapshot. Fixes are made in the main line and appear here with the
next published build.
