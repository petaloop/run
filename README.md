# Petaloop Run

Petaloop Run process 2.0.0 establishes a Principal-mediated first engagement
with the private `petaloop/fabric` repository from a private, unrecorded Linux
or macOS terminal.

## Controlled bootstrap

Run the bootstrap only at the Principal's invitation. Download first; never
stream moving network bytes directly into a shell for a controlled ceremony:

```bash
umask 077
bootstrap_dir="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/petaloop-run.XXXXXX")"
/usr/bin/curl --disable --proto '=https' --tlsv1.2 --location \
  --proto-redir '=https' --fail --silent --show-error \
  --output "${bootstrap_dir}/process.sh" \
  https://petaloop.run/process.sh
```

Obtain the authorized source commit, exact byte length, and SHA-256 from the
Principal through the governed channel. Verify all three before execution. A
digest served only beside the mutable script is not an independent trust root.
Then use the system Bash without ambient startup files, passing those exact
public provenance values back to the bootstrap:

```bash
/usr/bin/env -i HOME="${HOME}" TERM="${TERM:-dumb}" \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin PETALOOP_CLEAN_LAUNCH=1 \
  /bin/bash -n "${bootstrap_dir}/process.sh"
/usr/bin/env -i HOME="${HOME}" TERM="${TERM:-dumb}" \
  PATH=/usr/bin:/bin:/usr/sbin:/sbin PETALOOP_CLEAN_LAUNCH=1 /bin/bash \
  "${bootstrap_dir}/process.sh" \
  --source-commit <40-lowercase-hex> \
  --source-length <positive-byte-count> \
  --source-sha256 <64-lowercase-hex> \
  --access-mode <READ_ONLY-or-READ_WRITE>
```

The clean launcher prevents inherited shell functions and unrelated environment
configuration from shadowing security-critical commands before verification.
The script rejects engagement execution without that launcher. It also requires
the bootstrap directory and file to be owned, non-symlink, mode 0700/0600, and
free of permissive macOS ACLs.

The script resolves its own file, recomputes its byte length and SHA-256 before
network access or key creation, requires equality with the Principal-authorized
values, and records both values in the local lifecycle record. The commit is
Principal-supplied provenance; the byte identity is the locally enforced input.

The environment must be non-root and supply system Bash, Git, and OpenSSH 6.8
or newer. The script restricts its runtime path and ignores ambient system and
global Git configuration. It rejects unsafe or symlinked engagement parents.

## Host and credential trust

Before generating a credential, the process verifies GitHub's presented
Ed25519 host identity against
[GitHub's published fingerprint](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints).
It repeats that check after authorization and requires the two observed host
keys to agree. The verified host key is stored only in an isolated engagement
trust file; user and system SSH trust stores are not modified.

The process creates an unencrypted Ed25519 key in a mode-0700 engagement
directory and presents only its public half and SHA-256 fingerprint. The
private key is never displayed. The exact Principal signal is bound to:

- the selected permission;
- `git@github.com:petaloop/fabric.git`; and
- the generated public-key fingerprint.

The invocation requests exactly one access mode. The script displays only its
matching repository-and-fingerprint-bound signal. Read-only is recommended for
verification, review, and ordinary context access. Read/write is appropriate
only when a separate task expressly requires repository mutation. The
Principal must install the deploy key with the same permission named by the
request and returned signal, or decline the request.

The permission signal grants repository capability only. It grants no task,
commit, push, Git-note, release, deployment, or publication authority. The
private repository supplies its own task-acquisition and authorization rules
after access is established.

## Retention and revocation

Successful engagement retains the key, isolated host-trust file, lifecycle
record, and private working copy for later separately authorized ceremonies.
The lifecycle record identifies the repository, process version, platform,
Principal-attested access mode, public-key fingerprint, paths, timestamps,
host fingerprint, and zero task authority. It never contains private-key bytes
or the raw authorization transcript.

GitHub deploy keys do not expire automatically. The Principal governs rotation
and revocation. When engagement ends or compromise is suspected, revoke the
GitHub deploy key first, then remove the local engagement directory and private
working copy. Local deletion is not remote revocation. Permission escalation,
repository changes, rotation, or a replacement engagement require a new key
and a new fingerprint-bound Principal signal.

If engagement fails, the process removes the exact credential and workspace
paths it created. If the public key may have been installed, it reports the
fingerprint that the Principal must inspect and revoke. `SIGKILL`, power loss,
hostile same-user races, and a compromised host or system toolchain remain
outside what a Bash cleanup trap can guarantee.

## Context boundary

This public repository intentionally supplies no private project context. Once
authorized, the private repository may be read within the granted access mode.
Repository content and Git notes can provide project rules, objectives, and
task-selection procedures, but possession of the clone or credential never
creates task authority. Ambiguous, missing, or conflicting private instructions
require a stop and Principal resolution.
