#!/usr/bin/env bash

set -Eeuo pipefail
set +x
umask 077

readonly PROGRAM_NAME="process.sh"
readonly PRIVATE_REPOSITORY="git@github.com:petaloop/fabric.git"
readonly GITHUB_SSH_HOST="github.com"
readonly GITHUB_SSH_PORT="22"
# Public trust anchor published at:
# https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
readonly GITHUB_ED25519_FINGERPRINT="SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU"

KEY_DIRECTORY_TO_CLEAN=""
KEY_FILE_TO_CLEAN=""
PUBLIC_KEY_TO_CLEAN=""
HOST_KEY_FILE_TO_CLEAN=""
VERIFIED_GITHUB_KNOWN_HOST=""
PUBLIC_KEY_PRESENTED=0
ENGAGEMENT_COMPLETE=0

cleanup() {
    local status="$?"
    local cleanup_ok=1

    if [[ "$ENGAGEMENT_COMPLETE" -ne 1 &&
          -n "$KEY_DIRECTORY_TO_CLEAN" ]]; then
        rm -f -- \
            "$KEY_FILE_TO_CLEAN" \
            "$PUBLIC_KEY_TO_CLEAN" \
            "$HOST_KEY_FILE_TO_CLEAN" ||
            cleanup_ok=0
        rmdir -- "$KEY_DIRECTORY_TO_CLEAN" 2>/dev/null ||
            cleanup_ok=0
        if [[ "$cleanup_ok" -eq 1 ]]; then
            printf '%s\n' \
                "Engagement did not complete; local engagement material was removed." >&2
        else
            printf '%s\n' \
                "Engagement did not complete; local engagement cleanup was incomplete." >&2
        fi
        if [[ "$PUBLIC_KEY_PRESENTED" -eq 1 ]]; then
            printf '%s\n' \
                "If the public key was installed, the Principal must revoke it." >&2
        fi
    fi
    trap - EXIT
    exit "$status"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

die() {
    printf '%s: %s\n' "$PROGRAM_NAME" "$1" >&2
    exit "${2:-1}"
}

usage() {
    cat <<'EOF'
Usage:
  curl -fsSL https://petaloop.run/process.sh | bash

Optional downloaded-script form:
  bash process.sh

Run only from a private, unrecorded Linux terminal. The script creates a local
Ed25519 key, displays only its public half for the Principal, waits for manual
authorization, and then opens the private project context.

It never commits or pushes.
EOF
}

require_command() {
    command -v "$1" >/dev/null 2>&1 ||
        die "required command is unavailable: $1" 69
}

verify_github_host() {
    local phase="${1:-}"
    local failure_suffix=""
    local scan_output
    local line
    local field1=""
    local field2=""
    local field3=""
    local field4=""
    local verified_body=""
    local fingerprint_output
    local fingerprint_bits=""
    local fingerprint_value=""
    local fingerprint_detail=""
    local scan_found=0

    [[ "$phase" == "before-key" || "$phase" == "after-authorization" ]] ||
        die "internal host-verification phase is invalid" 70
    if [[ "$phase" == "before-key" ]]; then
        failure_suffix="; no deploy key was created"
    fi

    VERIFIED_GITHUB_KNOWN_HOST=""
    scan_output="$(
        LC_ALL=C ssh-keyscan -T 10 -p "$GITHUB_SSH_PORT" \
            -t ed25519 "$GITHUB_SSH_HOST" 2>/dev/null
    )" ||
        die "could not retrieve GitHub's SSH host identity${failure_suffix}" 69
    [[ -n "$scan_output" ]] ||
        die "GitHub returned no SSH host identity${failure_suffix}" 69

    while IFS= read -r line; do
        [[ -n "$line" && "$line" != \#* ]] || continue
        field1=""
        field2=""
        field3=""
        field4=""
        IFS=$' \t' read -r field1 field2 field3 field4 <<<"$line"
        [[ ( "$field1" == "$GITHUB_SSH_HOST" ||
             "$field1" == "[${GITHUB_SSH_HOST}]:${GITHUB_SSH_PORT}" ) &&
           "$field2" == "ssh-ed25519" &&
           -n "$field3" &&
           -z "$field4" ]] ||
            die "GitHub returned a malformed or unexpected SSH host identity${failure_suffix}" 77

        fingerprint_output="$(
            printf '%s %s\n' "$field2" "$field3" |
                LC_ALL=C ssh-keygen -l -E sha256 -f - 2>/dev/null
        )" ||
            die "could not fingerprint GitHub's SSH host identity; OpenSSH 6.8 or newer is required${failure_suffix}" 69
        [[ -n "$fingerprint_output" &&
           "$fingerprint_output" != *$'\n'* ]] ||
            die "GitHub's SSH host fingerprint output was malformed${failure_suffix}" 77

        fingerprint_bits=""
        fingerprint_value=""
        fingerprint_detail=""
        IFS=$' \t' read -r \
            fingerprint_bits fingerprint_value fingerprint_detail \
            <<<"$fingerprint_output"
        [[ "$fingerprint_bits" == "256" &&
           "$fingerprint_value" == "$GITHUB_ED25519_FINGERPRINT" &&
           -n "$fingerprint_detail" ]] ||
            die "GitHub's SSH host identity does not match the pinned official fingerprint${failure_suffix}" 77

        if [[ -z "$verified_body" ]]; then
            verified_body="$field3"
        else
            [[ "$verified_body" == "$field3" ]] ||
                die "GitHub returned inconsistent SSH host identities${failure_suffix}" 77
        fi
        scan_found=$((scan_found + 1))
    done <<<"$scan_output"

    [[ "$scan_found" -gt 0 && -n "$verified_body" ]] ||
        die "GitHub returned no usable SSH host identity${failure_suffix}" 69
    VERIFIED_GITHUB_KNOWN_HOST="${GITHUB_SSH_HOST} ssh-ed25519 ${verified_body}"
}

main() {
    if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
        usage
        exit 0
    fi
    [[ "$#" -eq 0 ]] || die "this first-engagement process takes no arguments" 64
    [[ "$(uname -s)" == "Linux" ]] ||
        die "this first-engagement process requires Linux" 69

    require_command git
    require_command id
    require_command mktemp
    require_command rm
    require_command rmdir
    require_command ssh
    require_command ssh-keygen
    require_command ssh-keyscan

    [[ "$(id -u)" -ne 0 ]] ||
        die "refusing to create an agent credential as root" 77
    [[ -n "${HOME:-}" ]] || die "HOME is unavailable" 69
    [[ "$HOME" =~ ^/[A-Za-z0-9._/@+-]+$ ]] ||
        die "HOME contains unsupported characters" 64
    [[ -r /dev/tty && -w /dev/tty && -t 1 && -t 2 ]] ||
        die "a private interactive terminal is required" 75
    exec 3<>/dev/tty ||
        die "could not open the private interactive terminal" 75

    verify_github_host before-key
    local initial_verified_github_host="$VERIFIED_GITHUB_KNOWN_HOST"

    local destination="${HOME}/petaloop-workspaces/fabric"
    [[ "$destination" != "/" &&
       "$destination" != "${HOME}/.ssh" &&
       "$destination" != "${HOME}/.ssh/"* ]] ||
        die "unsafe clone destination" 77
    [[ ! -e "$destination" && ! -L "$destination" ]] ||
        die "clone destination already exists: $destination" 73

    local destination_parent="${destination%/*}"
    [[ -n "$destination_parent" ]] || destination_parent="/"
    mkdir -p -- "$destination_parent"

    local key_parent="${HOME}/.ssh/petaloop-engagements"
    [[ ! -L "$key_parent" ]] ||
        die "refusing a symbolic-link key directory" 77
    mkdir -p -- "$key_parent"
    chmod 700 -- "$key_parent"

    local key_directory
    key_directory="$(mktemp -d "${key_parent}/engagement.XXXXXX")" ||
        die "could not create the local key directory" 73
    chmod 700 -- "$key_directory"
    KEY_DIRECTORY_TO_CLEAN="$key_directory"

    local key_file="${key_directory}/id_ed25519"
    local public_key="${key_file}.pub"
    local host_key_file="${key_directory}/github_known_hosts"
    KEY_FILE_TO_CLEAN="$key_file"
    PUBLIC_KEY_TO_CLEAN="$public_key"
    HOST_KEY_FILE_TO_CLEAN="$host_key_file"
    local public_type
    local public_body
    local public_comment
    local derived_public
    local confirmation
    local ssh_command
    local notes_status
    local destination_quoted

    printf '%s\n' "$initial_verified_github_host" >"$host_key_file" ||
        die "could not create the isolated GitHub host-trust file" 73
    chmod 600 -- "$host_key_file" ||
        die "could not secure the isolated GitHub host-trust file" 73

    ssh-keygen -q -t ed25519 -a 100 -N '' -C '' -f "$key_file" ||
        die "ssh-keygen failed" 70
    chmod 600 -- "$key_file" "$public_key"

    IFS=' ' read -r public_type public_body public_comment <"$public_key" ||
        die "could not read the generated public key" 65
    derived_public="$(ssh-keygen -y -P '' -f "$key_file")" ||
        die "could not derive the generated public key" 65
    [[ "$derived_public" == ssh-ed25519\ * &&
       "$derived_public" == "${public_type} ${public_body}" &&
       -z "${public_comment:-}" ]] ||
        die "the generated Ed25519 key pair is invalid" 65

    PUBLIC_KEY_PRESENTED=1
    cat >&3 <<EOF

============================================================
PETALOOP FIRST-ENGAGEMENT REQUEST v1
============================================================

STATE: WAITING_FOR_PRINCIPAL_ACTION

PRINCIPAL ACTION
  Install the public key below as a write-enabled deploy key for the private
  project repository.

PUBLIC KEY — BEGIN
${derived_public}
PUBLIC KEY — END

HANDLING
  Show this request only to the Principal through this private terminal.
  Never place it in chat, email, Git, Git notes, logs, transcripts, screenshots,
  issues, pull requests, or any public location.

PRINCIPAL SIGNAL
  After installing the key, the Principal must explicitly signal:

      AUTHORIZED

  Do not proceed on silence or on any other message.
EOF

    IFS= read -r -p \
        "After receiving the Principal's signal, type AUTHORIZED: " \
        confirmation <&3 ||
        die "terminal input ended before authorization confirmation" 75
    [[ "$confirmation" == "AUTHORIZED" ]] ||
        die "authorization was not confirmed" 75

    verify_github_host after-authorization
    [[ "$VERIFIED_GITHUB_KNOWN_HOST" == "$initial_verified_github_host" ]] ||
        die "GitHub's verified SSH host identity changed during authorization" 77

    ssh_command="ssh -F /dev/null -i ${key_file}"
    ssh_command+=" -o HostName=${GITHUB_SSH_HOST}"
    ssh_command+=" -o HostKeyAlias=${GITHUB_SSH_HOST}"
    ssh_command+=" -o Port=${GITHUB_SSH_PORT}"
    ssh_command+=" -o HostKeyAlgorithms=ssh-ed25519"
    ssh_command+=" -o UserKnownHostsFile=${host_key_file}"
    ssh_command+=" -o GlobalKnownHostsFile=/dev/null"
    ssh_command+=" -o CheckHostIP=no -o CanonicalizeHostname=no"
    ssh_command+=" -o ProxyCommand=none"
    ssh_command+=" -o IdentitiesOnly=yes -o BatchMode=yes"
    ssh_command+=" -o PreferredAuthentications=publickey"
    ssh_command+=" -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no"
    ssh_command+=" -o StrictHostKeyChecking=yes -o UpdateHostKeys=no"
    ssh_command+=" -o VerifyHostKeyDNS=no"
    ssh_command+=" -o ForwardAgent=no -o ClearAllForwardings=yes"
    GIT_TERMINAL_PROMPT=0 GIT_SSH_COMMAND="$ssh_command" \
        git clone -- "$PRIVATE_REPOSITORY" "$destination" ||
        die "clone failed; ask the Principal to verify authorization and host trust" 69

    git -C "$destination" config --local core.sshCommand "$ssh_command"
    git -C "$destination" config --local push.default nothing
    git -C "$destination" config --local notes.displayRef \
        'refs/notes/remotes/origin/*'
    git -C "$destination" config --local --add remote.origin.fetch \
        '+refs/notes/*:refs/notes/remotes/origin/*'

    {
        printf '\n# Local-only safety exclusions installed by petaloop/run\n'
        printf '.DS_Store\nThumbs.db\ntarget/\n**/target/\n*.rs.bk\n'
        printf '.env\n.env.*\n*.pem\n*.key\nid_rsa*\nid_ed25519*\n'
    } >>"$destination/.git/info/exclude"

    if git -C "$destination" ls-remote --exit-code --refs \
        origin 'refs/notes/*' >/dev/null; then
        git -C "$destination" fetch --no-tags origin \
            '+refs/notes/*:refs/notes/remotes/origin/*'
    else
        notes_status="$?"
        [[ "$notes_status" -eq 2 ]] ||
            die "could not query the private project notes" 69
    fi

    printf -v destination_quoted '%q' "$destination"
    cat >&3 <<EOF

============================================================
FIRST ENGAGEMENT
============================================================

Private access is established.

1. Enter the private working copy:

     cd -- ${destination_quoted}

2. Do not change, commit, or push anything yet.

3. Read the private repository's project documentation and local instructions.

4. Enumerate and read its Git-note channels:

     git fetch origin '+refs/notes/*:refs/notes/remotes/origin/*'
     git for-each-ref --format='%(refname)' refs/notes/remotes/origin/

5. Acquire objectives, task-selection rules, supervision state, communication
   protocol, validation requirements, and stop conditions only from that
   private content.

6. If private instructions or required notes are absent, ambiguous, or
   contradictory, stop and ask the Principal.

The public bootstrap grants no task and supplies no project authority.
It made no commit and performed no push.
EOF

    ENGAGEMENT_COMPLETE=1
}

main "$@"
