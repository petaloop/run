#!/bin/bash

set -Eeuo pipefail
set +x
umask 077

readonly PROGRAM_NAME="process.sh"
readonly PROCESS_VERSION="2.0.0"
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
LIFECYCLE_FILE_TO_CLEAN=""
DESTINATION_TO_CLEAN=""
DESTINATION_CREATED=0
VERIFIED_GITHUB_KNOWN_HOST=""
PUBLIC_KEY_FINGERPRINT_TO_REPORT=""
PUBLIC_KEY_PRESENTED=0
ENGAGEMENT_COMPLETE=0

# Restrict execution to system-owned tool locations and ignore ambient Git or
# shell configuration that could redirect the repository or substitute hooks.
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
export LC_ALL=C
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_TERMINAL_PROMPT=0
unset BASH_ENV ENV CDPATH GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE
unset GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_COMMON_DIR
unset GIT_CONFIG_PARAMETERS GIT_CONFIG_COUNT GIT_EXEC_PATH GIT_TEMPLATE_DIR
unset GIT_CEILING_DIRECTORIES GIT_DISCOVERY_ACROSS_FILESYSTEM
unset GIT_SSH GIT_SSH_COMMAND GIT_SSH_VARIANT GIT_PROXY_COMMAND
unset SSH_AUTH_SOCK SSH_ASKPASS SSH_ASKPASS_REQUIRE GIT_ASKPASS
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH
unset -f cat chmod date git id mkdir mktemp mv rm rmdir 2>/dev/null || true
unset -f ssh ssh-keygen ssh-keyscan uname 2>/dev/null || true

cleanup() {
    local status="$?"
    local cleanup_ok=1

    if [[ "$ENGAGEMENT_COMPLETE" -ne 1 &&
          ( -n "$KEY_DIRECTORY_TO_CLEAN" ||
            "$DESTINATION_CREATED" -eq 1 ) ]]; then
        if [[ "$DESTINATION_CREATED" -eq 1 ]]; then
            if [[ "$DESTINATION_TO_CLEAN" == \
                  "${HOME}/petaloop-workspaces/fabric" ]]; then
                rm -rf -- "$DESTINATION_TO_CLEAN" || cleanup_ok=0
            else
                cleanup_ok=0
            fi
        fi
        if [[ -n "$KEY_DIRECTORY_TO_CLEAN" ]]; then
            if [[ "$KEY_DIRECTORY_TO_CLEAN" == \
                  "${HOME}/.ssh/petaloop-engagements/engagement."* ]]; then
                rm -rf -- "$KEY_DIRECTORY_TO_CLEAN" || cleanup_ok=0
            else
                cleanup_ok=0
            fi
        fi
        if [[ "$cleanup_ok" -eq 1 ]]; then
            printf '%s\n' \
                "Engagement did not complete; created credentials and private workspace material were removed." >&2
        else
            printf '%s\n' \
                "Engagement did not complete; local cleanup was incomplete. Stop and obtain Principal-directed containment." >&2
        fi
        if [[ "$PUBLIC_KEY_PRESENTED" -eq 1 ]]; then
            printf '%s\n' "If the public key was installed, the Principal must revoke it." >&2
            if [[ -n "$PUBLIC_KEY_FINGERPRINT_TO_REPORT" ]]; then
                printf 'Public-key fingerprint requiring revocation review: %s\n' \
                    "$PUBLIC_KEY_FINGERPRINT_TO_REPORT" >&2
            fi
        fi
    fi
    trap - EXIT
    exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM

die() {
    printf '%s: %s\n' "$PROGRAM_NAME" "$1" >&2
    exit "${2:-1}"
}

usage() {
    cat <<'EOF'
Usage:
  umask 077
  bootstrap_dir="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/petaloop-run.XXXXXX")"
  /usr/bin/curl --disable --proto '=https' --tlsv1.2 --location \
    --proto-redir '=https' --fail --silent --show-error \
    --output "${bootstrap_dir}/process.sh" \
    https://petaloop.run/process.sh
  # Verify the Principal-supplied byte length and SHA-256, then:
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

Information:
  /bin/bash process.sh --help
  /bin/bash process.sh --version

Run only from a private, unrecorded Linux or macOS terminal. The script creates
a local Ed25519 key, displays only its public half and fingerprint for the
Principal, waits for an explicit read-only or read/write authorization signal,
and then opens the private project context.

The engagement key is retained locally after success so the Principal may
authorize later ceremonies. Key possession never supplies task authority.
The Principal must govern rotation and revoke the deploy key when the
engagement ends; the operator must then remove the local credential and clone.

The script never commits or pushes.

The source identity arguments are public provenance values supplied by the
Principal. The script remeasures its own file before network access or key
creation and stops on any mismatch.
EOF
}

require_command() {
    command -v "$1" >/dev/null 2>&1 ||
        die "required command is unavailable: $1" 69
}

mode_and_owner() {
    local path="${1:-}"
    local platform="${2:-}"

    case "$platform" in
        Darwin) stat -f '%Lp %u' "$path" ;;
        Linux) stat -c '%a %u' -- "$path" ;;
        *) die "internal mode-check platform is invalid" 70 ;;
    esac
}

require_owned_plain_directory() {
    local path="${1:-}"
    local label="${2:-directory}"
    local platform="${3:-}"
    local mode_owner
    local mode
    local owner
    local mode_value
    local acl_output
    local acl_line

    [[ -n "$path" && -d "$path" && ! -L "$path" && -O "$path" ]] ||
        die "$label must be a non-symlink directory owned by the current user: $path" 77
    mode_owner="$(mode_and_owner "$path" "$platform")" ||
        die "could not inspect $label permissions" 69
    mode=""
    owner=""
    IFS=' ' read -r mode owner <<<"$mode_owner"
    [[ "$mode" =~ ^[0-7]{3,4}$ && "$owner" == "$(id -u)" ]] ||
        die "$label ownership or mode output was malformed" 77
    mode_value=$((8#$mode))
    (( (mode_value & 0022) == 0 )) ||
        die "$label is group- or world-writable" 77
    if [[ "$platform" == "Darwin" ]]; then
        acl_output="$(ls -lde "$path")" ||
            die "could not inspect $label ACLs" 69
        if [[ "$acl_output" == *$'\n'* ]]; then
            while IFS= read -r acl_line; do
                [[ "$acl_line" != *" allow "* ]] ||
                    die "$label has a permissive access-control entry outside this bootstrap's permission model" 77
            done <<<"$acl_output"
        fi
    fi
}

require_exact_owned_mode() {
    local path="${1:-}"
    local expected="${2:-}"
    local label="${3:-path}"
    local platform="${4:-}"
    local mode_owner
    local mode
    local owner
    local acl_output
    local acl_line

    [[ -n "$path" && ! -L "$path" && -O "$path" ]] ||
        die "$label must be an owned non-symlink path" 77
    mode_owner="$(mode_and_owner "$path" "$platform")" ||
        die "could not inspect $label permissions" 69
    mode=""
    owner=""
    IFS=' ' read -r mode owner <<<"$mode_owner"
    [[ "$mode" == "$expected" && "$owner" == "$(id -u)" ]] ||
        die "$label does not have required mode $expected" 77
    if [[ "$platform" == "Darwin" ]]; then
        acl_output="$(ls -le "$path")" ||
            die "could not inspect $label ACLs" 69
        if [[ "$acl_output" == *$'\n'* ]]; then
            while IFS= read -r acl_line; do
                [[ "$acl_line" != *" allow "* ]] ||
                    die "$label has a permissive access-control entry outside this bootstrap's permission model" 77
            done <<<"$acl_output"
        fi
    fi
}

compute_sha256() {
    local path="${1:-}"
    local output
    local digest
    local remainder

    if command -v shasum >/dev/null 2>&1; then
        output="$(shasum -a 256 -- "$path")" ||
            die "could not hash the bootstrap with shasum" 69
    elif command -v sha256sum >/dev/null 2>&1; then
        output="$(sha256sum -- "$path")" ||
            die "could not hash the bootstrap with sha256sum" 69
    else
        die "no approved SHA-256 command is available" 69
    fi
    [[ -n "$output" && "$output" != *$'\n'* ]] ||
        die "the bootstrap SHA-256 output was malformed" 77
    digest=""
    remainder=""
    IFS=$' \t' read -r digest remainder <<<"$output"
    [[ "$digest" =~ ^[0-9a-f]{64}$ && -n "$remainder" ]] ||
        die "the bootstrap SHA-256 value was malformed" 77
    printf '%s\n' "$digest"
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
        [[ "$#" -eq 1 ]] || die "--help takes no additional arguments" 64
        usage
        exit 0
    fi
    if [[ "${1:-}" == "--version" ]]; then
        [[ "$#" -eq 1 ]] || die "--version takes no additional arguments" 64
        printf '%s %s\n' "$PROGRAM_NAME" "$PROCESS_VERSION"
        exit 0
    fi
    [[ "$#" -eq 8 &&
       "$1" == "--source-commit" &&
       "$3" == "--source-length" &&
       "$5" == "--source-sha256" &&
       "$7" == "--access-mode" ]] ||
        die "first engagement requires the exact Principal-authorized source identity" 64

    [[ "${PETALOOP_CLEAN_LAUNCH:-}" == "1" ]] ||
        die "first engagement requires the documented clean-environment launcher" 77

    local authorized_source_commit="$2"
    local authorized_source_length="$4"
    local authorized_source_sha256="$6"
    local requested_access_mode="$8"
    [[ "$authorized_source_commit" =~ ^[0-9a-f]{40}$ ]] ||
        die "the authorized source commit must be 40 lowercase hexadecimal characters" 64
    [[ "$authorized_source_length" =~ ^[1-9][0-9]*$ ]] ||
        die "the authorized source length must be a positive integer" 64
    [[ "$authorized_source_sha256" =~ ^[0-9a-f]{64}$ ]] ||
        die "the authorized source SHA-256 must be 64 lowercase hexadecimal characters" 64
    [[ "$requested_access_mode" == "READ_ONLY" ||
       "$requested_access_mode" == "READ_WRITE" ]] ||
        die "--access-mode must be exactly READ_ONLY or READ_WRITE" 64

    require_command cat
    require_command chmod
    require_command date
    require_command git
    require_command id
    require_command ls
    require_command mkdir
    require_command mktemp
    require_command rm
    require_command ssh
    require_command ssh-keygen
    require_command ssh-keyscan
    require_command stat
    require_command uname
    require_command wc

    local platform
    platform="$(uname -s)" ||
        die "could not identify the operating system" 69
    case "$platform" in
        Linux|Darwin) ;;
        *) die "this first-engagement process requires Linux or macOS" 69 ;;
    esac

    local invocation_path="$0"
    local invocation_directory
    local invocation_name
    local script_path
    local script_byte_length
    local script_sha256
    invocation_name="${invocation_path##*/}"
    if [[ "$invocation_path" == */* ]]; then
        invocation_directory="${invocation_path%/*}"
    else
        invocation_directory="."
    fi
    invocation_directory="$(cd -- "$invocation_directory" && pwd -P)" ||
        die "could not resolve the bootstrap directory" 69
    script_path="${invocation_directory}/${invocation_name}"
    [[ "$script_path" =~ ^/[A-Za-z0-9._/@+-]+$ ]] ||
        die "the resolved bootstrap path contains unsupported characters" 64
    [[ -f "$script_path" && ! -L "$script_path" && -O "$script_path" ]] ||
        die "the bootstrap must be an owned non-symlink regular file" 77
    require_exact_owned_mode "$invocation_directory" 700 \
        "bootstrap directory" "$platform"
    require_exact_owned_mode "$script_path" 600 \
        "bootstrap file" "$platform"
    script_byte_length="$(wc -c <"$script_path")" ||
        die "could not measure the bootstrap byte length" 69
    script_byte_length="${script_byte_length//[[:space:]]/}"
    [[ "$script_byte_length" =~ ^[1-9][0-9]*$ ]] ||
        die "the measured bootstrap byte length was malformed" 77
    script_sha256="$(compute_sha256 "$script_path")"
    [[ "$script_byte_length" == "$authorized_source_length" ]] ||
        die "the bootstrap byte length does not match the Principal-authorized value" 77
    [[ "$script_sha256" == "$authorized_source_sha256" ]] ||
        die "the bootstrap SHA-256 does not match the Principal-authorized value" 77

    [[ "$(id -u)" -ne 0 ]] ||
        die "refusing to create an agent credential as root" 77
    [[ -n "${HOME:-}" ]] || die "HOME is unavailable" 69
    [[ "$HOME" =~ ^/[A-Za-z0-9._/@+-]+$ ]] ||
        die "HOME contains unsupported characters" 64
    require_owned_plain_directory "$HOME" "HOME" "$platform"
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
    [[ ! -e "$destination_parent" ||
       ( -d "$destination_parent" && ! -L "$destination_parent" ) ]] ||
        die "refusing an unsafe workspace parent" 77
    mkdir -p -- "$destination_parent"
    chmod 700 -- "$destination_parent" ||
        die "could not secure the workspace parent" 73
    require_owned_plain_directory "$destination_parent" "workspace parent" "$platform"

    local ssh_parent="${HOME}/.ssh"
    [[ ! -e "$ssh_parent" ||
       ( -d "$ssh_parent" && ! -L "$ssh_parent" ) ]] ||
        die "refusing an unsafe SSH directory" 77
    mkdir -p -- "$ssh_parent"
    chmod 700 -- "$ssh_parent" ||
        die "could not secure the SSH directory" 73
    require_owned_plain_directory "$ssh_parent" "SSH directory" "$platform"

    local key_parent="${HOME}/.ssh/petaloop-engagements"
    [[ ! -e "$key_parent" ||
       ( -d "$key_parent" && ! -L "$key_parent" ) ]] ||
        die "refusing an unsafe engagement-key parent" 77
    mkdir -p -- "$key_parent"
    chmod 700 -- "$key_parent" ||
        die "could not secure the engagement-key parent" 73
    require_owned_plain_directory "$key_parent" "engagement-key parent" "$platform"

    local key_directory
    key_directory="$(mktemp -d "${key_parent}/engagement.XXXXXX")" ||
        die "could not create the local key directory" 73
    KEY_DIRECTORY_TO_CLEAN="$key_directory"
    chmod 700 -- "$key_directory" ||
        die "could not secure the local key directory" 73
    require_owned_plain_directory "$key_directory" "engagement-key directory" "$platform"

    local key_file="${key_directory}/id_ed25519"
    local public_key="${key_file}.pub"
    local host_key_file="${key_directory}/github_known_hosts"
    local lifecycle_file="${key_directory}/engagement.json"
    local hooks_directory="${key_directory}/empty-hooks"
    KEY_FILE_TO_CLEAN="$key_file"
    PUBLIC_KEY_TO_CLEAN="$public_key"
    HOST_KEY_FILE_TO_CLEAN="$host_key_file"
    LIFECYCLE_FILE_TO_CLEAN="$lifecycle_file"
    mkdir -- "$hooks_directory" ||
        die "could not create the isolated empty-hooks directory" 73
    chmod 700 -- "$hooks_directory" ||
        die "could not secure the isolated empty-hooks directory" 73
    require_owned_plain_directory "$hooks_directory" "empty-hooks directory" "$platform"
    local public_type
    local public_body
    local public_comment
    local derived_public
    local public_fingerprint_output
    local public_fingerprint_bits
    local public_fingerprint
    local public_fingerprint_detail
    local created_at
    local authorized_at
    local confirmation
    local access_mode
    local access_mode_evidence
    local expected_read_only_signal
    local expected_read_write_signal
    local ssh_command
    local notes_status
    local workspace
    local workspace_head
    local destination_quoted
    local key_directory_quoted
    local lifecycle_file_quoted

    created_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" ||
        die "could not create the engagement timestamp" 69

    printf '%s\n' "$initial_verified_github_host" >"$host_key_file" ||
        die "could not create the isolated GitHub host-trust file" 73
    chmod 600 -- "$host_key_file" ||
        die "could not secure the isolated GitHub host-trust file" 73
    require_exact_owned_mode "$host_key_file" 600 \
        "GitHub host-trust file" "$platform"

    ssh-keygen -q -t ed25519 -a 100 -N '' -C '' -f "$key_file" ||
        die "ssh-keygen failed" 70
    chmod 600 -- "$key_file" "$public_key" ||
        die "could not secure the generated key pair" 73
    require_exact_owned_mode "$key_file" 600 "private key" "$platform"
    require_exact_owned_mode "$public_key" 600 "public key" "$platform"

    IFS=' ' read -r public_type public_body public_comment <"$public_key" ||
        die "could not read the generated public key" 65
    derived_public="$(ssh-keygen -y -P '' -f "$key_file")" ||
        die "could not derive the generated public key" 65
    [[ "$derived_public" == ssh-ed25519\ * &&
       "$derived_public" == "${public_type} ${public_body}" &&
       -z "${public_comment:-}" ]] ||
        die "the generated Ed25519 key pair is invalid" 65

    public_fingerprint_output="$(
        LC_ALL=C ssh-keygen -l -E sha256 -f "$public_key" 2>/dev/null
    )" ||
        die "could not fingerprint the generated public key" 65
    [[ -n "$public_fingerprint_output" &&
       "$public_fingerprint_output" != *$'\n'* ]] ||
        die "the generated public-key fingerprint output was malformed" 65
    public_fingerprint_bits=""
    public_fingerprint=""
    public_fingerprint_detail=""
    IFS=$' \t' read -r \
        public_fingerprint_bits public_fingerprint public_fingerprint_detail \
        <<<"$public_fingerprint_output"
    [[ "$public_fingerprint_bits" == "256" &&
       "$public_fingerprint" == SHA256:* &&
       -n "$public_fingerprint_detail" ]] ||
        die "the generated public-key fingerprint was malformed" 65
    PUBLIC_KEY_FINGERPRINT_TO_REPORT="$public_fingerprint"
    expected_read_only_signal="AUTHORIZED_READ_ONLY ${PRIVATE_REPOSITORY} ${public_fingerprint}"
    expected_read_write_signal="AUTHORIZED_READ_WRITE ${PRIVATE_REPOSITORY} ${public_fingerprint}"

    PUBLIC_KEY_PRESENTED=1
    cat >&3 <<EOF

============================================================
PETALOOP FIRST-ENGAGEMENT REQUEST v${PROCESS_VERSION}
============================================================

STATE: WAITING_FOR_PRINCIPAL_ACTION

REPOSITORY
${PRIVATE_REPOSITORY}

PRINCIPAL ACTION
  The invoking task requested this repository access mode:

      ${requested_access_mode}

  Install the public key only if that mode matches the task and the minimum
  capability required. READ_ONLY is recommended for verification, review, and
  ordinary context use. READ_WRITE requires a separate task grant expressly
  calling for repository mutation.

PUBLIC KEY — BEGIN
${derived_public}
PUBLIC KEY — END

PUBLIC KEY FINGERPRINT
${public_fingerprint}

HANDLING
  Show this request only to the Principal through this private terminal.
  Never place it in chat, email, Git, Git notes, logs, transcripts, screenshots,
  issues, pull requests, or any public location.

PRINCIPAL SIGNAL
  After installing the key with the requested permission, the Principal must
  explicitly return the matching signal displayed below:
EOF

    if [[ "$requested_access_mode" == "READ_ONLY" ]]; then
        printf '      %s\n' "$expected_read_only_signal" >&3
    else
        printf '      %s\n' "$expected_read_write_signal" >&3
    fi

    cat >&3 <<EOF

  Each signal is bound to this repository and generated key fingerprint. Do
  not proceed on silence, a signal for another key, or any other message.

AUTHORITY EFFECT
  The selected signal authorizes repository access in that mode only.
  TASK AUTHORITY: NONE
  WRITE ACTION AUTHORITY: NONE
EOF

    IFS= read -r -p \
        "After receiving the Principal's signal, type it exactly: " \
        confirmation <&3 ||
        die "terminal input ended before authorization confirmation" 75
    if [[ "$requested_access_mode" == "READ_ONLY" &&
          "$confirmation" == "$expected_read_only_signal" ]]; then
        access_mode="READ_ONLY"
        access_mode_evidence="PRINCIPAL_ATTESTED_READ_ONLY"
    elif [[ "$requested_access_mode" == "READ_WRITE" &&
            "$confirmation" == "$expected_read_write_signal" ]]; then
        access_mode="READ_WRITE"
        access_mode_evidence="PRINCIPAL_ATTESTED_READ_WRITE"
    else
        die "authorization did not match this repository key and an accepted access mode" 75
    fi
    authorized_at="$(date -u '+%Y-%m-%dT%H:%M:%SZ')" ||
        die "could not create the authorization timestamp" 69

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
    mkdir -- "$destination" ||
        die "clone destination appeared or could not be reserved" 73
    DESTINATION_TO_CLEAN="$destination"
    DESTINATION_CREATED=1
    chmod 700 -- "$destination" ||
        die "could not secure the clone destination" 73
    require_owned_plain_directory "$destination" "clone destination" "$platform"
    workspace="$destination"

    GIT_SSH_COMMAND="$ssh_command" \
        git -c init.templateDir= \
            -c core.hooksPath="$hooks_directory" \
            -c protocol.file.allow=never \
            clone --no-checkout --no-tags --single-branch --branch main -- \
            "$PRIVATE_REPOSITORY" "$workspace" ||
        die "clone failed; ask the Principal to verify authorization and host trust" 69

    [[ "$(git -C "$workspace" remote get-url origin)" == \
       "$PRIVATE_REPOSITORY" ]] ||
        die "the cloned origin URL differs from the fixed private repository" 77

    git -C "$workspace" config --local core.sshCommand "$ssh_command"
    git -C "$workspace" config --local core.hooksPath "$hooks_directory"
    git -C "$workspace" config --local push.default nothing
    git -C "$workspace" config --local remote.origin.tagOpt --no-tags
    git -C "$workspace" config --local petaloop.processVersion \
        "$PROCESS_VERSION"
    git -C "$workspace" config --local petaloop.accessMode "$access_mode"
    git -C "$workspace" config --local petaloop.accessModeEvidence \
        "$access_mode_evidence"
    git -C "$workspace" config --local petaloop.publicKeyFingerprint \
        "$public_fingerprint"
    if [[ "$access_mode" == "READ_ONLY" ]]; then
        git -C "$workspace" config --local remote.origin.pushurl \
            'disabled://petaloop-read-only-engagement'
    fi
    git -C "$workspace" config --local notes.displayRef \
        'refs/notes/remotes/origin/*'
    git -C "$workspace" config --local --add remote.origin.fetch \
        '+refs/notes/*:refs/notes/remotes/origin/*'

    {
        printf '\n# Local-only safety exclusions installed by petaloop/run\n'
        printf '.DS_Store\nThumbs.db\ntarget/\n**/target/\n*.rs.bk\n'
        printf '.env\n.env.*\n*.pem\n*.key\nid_rsa*\nid_ed25519*\n'
    } >>"$workspace/.git/info/exclude"

    if git -C "$workspace" ls-remote --exit-code --refs \
        origin 'refs/notes/*' >/dev/null; then
        git -C "$workspace" fetch --no-tags origin \
            '+refs/notes/*:refs/notes/remotes/origin/*'
    else
        notes_status="$?"
        [[ "$notes_status" -eq 2 ]] ||
            die "could not query the private project notes" 69
    fi

    git -C "$workspace" checkout --detach origin/main ||
        die "could not create the private read-only context checkout" 69

    workspace_head="$(git -C "$destination" rev-parse --verify 'HEAD^{commit}')" ||
        die "could not identify the retained private workspace commit" 69
    [[ "$workspace_head" =~ ^[0-9a-f]{40}$ ]] ||
        die "the retained private workspace commit identity was malformed" 77

    cat >"$lifecycle_file" <<EOF
{
  "schema_version": "1.0.0",
  "process_version": "${PROCESS_VERSION}",
  "clean_environment_launcher": "REQUIRED_AND_PRESENT",
  "authorized_source_commit": "${authorized_source_commit}",
  "authorized_source_byte_length": ${authorized_source_length},
  "authorized_source_sha256": "${authorized_source_sha256}",
  "executed_source_path": "${script_path}",
  "executed_source_byte_length": ${script_byte_length},
  "executed_source_sha256": "${script_sha256}",
  "repository": "${PRIVATE_REPOSITORY}",
  "platform": "${platform}",
  "requested_access_mode": "${requested_access_mode}",
  "access_mode": "${access_mode}",
  "access_mode_evidence": "${access_mode_evidence}",
  "public_key_fingerprint": "${public_fingerprint}",
  "github_host_fingerprint": "${GITHUB_ED25519_FINGERPRINT}",
  "private_key_path": "${key_file}",
  "public_key_path": "${public_key}",
  "host_trust_path": "${host_key_file}",
  "workspace_path": "${destination}",
  "workspace_head": "${workspace_head}",
  "created_at": "${created_at}",
  "authorized_at": "${authorized_at}",
  "credential_state": "RETAINED_LOCAL",
  "private_key_at_rest": "FILE_MODE_0600_NO_PASSPHRASE",
  "automatic_expiry": "NONE_REQUIRES_PRINCIPAL_REVOCATION",
  "task_authority": "NONE",
  "write_action_authority": "NONE_UNTIL_SEPARATE_TASK_GRANT",
  "revocation_order": "PRINCIPAL_REVOKES_GITHUB_DEPLOY_KEY_THEN_OPERATOR_REMOVES_LOCAL_KEY_AND_WORKSPACE"
}
EOF
    chmod 600 -- "$lifecycle_file" ||
        die "could not secure the credential lifecycle record" 73
    require_exact_owned_mode "$lifecycle_file" 600 \
        "credential lifecycle record" "$platform"

    printf -v destination_quoted '%q' "$destination"
    printf -v key_directory_quoted '%q' "$key_directory"
    printf -v lifecycle_file_quoted '%q' "$lifecycle_file"
    cat >&3 <<EOF

============================================================
FIRST ENGAGEMENT
============================================================

Private access is established.

Process version: ${PROCESS_VERSION}
Authorized source commit: ${authorized_source_commit}
Executed source byte length: ${script_byte_length}
Executed source SHA-256: ${script_sha256}
Principal-authorized access mode: ${access_mode_evidence}
Public-key fingerprint: ${public_fingerprint}
Private workspace HEAD: ${workspace_head}
TASK AUTHORITY: NONE
WRITE ACTION AUTHORITY: NONE UNTIL A SEPARATE MATCHING TASK GRANT

1. Enter the private working copy:

     cd -- ${destination_quoted}

2. Possession of this key and working copy grants no task authority. Do not
   change, commit, or push anything without a separate matching task grant.

3. Read the private repository's project documentation and local instructions.

4. Enumerate and read its Git-note channels:

     git fetch origin '+refs/notes/*:refs/notes/remotes/origin/*'
     git for-each-ref --format='%(refname)' refs/notes/remotes/origin/

5. Acquire objectives, task-selection rules, supervision state, communication
   protocol, validation requirements, and stop conditions only from that
   private content.

6. If private instructions or required notes are absent, ambiguous, or
   contradictory, stop and ask the Principal.

7. The engagement key is retained locally at:

     ${key_directory_quoted}

   The local credential lifecycle record is:

     ${lifecycle_file_quoted}

   Protect this directory. When the Principal ends the engagement, revoke the
   deploy key in GitHub and securely remove this directory and any retained
   private working copy. For retained read-only access, every later operation
   still requires its own task authorization.

The public bootstrap grants no task and supplies no project authority.
It made no commit and performed no push. The access mode above is a
Principal-supplied authorization statement; the script does not infer broader
authority from successful authentication.
EOF

    ENGAGEMENT_COMPLETE=1
}

main "$@"
