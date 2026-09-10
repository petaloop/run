#!/bin/bash

set -Eeuo pipefail

test_directory="$(cd -- "$(dirname -- "$0")" && pwd -P)"
repository_root="$(cd -- "${test_directory}/.." && pwd -P)"
process_path="${repository_root}/process.sh"

/bin/bash -n "$process_path"

actual_version="$(/bin/bash "$process_path" --version)"
[[ "$actual_version" == "process.sh 2.0.2" ]] || {
    printf 'process-portability: unexpected version: %s\n' \
        "$actual_version" >&2
    exit 1
}

if LC_ALL=C /usr/bin/grep -En \
    '(^|[[:space:]])chmod[[:space:]]+[0-7]+[[:space:]]+--([[:space:]]|$)' \
    "$process_path"; then
    printf '%s\n' \
        'process-portability: GNU-only chmod operand order detected' >&2
    exit 1
fi

printf '%s\n' 'process-portability: PASS'
