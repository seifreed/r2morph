#!/usr/bin/env bash

set -euo pipefail

readonly version="6.2.0"
readonly source_url="https://github.com/radareorg/radare2.git"
readonly destination="/tmp/radare2"
readonly max_attempts=3

rm -rf "$destination"

cloned=false
for attempt in $(seq 1 "$max_attempts"); do
    if git clone --depth 1 --branch "$version" "$source_url" "$destination"; then
        cloned=true
        break
    fi
    rm -rf "$destination"
    if [[ "$attempt" -lt "$max_attempts" ]]; then
        sleep $((attempt * 10))
    fi
done

if [[ "$cloned" != true ]]; then
    printf 'Unable to clone radare2 after %s attempts.\n' "$max_attempts" >&2
    exit 1
fi

cd "$destination"
./sys/install.sh
