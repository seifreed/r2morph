#!/usr/bin/env bash

set -euo pipefail

readonly version="6.2.2"
readonly source_url="https://github.com/radareorg/radare2.git"
readonly destination="/tmp/radare2"
readonly max_attempts=3

configure_git_ca_bundle() {
    local ca_bundle
    for ca_bundle in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem; do
        if [[ -r "$ca_bundle" ]]; then
            export GIT_SSL_CAINFO="$ca_bundle"
            git config --global http.sslCAInfo "$ca_bundle"
            return
        fi
    done
}

configure_git_ca_bundle

if [[ "$(uname -s)" == "Linux" && "$(uname -m)" == "x86_64" ]]; then
    package="/tmp/radare2-${version}-amd64.deb"
    curl --fail --location --retry 3 --retry-all-errors --max-time 120 \
        "https://github.com/radareorg/radare2/releases/download/${version}/radare2_${version}_amd64.deb" \
        --output "$package"
    printf '%s  %s\n' "09234e4139bf8dfcbb7fc1fdb2519859ad516e63c19d3c27d92aaecdf463b1ad" "$package" \
        | sha256sum --check --status
    sudo apt-get install -y "$package"
    r2 -v
    exit 0
fi

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
