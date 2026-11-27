#!/usr/bin/env bash
# Tests for scripts/check-version.sh: run `bash scripts/test-check-version.sh`.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

manifest() {
    cat >"$tmp/Cargo.toml" <<EOF
[workspace]
members = ["crates/a"]

[workspace.dependencies]
version = "9.9.9"

[workspace.package]
version = "$1"
edition = "2021"

[package]
version = "8.8.8"
EOF
}

failed=0
# tag | workspace version | expected exit code
for case in \
    "v0.1.0|0.1.0|0" \
    "v0.1.0-rc.1|0.1.0-rc.1|0" \
    "v0.1.0|0.1.0-rc.1|1" \
    "0.1.0|0.1.0|1" \
    "v0.1.0-rc.1|0.1.0|1" \
    "v0.1.0|0.1.00|1" \
    "|0.1.0|1"; do
    IFS='|' read -r tag version want <<<"$case"
    manifest "$version"
    got=0
    bash "$here/check-version.sh" "$tag" "$tmp/Cargo.toml" >/dev/null 2>&1 || got=$?
    if [ "$got" != "$want" ]; then
        echo "FAIL: tag '$tag', version '$version': exit $got, want $want"
        failed=$((failed + 1))
    fi
done
if [ "$failed" -gt 0 ]; then
    exit 1
fi
echo "ok: check-version"
