#!/usr/bin/env bash
# Fails unless a release tag matches the workspace version:
# `v<version>` where <version> is `[workspace.package] version` in Cargo.toml.
#
#   scripts/check-version.sh <tag> [Cargo.toml]
set -euo pipefail

tag=${1:-}
manifest=${2:-Cargo.toml}

version=$(awk '
    /^\[/ { in_pkg = ($0 == "[workspace.package]") }
    in_pkg && /^version[[:space:]]*=/ {
        sub(/^version[[:space:]]*=[[:space:]]*"/, "")
        sub(/".*$/, "")
        print
        exit
    }
' "$manifest" | tr -d '\r')

if [ -z "$version" ]; then
    echo "error: no [workspace.package] version in $manifest" >&2
    exit 1
fi
if [ "$tag" != "v$version" ]; then
    echo "error: tag '$tag' does not match the workspace version '$version' (expected 'v$version')" >&2
    exit 1
fi
echo "tag $tag matches version $version"
