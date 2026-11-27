#!/usr/bin/env bash
# Prints the GitHub release notes for a version: its CHANGELOG section
# (a pre-release such as 0.1.0-rc.1 uses the 0.1.0 section), then how to
# verify the download.
#
#   ATTESTED=true|false [SKIP_SMOKE="<targets>"] scripts/release-notes.sh <version> [CHANGELOG.md]
set -euo pipefail

version=${1:?usage: release-notes.sh <version> [CHANGELOG.md]}
changelog=${2:-CHANGELOG.md}
base=${version%%-*}

section=$(awk -v want="## [$base]" '
    index($0, "## [") == 1 {
        if (found) exit
        if (index($0, want) == 1) { found = 1; next }
    }
    found { print }
' "$changelog" | tr -d '\r')

if [ -z "$(tr -d '[:space:]' <<<"$section")" ]; then
    echo "error: no '## [$base]' section in $changelog" >&2
    exit 1
fi

printf '%s\n' "$section"
cat <<'EOF'

## Verify the download

```bash
# Checksums (Linux; on macOS use `shasum -a 256 -c`)
sha256sum -c SHA256SUMS --ignore-missing
# Build provenance: built by this repository's release workflow
gh attestation verify <archive> --repo VoroN5k/rtriage
```

On Windows, compare `Get-FileHash -Algorithm SHA256 <archive>` with the
line in `SHA256SUMS`.

The binaries are not code-signed: Windows SmartScreen and macOS Gatekeeper
will warn about an unknown publisher. Verify the archive first; see the
README for details.
EOF
if [ "${ATTESTED:-true}" != "true" ]; then
    printf '\nNot attested: built from a private repository.\n'
fi
if [ -n "${SKIP_SMOKE:-}" ]; then
    printf '\nNot smoke-tested on the build machine (built and checked for the right architecture only): %s\n' "$SKIP_SMOKE"
fi
