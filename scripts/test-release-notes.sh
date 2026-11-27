#!/usr/bin/env bash
# Tests for scripts/release-notes.sh: run `bash scripts/test-release-notes.sh`.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cat >"$tmp/CHANGELOG.md" <<'EOF'
# Changelog

## [Unreleased]

## [0.2.0] - 2027-01-01

- Later thing.

## [0.1.0] - unreleased

### Added

- First thing.

## [0.0.1] - 2026-01-01

- Older thing.
EOF

failed=0
check() { # description, condition result
    if [ "$2" != 0 ]; then
        echo "FAIL: $1"
        failed=$((failed + 1))
    fi
}
notes() { bash "$here/release-notes.sh" "$@" "$tmp/CHANGELOG.md"; }

out=$(ATTESTED=true notes 0.1.0-rc.1)
grep -qF -- "- First thing." <<<"$out"; check "rc version uses the base section" $?
! grep -qF "Later thing" <<<"$out"; check "stops before the newer section" $?
! grep -qF "Older thing" <<<"$out"; check "stops before the next section" $?
! grep -qF "## [0.1.0]" <<<"$out"; check "section heading itself is not repeated" $?
grep -qF "sha256sum -c SHA256SUMS" <<<"$out"; check "verify block: checksums" $?
grep -qF "gh attestation verify" <<<"$out"; check "verify block: attestation" $?
grep -qF "not code-signed" <<<"$out"; check "verify block: unsigned note" $?
! grep -qF "Not attested" <<<"$out"; check "attested build has no private note" $?

out=$(ATTESTED=false notes 0.1.0)
grep -qF "Not attested: built from a private repository." <<<"$out"; check "private note" $?

out=$(SKIP_SMOKE="x86_64-apple-darwin" ATTESTED=true notes 0.1.0)
grep -qF "x86_64-apple-darwin" <<<"$out"; check "skipped smoke target named" $?

code=0
ATTESTED=true notes 9.9.9 >/dev/null 2>&1 || code=$?
[ "$code" = 1 ]; check "missing section fails" $?

if [ "$failed" -gt 0 ]; then
    exit 1
fi
echo "ok: release-notes"
