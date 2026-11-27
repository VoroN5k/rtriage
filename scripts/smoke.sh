#!/usr/bin/env bash
# Release smoke test: runs a built rtriage binary against the synthetic
# samples and checks risk levels, finding IDs, --fail-on exit codes, scan,
# Markdown output and that YARA is compiled in.
#
#   scripts/smoke.sh <rtriage-binary> <samples-dir> <expected-version>
#
# Samples come from `cargo run -p rtriage-fixtures --example samples -- <dir>`
# (synthetic, benign). Expected values are written here by hand, not taken
# from the binary under test. Levels and IDs only, never exact scores.
# SMOKE_BREAK=1 deliberately expects a wrong level (to prove a failing smoke
# run blocks a release).
set -euo pipefail

if [ "$#" -ne 3 ]; then
    echo "usage: $0 <rtriage-binary> <samples-dir> <expected-version>" >&2
    exit 2
fi
bin=$1
dir=$2
version=$3

checks=0
failed=0
pass() { checks=$((checks + 1)); }
fail() {
    checks=$((checks + 1))
    failed=$((failed + 1))
    echo "FAIL: $*"
}

# name|level|required finding IDs (space-separated)
samples=(
    "pe-clean.exe|clean_looking|"
    "pe-upx.exe|low|PE-PACKER-KNOWN PE-SECTION-RWX"
    "pe-medium.exe|medium|PE-SECTION-VIRTUAL-ONLY PE-PACKED-LIKELY"
    "pe-high.exe|high|PE-EXPORTS-REFLECTIVE-LOADER PE-OVERLAY-EMBEDDED-PE"
    "elf-clean|clean_looking|"
    "elf-upx|low|ELF-PACKER-KNOWN"
)
if [ "${SMOKE_BREAK:-0}" = "1" ]; then
    samples[1]="pe-upx.exe|high|PE-PACKER-KNOWN"
fi

rank() {
    case $1 in
        clean_looking) echo 0 ;;
        low) echo 1 ;;
        medium) echo 2 ;;
        high) echo 3 ;;
        *) echo -1 ;;
    esac
}

# Runs rtriage, returns its exit code without tripping `set -e`.
run_code() {
    local code=0
    "$bin" "$@" >/dev/null 2>&1 || code=$?
    echo "$code"
}

# --version
got_version=$("$bin" --version | tr -d '\r')
if [[ $got_version == *"$version"* ]]; then pass; else fail "--version: got '$got_version', want '$version'"; fi

for entry in "${samples[@]}"; do
    IFS='|' read -r name level ids <<<"$entry"
    file="$dir/$name"
    if [ ! -f "$file" ]; then
        fail "$name: missing sample"
        continue
    fi
    json=$("$bin" -f json "$file" 2>/dev/null) || true
    got=$(jq -r '.reports[0].risk.level' <<<"$json" 2>/dev/null | tr -d '\r') || got="(no report)"
    if [ "$got" = "$level" ]; then pass; else fail "$name: level '$got', want '$level'"; fi
    for id in $ids; do
        if jq -e --arg id "$id" '[.reports[0].findings[].id] | index($id) != null' <<<"$json" >/dev/null 2>&1; then
            pass
        else
            fail "$name: finding $id missing"
        fi
    done
    for threshold in low medium high; do
        want=0
        if [ "$(rank "$level")" -ge "$(rank "$threshold")" ]; then want=3; fi
        code=$(run_code --fail-on "$threshold" "$file")
        if [ "$code" = "$want" ]; then pass; else fail "$name: --fail-on $threshold exit $code, want $want"; fi
    done
done

# YARA compiled in: the bundled rules were loaded.
if [ -f "$dir/pe-high.exe" ] &&
    "$bin" -f json "$dir/pe-high.exe" 2>/dev/null |
    jq -e '.reports[0].facts.yara.rules_loaded > 0' >/dev/null 2>&1; then
    pass
else
    fail "yara: no bundled rules loaded (built without the yara feature?)"
fi

# scan over the directory lists every sample.
scan_out=$("$bin" --no-color scan "$dir" 2>/dev/null) && scan_code=0 || scan_code=$?
if [ "$scan_code" = 0 ]; then pass; else fail "scan: exit $scan_code, want 0"; fi
for entry in "${samples[@]}"; do
    name=${entry%%|*}
    if grep -qF "$name" <<<"$scan_out"; then pass; else fail "scan: $name not listed"; fi
done

# Markdown output.
md=$("$bin" -f md "$dir/pe-high.exe" 2>/dev/null | tr -d '\r') || true
if [ "$(head -n 1 <<<"$md")" = "# rtriage report" ] && grep -qx '### Findings' <<<"$md"; then
    pass
else
    fail "md: not a report document (title and a Findings section)"
fi

if [ "$failed" -gt 0 ]; then
    echo "smoke: $failed of $checks checks failed"
    exit 1
fi
echo "ok: $checks checks"
