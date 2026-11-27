# Security policy

rtriage reads files that are often built to attack whatever opens them.
Bugs that let such a file affect the analyst's machine or mislead the
analyst's terminal are security bugs, and reports are very welcome.

## Supported versions

During 0.x only the latest release gets fixes. Please check that a bug
still reproduces on the latest release (or `main`) before reporting.

## Reporting a vulnerability

Report privately through GitHub:
**[Report a vulnerability](https://github.com/VoroN5k/rtriage/security/advisories/new)**
(Security tab → "Report a vulnerability"). Please do not open a public issue
for security bugs.

Include:

- the rtriage version (`rtriage --version`), OS and the exact command;
- what happened and what you expected;
- a **synthetic** reproducer if you can (a small crafted file, or a script
  or bytes that build one). **Never attach live malware.** If the trigger
  is a real sample, describe it and give its SHA-256 instead.

This is a personal project: responses are best effort, usually within a
week. There is no bug bounty. Credit goes in the advisory and changelog
unless you prefer otherwise.

## In scope

- A crafted input that makes rtriage panic, hang past `--timeout`, or use
  memory or disk far beyond the documented limits.
- Terminal escape sequences or other control characters from a file
  reaching the terminal unescaped, or file data becoming markup (links,
  images, HTML, mentions) in Markdown output.
- Bypassing worker isolation in batch mode, or one file affecting the
  results of another.
- Anything that makes rtriage execute, load or emulate an input file, or
  access the network without an explicit option.
- Supply-chain problems in the release process (build, checksums,
  provenance).

## Out of scope

- Missed detections, false positives and scoring disagreements: these are
  ordinary issues, please open one (with a synthetic example where
  possible).
- Problems that need an attacker who already controls the analyst's
  machine, rules directory or command line.
- Warnings from Windows SmartScreen or macOS Gatekeeper: release binaries
  are not code-signed (see the README for how to verify them).
