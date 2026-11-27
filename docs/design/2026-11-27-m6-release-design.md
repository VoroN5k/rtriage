# M6.2: first public release (v0.1.0) design

Status: approved by the user, with approach A and the details below
(2026-11-27). This is the second M6 sub-project and comes after Markdown
output (M6.1).

## Intent

Make `rtriage` something a stranger who finds it on GitHub can understand,
install, verify and trust, without building it from source. The tool
analyzes hostile files, so the release has to show the same care the code
does:
- every build input is locked;
- every CI permission is the minimum needed;
- every binary has a checksum and provenance;
- the README is honest about what the tool does not do.

## Goals

- **Distribution for v0.1.0:** prebuilt binaries in GitHub Releases, plus
  `cargo install --git … --locked`. That is all.
- **A tag-driven release workflow** that builds, smoke-tests, packages,
  checksums, attests and creates a **draft** release. A release is created
  only when every build and every smoke test passed.
- **Targets:**
  - Linux x86_64 (musl if it passes the benchmark, otherwise gnu);
  - Windows x86_64 (msvc);
  - macOS aarch64 (Apple Silicon);
  - macOS x86_64, cross-built on the Apple Silicon runner.
- **Dry run:** `v0.1.0-rc.1` is a draft in the still-private repository.
  The real `v0.1.0` is published as a **pre-release**, and
  `schema_version = 1` is frozen at that point. *Update (user, after
  publishing): v0.1.0 was re-marked as a normal release; from then on only
  tags with a suffix (`-rc.N`) are pre-releases. 0.x versioning already
  says the CLI may change.*
- **Supply chain:** `cargo-deny` (licenses compatible with
  GPL-3.0-or-later, advisories, bans, sources) runs in CI and on a
  schedule; Dependabot covers cargo and GitHub Actions.
- **Docs:** `SECURITY.md` and a security model section in the README. The
  README gets:
  - honest limitations;
  - a logo that switches with the GitHub theme (`<picture>`);
  - screenshots (the user makes them from `samples/`);
  - install and verification steps (`sha256sum -c`,
    `gh attestation verify`);
  - a note that the binaries are not code-signed.
- **Before the repository goes public:** an audit of the git history for
  secrets and personal email, a decision on `docs/superpowers/`, and a
  check that the name `rtriage` is free on GitHub and crates.io.

## Non-goals

- crates.io publishing, Homebrew, winget, AUR, Docker images.
- Code signing or notarization (Authenticode, Apple). The README says
  this openly.
- An installer script (`curl | sh`).
- Linux aarch64 and Windows aarch64 builds (possibly later).
- Changes to analysis behavior. This sub-project is release engineering
  and docs only.

## Anti-goals (a failure even if it works)

- A published release with a binary that was not smoke-tested, or with
  missing archives (a partial release).
- A tag whose binaries report a different version (`rtriage --version`
  must match the tag).
- Any malware-like bytes on disk or in release assets:
  - `samples/` is synthetic and generated in CI, never committed and never
    uploaded as a release asset;
  - the EICAR string is never written to disk (it exists only in memory,
    in tests, as today).
- Workflow permissions broader than one job needs, or any action not
  pinned to a full commit SHA.
- A public repository whose history still contains secrets or an email
  address the user did not choose to publish.

## Constraints

- **Git is read-only for Claude.** The user commits, tags and pushes.
  Claude writes files and gives the commit text and commands.
- **Third-party actions** are pinned to full SHAs with the tag in a
  comment, as in `ci.yml`. Workflow-level `permissions: contents: read`;
  any wider permission is granted per job.
- **Every cargo invocation uses `--locked`.** The toolchain comes from
  `rust-toolchain.toml` (1.95.0); targets are added with `rustup target add`.
- **New dependencies or tools need the user's approval.** This design
  approves:
  - `cargo-deny`, run through a pinned `EmbarkStudios/cargo-deny-action`;
  - `actions/attest-build-provenance`;
  - the `gh` CLI that ships on GitHub runners.

  Nothing else, unless asked.
- **Release builds** use `--features yara` (TUI is a default feature) and
  never enable `test-hooks`.

## Approaches (decided)

- **A, chosen:** a hand-written `.github/workflows/release.yml`. It gives
  full control over SHA pinning, per-job permissions and the order of
  build, smoke, package, checksums, attest and draft. Cost: roughly 150–200
  lines of YAML that the project maintains itself.
- **B, rejected: cargo-dist.** Its workflow is generated and regenerated,
  pulls in more third-party actions, is harder to pin and restrict, and
  defaults to `curl | sh` installers.
- **C, rejected: release-plz / cargo-release.** These tools exist for
  crates.io publishing and version bumping, which is out of scope.

## Design

### Order of work (the user's order)

1. Name check and history audit.
2. cargo-deny, Dependabot and `SECURITY.md`.
3. README (with logo, security model, limitations, install and verify).
4. `samples/` generator, smoke test, release workflow, then a dry run
   with `v0.1.0-rc.1`.
5. The `v0.1.0` release: CHANGELOG, schema freeze, tag.

### 1. Name check and history audit

- **Name.** Look up `rtriage` on crates.io (API: `GET /api/v1/crates/rtriage`)
  and on GitHub (an existing user, organization or well-known repository
  with that name). Only the name is sent. Claude reports what it finds,
  and the user decides.
- **Secrets.** Scan the whole history (`git log -p --all`) for credential
  patterns (keys, tokens, `password=`, private key headers, `.env`-like
  files) and list every author and committer identity.

  Finding so far: every one of the 60 commits uses the user's personal
  email address.
- **User decision (history):** the user rewrites the history in one pass,
  on a fresh clone with a backup:
  - `git filter-repo` with a mailmap maps the personal address to the
    GitHub `noreply` address;
  - the same pass removes `docs/superpowers/plans/`.

  The user then publishes the result as a **new** repository and deletes
  the old one, sets `noreply` as the commit email, and turns on GitHub's
  "block command line pushes that expose my email". Claude prepares the
  exact commands and mailmap but runs nothing that writes to git.
- **User decision (`docs/superpowers/`):** specs move to `docs/design/`
  (a normal commit before the rewrite), plans are removed (from the
  working tree and, through the rewrite, from history). `CLAUDE.md` stays.
  Later specs are written to `docs/design/`.

### 2. cargo-deny, Dependabot, SECURITY.md

- **`deny.toml`:**
  - **licenses:** an allow-list compatible with distributing a
    GPL-3.0-or-later binary (MIT, Apache-2.0, Apache-2.0 WITH
    LLVM-exception, BSD-2-Clause, BSD-3-Clause, ISC, Zlib, Unicode-3.0,
    MPL-2.0, and others only if the real dependency tree needs them and they
    are compatible). Unknown or unlicensed crates are denied.
  - **advisories:** deny vulnerabilities, warn on unmaintained crates.
  - **bans:** deny wildcard versions and warn on duplicates.
  - **sources:** crates.io only.
- **CI.** A `deny` job in `ci.yml` (pull requests and `main`), plus a
  separate `deny-schedule.yml` that runs weekly (cron) so advisories
  published after a merge still surface.
- **`.github/dependabot.yml`:** weekly updates for the `cargo` ecosystem
  and for `github-actions`. Actions stay SHA-pinned, and Dependabot updates
  the SHA and the tag comment.
- **`SECURITY.md`:**
  - Supported versions: the latest release only, during 0.x.
  - How to report: GitHub private vulnerability reporting. No email
    address is published.
  - In scope:
    - parser panics, hangs, or memory blow-ups on crafted input;
    - escape sequences reaching a terminal, or markup injection in
      Markdown;
    - bypassing worker isolation or the limits;
    - anything that makes rtriage execute or load input;
    - supply chain.
  - Out of scope: missed detections and heuristic false positives (those
    are ordinary issues). No bounty. Response is best effort.

### 3. README

- **Header:** a `<picture>` element with `rtriage-logo-dark.svg` for
  `prefers-color-scheme: dark` and `rtriage-logo-light.svg` otherwise, with
  alt text `rtriage`.
- **Brand assets** go to `assets/brand/`: the logo and mark SVGs and
  `social-preview.png` (1280×640, uploaded by the user in repository
  Settings; GitHub has no API for it). The favicons are not committed,
  because there is no website yet *(Claude's call)*.
- **Screenshots** go to `docs/images/`. The user makes them from
  `samples/` (text output, `--explain`, the `scan` table, the TUI). The
  README references fixed file names, and Claude lists those names so the
  user can drop the images in.
- **Install:**
  - download from Releases, verify with `sha256sum -c SHA256SUMS` (and
    the PowerShell `Get-FileHash` equivalent), verify provenance with
    `gh attestation verify <archive> --repo VoroN5k/rtriage`;
  - or `cargo install --git https://github.com/VoroN5k/rtriage --locked rtriage-cli`
    (with `--features yara` for YARA).
  - **Unsigned binaries:** Windows SmartScreen and macOS Gatekeeper will
    warn. The README explains why the binaries are unsigned and how to
    verify them instead, and says that `xattr -d com.apple.quarantine`
    is the user's own decision after verifying.
- **Security model:**
  - no execution, loading or emulation;
  - every input treated as hostile;
  - bounded, panic-free parsers;
  - terminal and Markdown output sanitized;
  - per-file worker isolation in batch mode;
  - no network access;
  - no telemetry.
- **Limitations** (honest):
  - static only, so there is no unpacking (packed files show the packer,
    not the payload);
  - heuristics produce false positives and the score is not a verdict;
  - Authenticode presence only, signatures are not validated;
  - no Mach-O, .NET IL, scripts or Office documents;
  - YARA only in builds with the `yara` feature (release binaries have it);
  - pre-1.0: the CLI may change, and the JSON schema follows the documented
    versioning rules;
  - unsigned binaries.
- The Status line is updated (M1–M6 done, first pre-release).

### 4. Samples, smoke test, release workflow

- **`samples/` generator:** a new example,
  `cargo run -p rtriage-fixtures --example samples --locked -- <dir>`.
  It writes synthetic, benign binaries built with the existing builders, at
  least one per risk level:
  - clean-looking (plain data or a minimal PE);
  - low (UPX-like PE);
  - medium (injection-chain PE);
  - high (a fixture that reaches high, for example an injection chain plus
    a persistence or anti-debug group, whichever the current rules make
    high);
  - at least one ELF (unusual interpreter).

  Then `samples/` is added to `.gitignore`. The user can run the same
  command locally for screenshots. No EICAR content.
- **Smoke test:** `scripts/smoke.sh <rtriage-binary> <samples-dir>`, in bash
  (Git Bash on Windows runners), using `jq` from the runner image. It checks:
  - `--version` prints the tag's version;
  - for each sample, `-f json` gives the expected `risk.level` and that the
    expected finding IDs are present;
  - `--fail-on` exit codes: 3 at or below the sample's level, 0 above it,
    and 0 on clean-looking;
  - `scan` over the directory exits 0 and lists every sample;
  - `-f md` produces `# rtriage report`;
  - YARA is compiled in (a release binary loads the bundled rules: `--yara`
    accepts a rule file without the "built without YARA" usage error).

  Expected values live in the script, written by hand rather than derived
  from the binary under test.
- **Linux target decision (musl benchmark):** before writing the workflow,
  build `x86_64-unknown-linux-musl` and `x86_64-unknown-linux-gnu` release
  binaries and time, over several runs:
  - compiling the bundled YARA rules (a run on one small file, which is
    dominated by rule compilation);
  - `scan` over a generated directory of a few hundred samples.

  If musl is at most **1.3×** slower than gnu on both, ship musl.
  Otherwise ship gnu, built on `ubuntu-22.04` for an older glibc baseline.
  The 1.3× threshold is *Claude's call*. A faster allocator for musl would
  be a new dependency, so it is not part of this design. The numbers go in
  the plan's notes and the release notes.

  **Result and exception (user, 2026-11-27): musl ships.** Measured with
  `musl-bench.yml` on one `ubuntu-latest` runner, median of 7 runs:

  | Target | One file (YARA compile) | `scan` of 240 files |
  |---|---|---|
  | gnu | 10 ms | 59 ms |
  | musl | 16 ms | 75 ms |
  | musl / gnu | 1.6× | 1.27× |

  The one-file case misses the 1.3× rule, but the gap is 6 ms per run, so at
  that size process start-up sets the ratio rather than real work. The batch
  case, which reflects real use, is within the threshold. A static binary
  that runs on any Linux distribution is worth more than 6 ms, so the user
  made an exception to the rule. Re-run `musl-bench.yml` if the YARA rules
  or the allocator story change much.
- **`release.yml`**, triggered on `push` of tags `v*`:
  1. **check:** the tag without `v` must equal the workspace version in
     `Cargo.toml`. Fail otherwise. So `v0.1.0-rc.1` requires
     `version = "0.1.0-rc.1"`, and the final tag requires `0.1.0`.
  2. **build** (matrix):
     - `x86_64-unknown-linux-musl|gnu` on ubuntu;
     - `x86_64-pc-windows-msvc` on windows;
     - `aarch64-apple-darwin` on macos (arm);
     - `x86_64-apple-darwin` on the same arm runner, with
       `rustup target add`.

     Each runs `cargo build --release --locked -p rtriage-cli --features yara --target <t>`,
     generates samples, runs the smoke test, and uploads the archive as a
     workflow artifact:
     - `rtriage-<tag>-<target>.tar.gz` (`.zip` on Windows);
     - contents: the binary, `LICENSE`, `README.md`.

     The x86_64 macOS binary is smoke-tested under Rosetta if the runner
     can execute it; if not, the job only checks that the file is a valid
     x86_64 Mach-O and says so in the release notes *(Claude's call)*.
  3. **release** (needs every build; runs only if all succeeded):
     - downloads the artifacts and writes `SHA256SUMS`;
     - attests every archive with `actions/attest-build-provenance`, only
       if `github.event.repository.private == false`, so the private rc.1
       skips it and says so in its notes;
     - creates a **draft** release with `gh release create --draft` and
       attaches the archives and `SHA256SUMS`;
     - for tags with a `-` (rc), and for `v0.1.0`, adds `--prerelease`.

     The notes body is the matching CHANGELOG section plus the
     verification instructions.
  4. **Permissions:**
     - workflow level: `contents: read`;
     - release job: `contents: write`, plus `id-token: write` and
       `attestations: write` (used only when attesting);
     - build jobs: read-only.

     `persist-credentials: false` on checkout. No secrets other than
     `GITHUB_TOKEN`.
- **Dry run.** Bump the version to `0.1.0-rc.1`, tag and push in the
  private repository, check the draft (assets, sums, notes, smoke logs),
  then delete the draft and the `v0.1.0-rc.1` tag, locally and on the
  remote. The user publishes nothing.

### 5. The release

- **`CHANGELOG.md`** (Keep a Changelog style): one `0.1.0` entry that
  summarizes M1–M6 by area, says the JSON schema version is 1, and notes
  that the build is unsigned.
- **`docs/output-schema.md`:** "Current version: 1 (unreleased)" becomes
  released with v0.1.0. The table's "after a release" rules apply from now
  on.
- **Version back to `0.1.0`.** The user makes the repository public (after
  the audit), tags `v0.1.0` and pushes. The workflow attests and drafts,
  and the user reviews and publishes the pre-release.
- After publishing, the user uploads `social-preview.png` and sets the
  repository description and topics.

## Left to the builder

- The exact fixtures for each risk level and their expected finding IDs
  (read them from the current rules and tests).
- The exact deny.toml allow-list (from `cargo deny list` on the real tree;
  every addition must be GPL-3.0-compatible).
- How the release notes are assembled from the CHANGELOG (a small script
  step is fine).
- A version bump also changes `Cargo.lock`. Both are committed together, otherwise `--locked` fails in the workflow.
- Whether `jq` needs installing on any runner image (it is preinstalled on
  current GitHub images; verify).

## Claude's calls (check these)

- Favicons are not committed (no website).
- Brand assets in `assets/brand/`, screenshots in `docs/images/`.
- musl threshold is 1.3× gnu, measured as the median of several runs on
  one machine (user).
- The x86_64 macOS smoke test is skipped if Rosetta is unavailable, with a
  note.
- Every release is created as a draft, and the user publishes it by hand.
- Rc tags require the matching pre-release version in `Cargo.toml`. After
  the dry run, the rc tag (local and remote) and its draft are deleted
  (user).
