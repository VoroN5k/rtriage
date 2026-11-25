# JSON output schema

`rtriage -f json` writes one JSON document per invocation.

**Versioning.** `schema_version` is an integer. It is bumped only on breaking
changes: removing or renaming a field, or changing a field's type or meaning.
Adding fields or enum values is *not* breaking. Consumers should ignore
unknown fields and treat unknown enum values gracefully.

Current version: **1**.

## Top level

| Field | Type | Description |
|---|---|---|
| `schema_version` | integer | Schema version, currently `1`. |
| `tool.name` | string | Always `"rtriage"`. |
| `tool.version` | string | rtriage version that produced the document. |
| `reports` | array of [Report](#report) | One per successfully analyzed file, in command-line order. |
| `failures` | array of [Failure](#failure) | Files that could not be analyzed at all. |

### Failure

| Field | Type | Description |
|---|---|---|
| `path` | string | Path as given on the command line (lossy UTF-8). |
| `error` | string | Human-readable reason (unreadable, directory, over size limit, ...). |

## Report

| Field | Type | Description |
|---|---|---|
| `file` | [FileInfo](#fileinfo) | Identity of the file. |
| `facts` | [Facts](#facts) | Neutral extracted data. |
| `findings` | array of [Finding](#finding) | Judgments, sorted by severity desc, confidence desc, id. |
| `risk.score` | integer | Aggregate score for sorting (see `heuristics.md`, "Scoring v1"). |
| `risk.level` | enum | `clean_looking` \| `low` \| `medium` \| `high`. |
| `risk.breakdown` | array | One entry per finding in scoring order: `{ id, category, table_points, points, reduced_by? }`. `reduced_by` is `{ kind: "suppressed", by, packer }`, `{ kind: "duplicate" }`, `{ kind: "category_cap", cap }` or `{ kind: "low_severity_cap", cap }`. Not affected by `--min-severity`. |
| `analysis_limited` | array of enum | Why static analysis is less complete: `packed`. Empty normally. |
| `errors` | array of [AnalyzerFailure](#analyzerfailure) | Analyzers that failed; the rest of the report is still valid. |

### FileInfo

| Field | Type | Description |
|---|---|---|
| `path` | string | Path (lossy UTF-8). |
| `size` | integer | Size in bytes. |
| `format` | enum | `pe` \| `elf` \| `unknown`. |
| `hashes` | object \| null | `md5`, `sha1`, `sha256` as lowercase hex. |

### Facts

Every member is `null` if its analyzer did not run.

**`entropy`**

| Field | Type | Description |
|---|---|---|
| `whole_file` | number | Shannon entropy of the file, bits per byte (0.0–8.0). |
| `window` | integer | Window size in bytes used for region detection. |
| `high_threshold` | number | Entropy a window had to reach to count as high. |
| `high_regions` | array | `{ offset, len, entropy }` per run of consecutive high windows. |

**`strings`**

| Field | Type | Description |
|---|---|---|
| `min_len` | integer | Minimum string length in characters. |
| `total` | integer | Strings found, including any beyond the `max_strings` limit. |
| `limit_reached` | bool | `true` if more than `max_strings` strings were found. |
| `items_included` | enum | `classified` (default: only strings with `kinds`) \| `all` (`--all-strings`). |
| `items` | array | See below, sorted by offset. |

**`pe`** (non-PE input: `null`). Each part is `null` if its analyzer failed.

`pe.headers`:

| Field | Type | Description |
|---|---|---|
| `machine` / `machine_raw` | string / integer | `i386`, `amd64`, `arm64`, ... or `unknown_0x....`; raw COFF value. |
| `bits` | integer | `32` (PE32) or `64` (PE32+). |
| `kind` | enum | `exe` \| `dll` \| `driver` (subsystem `native`). |
| `subsystem` / `subsystem_raw` | string / integer | `windows_gui`, `windows_cui`, `native`, ...; raw value. |
| `characteristics` | array of string | Set COFF flags, e.g. `executable_image`, `dll`. |
| `dll_characteristics` | array of string | Set flags, e.g. `nx_compat`, `dynamic_base`, `guard_cf`. |
| `entry_point` | object \| null | `{ rva, section: { index, name } \| null }`; `null` when `AddressOfEntryPoint` is 0. |
| `image_base` | integer | Preferred load address. |
| `size_of_image` | integer | `SizeOfImage`. |
| `number_of_sections` | integer | COFF `NumberOfSections`. |
| `timestamp` | object | `{ raw, utc }`, `utc` is ISO 8601 or `null` when `raw` is 0. |
| `checksum` | object | `{ stored, computed }`. |
| `managed_dotnet` | bool | CLR header present (managed .NET assembly). |

`pe.sections`: array, one object per section table entry, in table order:

| Field | Type | Description |
|---|---|---|
| `index` | integer | Index in the section table. |
| `name` | string | Raw name up to the first NUL (lossy UTF-8; sanitize before display). |
| `virtual_address`, `virtual_size` | integer | `VirtualAddress`, `VirtualSize`. |
| `raw_offset`, `raw_size` | integer | `PointerToRawData`, `SizeOfRawData`. |
| `characteristics_raw` | integer | Raw `Characteristics`. |
| `permissions` | string | `rwx` with `-` for unset bits, e.g. `r-x`. |
| `flags` | array of string | `code`, `initialized_data`, `uninitialized_data`, `discardable`, `shared`. |
| `entropy` | number \| null | Entropy of raw data present in the file; `null` if under 512 bytes. |
| `raw_truncated` | bool | Raw data claimed past end of file. |

`pe.imports`:

| Field | Type | Description |
|---|---|---|
| `libraries` | array | `{ name, functions: [{ name, ordinal }] }` in descriptor / thunk order. `name` is `null` for ordinal-only imports, `ordinal` is `null` for named ones. Names are raw (sanitize before display). |
| `total_functions` | integer | Imported functions across all libraries. |
| `limit_reached` | bool | Parsing stopped at `max_imports` or `max_import_libraries`. |
| `imphash` | string \| null | pefile-compatible import hash; `null` without imports. |

`pe.overlay` (`null` if none): `{ offset, size, entropy, kind }`; `entropy`
is `null` under 512 bytes; `kind` is `pe`, `zip`, `7z`, `rar`, `cab`, `gzip`,
`pdf`, `nsis`, `png`, `jpeg`, `gif` or `null`. A trailing certificate table is not overlay.

`pe.tls` (`null` without a TLS directory): `{ callbacks: [{ va, section }],
limit_reached }`; `section` is `{ index, name }` or `null`.

`pe.debug` (`null` without a CodeView record): `{ codeview, pdb_path,
pdb_guid, pdb_age }`; `codeview` is `RSDS` or `NB10`; `pdb_guid` is
`XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (`RSDS` only) or `null`.

`pe.packers`: array of detected packers (empty if none):
`{ name, indicators }`, e.g.
`{ "name": "UPX", "indicators": ["section_names", "header_signature", "stub_structure"] }`.

`pe.rich` (`null` if absent): `{ offset, key, computed_checksum,
checksum_valid, entries: [{ product_id, build, count }] }`. `offset` is the
`DanS` marker; `checksum_valid` is `key == computed_checksum`.

`pe.exports` (`null` without an export table): `{ dll_name, timestamp,
ordinal_base, exports: [{ ordinal, name, rva, forwarder }], limit_reached }`.
`name` is `null` for ordinal-only exports; `forwarder` (`"DLL.Function"`) is
set when the address points inside the export directory.

`pe.resources` (`null` without a resource directory): `{ entries: [{
type_name, name, lang, rva, size, entropy, kind }], limit_reached }`.
`type_name` is `RT_*` for standard types, else `#<id>` or the stored name;
`name` is `#<id>` or the stored name; `kind` as for the overlay.

`pe.signature` (`null` when unsigned): `{ offset, size, status,
certificates: [{ offset, length, revision, kind, pkcs7_signed_data }],
problems }`. `status` is `signed_unverified` (well-formed table containing a
PKCS#7 SignedData) or `malformed` (see `problems`). **The signature is never
verified**: no hash or certificate chain check.

A PE that fails to parse produces one `errors` entry from analyzer
`pe-parse`; the other PE analyzers then leave their facts `null`.

String item: `offset` (integer), `encoding` (`ascii` \| `utf16_le`), `len`
(characters, before truncation), `value` (raw text, JSON-escaped; **sanitize
before displaying**), `truncated` (bool), `kinds` (array, omitted when empty).

`kinds` values: `url`, `ipv4`, `ipv6`, `domain`, `email`, `file_path`,
`registry_key`, `base64`, `suspicious_command`, `crypto_wallet`, `user_agent`.

### Finding

| Field | Type | Description |
|---|---|---|
| `id` | string | Stable identifier, documented in `heuristics.md`. |
| `severity` | enum | `info` \| `low` \| `medium` \| `high`. |
| `confidence` | enum | `low` \| `medium` \| `high`. |
| `category` | enum | `packing`, `obfuscation`, `anti_analysis`, `injection`, `persistence`, `network`, `credential_access`, `collection`, `impact`, `hardening`, `anomaly`, `metadata`. |
| `title` | string | One-line summary. |
| `detail` | string | Explanation. |
| `evidence` | array | Tagged by `type`: `range {offset,len}`, `section {index,name}`, `import {library,symbol}`, `string {offset,encoding,value}`, `metric {name,value}`, `field {name,value}`. |
| `attack` | array of string | MITRE ATT&CK technique IDs. |
| `suppressed` | object (optional) | Present when a confirmed packer explains the finding: `{ by, packer }`, e.g. `{ "by": "PE-PACKER-KNOWN", "packer": "UPX" }`. Such findings score 0. |

`--min-severity` removes findings below the level from `findings` only;
`risk` always reflects all findings.

### AnalyzerFailure

| Field | Type | Description |
|---|---|---|
| `analyzer` | string | Analyzer name, e.g. `strings`. |
| `error.kind` | enum | `truncated` \| `limit_exceeded` \| `timeout` \| `internal` \| `malformed`, plus kind-specific fields. |

`timeout` (with `limit_ms`) means the per-file time limit expired: the
analyzer was interrupted or never started, and the report is partial.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | All files analyzed. |
| `1` | At least one file failed (see `failures`), or the report could not be written. |
| `2` | Usage error. |
