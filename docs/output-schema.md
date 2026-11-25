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
| `risk.score` | integer | Aggregate score for sorting (always `0` until scoring lands in M2). |
| `risk.level` | enum | `clean_looking` \| `low` \| `medium` \| `high`. |
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
