# Heuristics and scoring

Every finding ID, its rationale, thresholds and known false positives are
documented here. IDs are stable: renaming one requires a changelog note.

> Status: the scoring rules below are agreed and fixed; they are implemented
> in M2 step 7. Findings are added to the catalogue as their analyzers land.

## Scoring v1

Scoring is deterministic and integer-only. No floating point is involved.

### Points per finding

Points come from this fixed table. It was derived once as
`(severity × confidence% + 50) / 100` (round half up) with severity weights
High 40, Medium 15, Low 5, Info 0 and confidence 100 / 70 / 40 %, but the
code uses the table, not the formula.

| Severity \ Confidence | high | medium | low |
|---|---|---|---|
| High | 40 | 28 | 16 |
| Medium | 15 | 11 | 6 |
| Low | 5 | 4 | 2 |
| Info | 0 | 0 | 0 |

### Caps

Per category:

| Category | Cap |
|---|---|
| `packing` | 30 |
| `obfuscation` | 30 |
| `anomaly` | 20 |
| `anti_analysis` | 15 |
| `hardening` | 10 |
| `metadata` | 0 |
| `injection`, `persistence`, `network`, `credential_access`, `collection`, `impact` | 40 each |

Global: the sum contributed by all `low`-severity findings is at most **15**.

### Algorithm and order

1. **Points.** Each finding gets its points from the table.
2. **Deduplicate by ID.** If several findings share an ID, only the one with
   the most points counts; ties keep the first in report order (step 3).
   The others are listed by `--explain` with 0 points ("duplicate").
3. **Sort.** Remaining findings are ordered by, in this priority:
   1. severity, descending (`high` > `medium` > `low` > `info`);
   2. confidence, descending (`high` > `medium` > `low`);
   3. ID, ascending, compared byte-wise (IDs are ASCII).

   After deduplication IDs are unique, so this is a total order and the
   result does not depend on analyzer order. It is the same order the report
   uses for `findings`.
4. **Accumulate greedily** in that order. Each finding contributes
   `min(points, category cap remaining, low cap remaining if severity is low)`,
   and both remainders are reduced by the contribution.
5. **Score** = sum of contributions (a non-negative integer, bounded by the
   sum of category caps).
6. **Level:**

   | Score | Level |
   |---|---|
   | 0–9 | `clean_looking` |
   | 10–29 | `low` |
   | 30–59 | `medium` |
   | ≥ 60 | `high` |

Because the highest-severity, highest-confidence findings are taken first,
caps cut the weakest contributions. `--explain` prints every finding with its
table points, its contribution, and which cap (if any) reduced it.

### Calibration checks

| Scenario | Points | Level |
|---|---|---|
| Single full injection chain (`PE-API-INJECTION`, High/High) | 40 | medium |
| Injection + anti-debug (Low/Medium) | 40 + 4 = 44 | medium |
| Injection + known packer (15) + RWX section (11) | 66 | high |
| Packing signals alone, any number | ≤ 30 | at most medium |
| TLS callbacks (Low/Medium) + anti-debug (Low/Medium) | 4 + 4 = 8 | clean_looking |

**Packing cap = 30.** Packing on its own can reach the bottom of `medium`
but never `high`: packers are common in legitimate software (installers,
games, UPX-compressed tools), and a packed file deserves a look, not an alarm.

## Finding catalogue

Entries are added as analyzers land (M2 steps 2–6).
