# ADR-0012: Unscored finding placeholder
Status: accepted (owner-approved, including the `docs/io-contracts.md` change, round 25). Implemented on the Step 1 branch.

## Context
`docs/io-contracts.md` "Finding" requires `cvss{version, vector, score, source, snapshot}` and `priority{band, reasons[], policy_version, unknown_inputs[]}`, and `severity` is derived from the CVSS band. Step 1 (ADR-0013) produces a finding before any scoring exists. A made-up score such as `0.0` reads as "scored, no impact", which is false and breaks the honest-measurement rule.

## Decision
`CvssInfo.score` becomes `float | None` (contract change, `schema_version` stays 1). An unscored finding has exactly these values:

| Field | Value |
|---|---|
| `cvss.version` | `"unscored"` |
| `cvss.score` | `null` |
| `cvss.vector` | `""` |
| `cvss.source` | `"none"` |
| `cvss.snapshot` | `"none"` |
| `priority.band` | `"unscored"` |
| `priority.reasons` | `[]` |
| `priority.policy_version` | `"none"` |
| `priority.unknown_inputs` | `["cvss", "kev", "epss", "asset_criticality", "exposure"]` |
| `severity` | `null` |

`score` is `null` if and only if `version` is `"unscored"`. No fake `0.0` is ever written.

## Consequences
- No migration: `findings.cvss` and `findings.priority` already hold these objects and `findings.severity` is nullable.
- Every consumer must handle `score = null`; a report shows "unscored" with the unknown inputs and severity as not assessed, never a number.
- Scored findings stay valid and unchanged.
- The schema change and its validation tests are Step 1 task T2; until it lands the schema still rejects a null score.
