# Threat model: attacks against VulnScope itself (STRIDE)

Assets: engagement scope and authorization, credentials by reference, evidence, ledger integrity, the scan plane's network reach, the operator's trust in reports.
Adversaries: a malicious or compromised target; a malicious tenant/operator trying to scan beyond authorization; a compromised dependency or adapter; an insider editing history.

| ID | Threat | Category | Mitigation | Test |
|---|---|---|---|---|
| T1 | Target redirect or DNS trick sends the scanner to an out-of-scope or internal host (SSRF-style) | Elevation | Gateway enforces allowlist, resolves and pins IPs, re-checks every redirect, blocks link-local/metadata always | policy property tests; gateway integration test |
| T2 | URL parsing differences (userinfo, IDN, trailing dot, alternative IP encodings, IPv4-mapped IPv6) bypass the scope check | Elevation | Single canonical target parser; decide on the resolved IP, not the string | hypothesis tests over a corpus of tricky forms |
| T3 | A wrapped tool makes connections the adapter did not plan | Elevation | Workers have no direct egress; only the gateway is reachable | integration test: direct connect attempt fails |
| T4 | Hostile response content injects into the report or UI (XSS, terminal escapes, huge payloads) | Tampering | Sanitize on ingest, escape on render, strict CSP, size and time caps | fuzz fixtures through the report pipeline |
| T5 | Ledger edit, truncation, reorder or fork | Tampering/Repudiation | Per-engagement hash chain, signed checkpoints stored outside the DB (needed to detect tail truncation), verify command, append-only DB role | tamper, fork and truncation tests |
| T6 | Secrets leak via logs, errors, evidence or reports | Information disclosure | `ref://` only, redaction at ingest, log scrubber, secret-scanning in CI | canary-secret test across all outputs |
| T7 | Operator claims authorization they lack | Spoofing | Recorded approver and statement, window, deny list, rate ceiling, everything logged; cannot be proven legally by software, documented as a limit | validation tests |
| T8 | Validator performs a state-changing or bulk-extracting action | Tampering | Validator API only exposes safe methods under `write_tests=false`; code review gate; allowlisted request methods | test that mutating methods raise |
| T9 | Cross-tenant data access | Information disclosure | `org_id` checks in the data layer, tested | multi-org isolation tests |
| T10 | Revocation does not stop running work | Elevation | Stop signal + gateway allowlist removal; bounded latency | revoke-during-scan test with latency assertion |
| T11 | DoS of the platform or the target (runaway scan, huge output) | DoS | Per-job CPU/mem/time/output limits, rate limits, circuit breaker | load and limit tests |
| T12 | Compromised dependency or image | Tampering | Digest pinning, lockfile, SBOM, dependency and licence scanning | CI gates |
| T13 | Job forgery: a process outside the control plane submits work | Spoofing | Signed job tokens verified by workers | forged-token test |

Residual risks are listed in `docs/gates/` after each slice. Update this file whenever a mitigation changes.
| T14 | A name in scope resolves to third-party infrastructure | Elevation | Check every resolved IP against deny rules; optional `expected_ip_ranges`; record resolved IPs; report "hosting not verified" | resolver-fake tests |
| T15 | A "safe" validator request mutates state (some GETs do) | Tampering | Per-validator `safe_proof` metadata and checklist review | post-gate checklist |
| T16 | Reviewer/tester agent edits production code or weakens tests | Tampering | Read-only test rule R1, branch diff scope check R4, human gate review R2 | post-gate diff check |
