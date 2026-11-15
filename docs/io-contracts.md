# I/O contracts (schema_version 1)

Changing anything here requires an ADR and the owner's approval. Every object carries `schema_version`. Decisions behind these rules are in `docs/decisions.md`.

## Conventions
- JSON, UTF-8. Timestamps are ISO8601 UTC with `Z`; naive datetimes are rejected (`WINDOW_NAIVE_DATETIME`).
- Auth: `Authorization: Bearer <api key>`; keys are hashed at rest. Roles: `admin`, `assessor`, `viewer`.
- `Idempotency-Key` header on every POST that creates a resource. Same key + same body returns the original response; same key + different body returns 409. Keys kept 24 h.
- Errors: RFC 9457 `application/problem+json` with extra fields `code` (enum below), `ledger_seq` (if written) and `request_id`.
- IDs are UUIDv7. Every row has `org_id`; engagement-scoped rows also `engagement_id`.

## Reason codes (request validation)
`AUTH_NOT_CONFIRMED, SCOPE_EMPTY, TARGET_DENIED, TARGET_NOT_IN_SCOPE, RATE_ABOVE_CEILING, WINDOW_MISSING, WINDOW_EXPIRED, WINDOW_NAIVE_DATETIME, WINDOW_TOO_LONG, SECRET_INLINE, UNKNOWN_FIELD, PROFILE_NOT_ENABLED, IDEMPOTENCY_CONFLICT, FORBIDDEN_ROLE, NOT_FOUND`
Policy decision `rule_id` values: `ALLOW, DENY_ALWAYS_LIST, DENY_PRIVATE_RANGE, EXCLUDED, OUT_OF_SCOPE, EXPIRED, NOT_YET_VALID, REVOKED, RATE, RESOLVED_OUTSIDE_EXPECTED, REDIRECT_DENIED, RESOLUTION_FAILED`

## Engagement: `POST /v1/engagements`
```json
{
  "schema_version": 1,
  "name": "string",
  "profile": "standard | lab",
  "targets": {"domains": [], "ip_ranges": [], "openapi_url": null},
  "scope": {"allow": [], "deny": [], "expected_ip_ranges": [],
            "rate_limit_rps": 5,
            "window": {"not_before": "2026-01-01T00:00:00Z", "not_after": "2026-01-31T00:00:00Z"}},
  "authorization": {"confirmed": true, "statement": "string", "approver": "string"},
  "identities": [{"label": "user_a", "role": "citizen",
                  "auth": {"type": "bearer | api_key_header | basic", "secret_ref": "ref://engagements/e1/user_a"}}],
  "ownership_rules": [{"resource": "/records/{id}", "owner_identity": "user_a"}],
  "asset_tags": [{"match": "api.example.test", "criticality": "high", "data": "personal"}]
}
```
Validation: `authorization.confirmed` must be true; `scope.allow` non-empty; **every target must be covered by `scope.allow`** and must not match the deny rules; `rate_limit_rps` is per target host and must not exceed `VULNSCOPE_MAX_RPS_PER_HOST` (default 10); window required, timezone-aware, `not_after` in the future, length <= `VULNSCOPE_MAX_WINDOW_DAYS` (default 90); `secret_ref` must match `^ref://[a-z0-9_/-]+$`; unknown fields forbidden; `profile=lab` only when the deployment enables it. A best-effort secret-pattern scan runs on free-text fields (name, statement) and rejects obvious secrets (`SECRET_INLINE`); it has false negatives and is documented as such.
Response `201`: `{id, status: "active", created_at, ledger_seq}`. Rejections are written to the org's intake chain.

Other engagement endpoints: `GET /v1/engagements/{id}`; `POST /v1/engagements/{id}/revoke` body `{reason}` -> `{status: "revoked", revoked_at, ledger_seq}` (admin or assessor owner).

## Scan: `POST /v1/engagements/{id}/scans`
`{"schema_version":1, "stages":["discover","detect","validate","path"], "options":{"write_tests":false}, "schedule":null}`
Fails with `REVOKED`/`EXPIRED`/`NOT_FOUND` when the engagement is not active. `write_tests=true` is rejected unless the engagement authorization statement explicitly covers it (S2+). Response `202`: `{scan_id, status:"queued"}`.
`GET /v1/scans/{id}`, `GET /v1/scans/{id}/findings`, `GET /v1/scans/{id}/paths`, `GET /v1/scans/{id}/report?format=html|pdf|json`.

## Policy decision
```json
{"allowed": false, "reason": "string", "rule_id": "DENY_ALWAYS_LIST", "policy_version": "1.0.0+<ruleset-hash>",
 "action": {"kind": "http|tcp|dns", "target": "...", "resolved_ips": [], "adapter": "..."}, "ts": "ISO8601"}
```
`policy_version` is the semver of the always-deny list and rule set plus a hash of the loaded configuration. Every decision, allow or deny, becomes a ledger entry.

## Ledger entry (one chain per engagement; intake chain per org)
```json
{"schema_version":1, "chain_id":"engagement:<id> | intake:<org>", "seq":0,
 "kind":"policy.decision | evidence | finding.transition | engagement.created | engagement.revoked | scan.* | checkpoint",
 "actor":"user:<id> | system", "payload":{}, "ts":"ISO8601",
 "prev_hash":"hex", "record_hash":"hex"}
```
`record_hash = SHA-256(prev_hash || canonical_json(entry_without_record_hash))`. Canonical JSON: sorted keys, UTF-8, no insignificant whitespace, UTC timestamps; golden vectors committed (ADR-0003). Genesis `prev_hash` = SHA-256 of `"vulnscope-ledger-v1:" + chain_id`.
`GET /v1/ledger/verify?chain=<chain_id>[&checkpoint=<file>]` -> `{"result":"ok|bad_record|fork|truncated","first_bad_seq":null,"records":N,"checkpoint_seq":M}`.
Checkpoint: `{chain_id, seq, head_hash, ts, signature}` (Ed25519).

## Adapter interface
```python
class Adapter(Protocol):
    name: str
    version: str
    def plan(self, target: Target, policy: PolicyClient) -> list[Action]: ...
    def run(self, action: Action, policy: PolicyClient) -> RawResult: ...
    def normalize(self, raw: RawResult) -> list[Finding]: ...
    def stop(self, run_id: str) -> None: ...
```
Adapters never open sockets directly; `run` goes through the gateway client (S1). Output is size-capped, time-capped and treated as hostile. A missing external tool yields `tool_unavailable`, not a crash.

## Finding
`id, schema_version, org_id, engagement_id, asset_id, title, cwe, taxonomy[] , owasp_api (nullable), status, severity (derived from CVSS band), evidence_ids[], cvss{version, vector, score, source, snapshot}, priority{band, reasons[], policy_version, unknown_inputs[]}, source_adapter{name, version}, first_seen, last_seen`
**Status transitions (all others are "backward" and need a reviewer role plus a recorded reason):**
`candidate -> likely | confirmed | false_positive | inconclusive | blocked_by_policy`; `likely -> confirmed | false_positive | inconclusive`; `inconclusive -> likely | confirmed | false_positive`; `confirmed -> remediated` (only by a passing retest); `remediated -> confirmed` (regression); `blocked_by_policy -> candidate` (only after a scope change); `false_positive -> candidate` (reopen, with reason). Every transition is a ledger entry.

## Evidence record
`id, finding_id, kind, redacted_excerpt, content_sha256, identity_label, expected, observed, policy_version, adapter{name, version}, ledger_chain, ledger_seq, created_at`
The evidence row is referenced from a ledger entry of kind `evidence`; the chain provides integrity. Excerpts are size-capped and redacted at ingest.

## Attack path
`nodes[{id, type: asset|finding}], edges[{from, to, precondition, postcondition}], fix_set[{finding_id, paths_broken}], method: "exact_min_vertex_cut | greedy_hitting_set", paths_total, derived_from_rules[]`
Edges derive from `graph/rules.yaml` pre/postconditions per finding type, never hand-drawn.

## Retest: `POST /v1/findings/{id}/retest`
Body `{}`; response `202 {retest_id}`; the result appends a new evidence record and may transition the finding (`confirmed -> remediated`). Original evidence is never mutated.

## Other endpoints
`GET /v1/findings/{id}/evidence`, `GET /healthz`, `GET /metrics` (operator network only).

## Report layout
1 Summary and top fixes; 2 Scope, authorization (self-attested), policy used and hosting-verification notes; 3 Assets and lifecycle; 4 Findings (status, evidence, CVSS v4, priority with reasons and unknown inputs); 5 Attack paths and the recommended fix set (method stated); 6 Fix snippets and retest results; 7 Ledger verification result, checkpoint status and limitations. All target-derived text is escaped.
