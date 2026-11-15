# Stress-test catalogue

"Stress-tested" means the relevant rows below pass and the results are recorded in the post-gate file. All tests target our own code and local labs.

## Policy / scope guard (`policy/`)
- Property tests (hypothesis) over target strings: userinfo tricks, IDN and mixed-case hosts, trailing dots, alternative IP encodings (decimal, octal, hex), IPv4-mapped IPv6, bracketed IPv6, ports and default ports. Invariant: decision is made on the canonical resolved address; deny list always wins.
- Exclusion-beats-inclusion matrix; overlapping CIDRs; wildcard domains vs apex.
- Expiry and window boundaries (exact second, clock skew, monotonic deadlines).
- Redirect chains: allowed -> allowed -> denied; redirect loops; scheme downgrades.
- DNS: name that resolves to a denied address; resolution change between check and connect (pinning test); CNAME into an excluded name.
- Throughput: decision latency p99 under concurrent calls; no shared mutable state.

## Ledger (`ledger/`)
- Tamper: edit, delete, insert, reorder, truncate tail, fork. `verify()` must name the first bad index.
- Concurrency: many writers appending; chain stays linear; no gaps.
- Crash safety: kill the process mid-append; chain remains verifiable.
- Golden tests: canonical JSON and hash vectors fixed across versions.
- Truncation vs checkpoint; forged checkpoint signature; checkpoint older than the data; intake-chain isolation per org.
- Scale: append and verify throughput at 1e5 and 1e6 records; verify memory is bounded.

## API (`api/`)
- Schema fuzzing against the OpenAPI spec (schemathesis); invalid-request matrix from `io-contracts.md`.
- Load: sustained and burst request rates; p95 latency and error rate recorded.
- AuthZ: cross-org access attempts on every endpoint return 404/403 and are logged.
- Idempotency: replayed `POST /scans` with the same key creates one engagement.

## Workers and queue (`worker/`)
- Kill a worker mid-scan; job resumes or fails cleanly; no partial evidence marked confirmed.
- Duplicate delivery; broker restart; poison job quarantine.
- Cancellation: revoke during a running scan; measure stop latency against the configured bound.
- Resource limits: CPU, memory, time and output caps enforced; runaway tool is killed.
- Forged or expired job token is rejected.

## Adapters and validators
- Malformed, truncated and oversized tool output; non-UTF-8 bytes; control and terminal-escape characters.
- Hostile target behaviour (served by a local test server): huge headers, endless streams, slow-loris responses, compression bombs, redirect storms. Adapters must cap, time out and report `inconclusive`.
- Validator safety: attempting a mutating method under `write_tests=false` raises; redaction removes planted canary secrets; excerpt size cap enforced.
- Direct egress from a worker (bypassing the gateway) fails.

## Reporting
- Hostile strings (script tags, HTML entities, huge text) in findings and evidence render escaped; CSP header present.
- Canary-secret test: a planted secret never appears in logs, reports, errors or the database dump.

## Whole-system (slice gates)
- Chaos run: random worker kills, broker restart and DB restart during a scan; final ledger verifies.
- Multi-engagement soak: several concurrent engagements; no cross-talk in findings, evidence or scope.
- Regression: all earlier acceptance tests rerun.
