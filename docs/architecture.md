# VulnScope architecture

Status key: **[S0]** slice 0, **[S1]** slice 1, **[P2+]** later phase, **[design]** specified now, built only if needed.

## 1. System context
VulnScope assesses targets an operator is authorized to test. Inputs: a scan request. Outputs: findings, evidence, attack paths, a report, and a verifiable ledger.

```
Operator --(API/CLI/UI)--> Control plane --jobs--> Scan plane --(egress gateway)--> Authorized targets
                              |  |                      |
                         PostgreSQL  Redis        Lab / customer network
                              \__ Evidence ledger __/
```

## 2. Trust zones (enforced by network and process boundaries, not convention)
| Zone | Contains | Trusts | Must never |
|---|---|---|---|
| Control plane | API, scheduler, policy service, DB, ledger, reporting | Operator input after validation | Talk to targets directly |
| Scan plane | Celery workers, tool adapters, validators | Only signed jobs from the control plane | Reach the control DB; open sockets except via the egress gateway |
| Egress gateway **[S1]** | Policy-enforcing forward proxy / per-run network allowlist | The policy service decision | Forward anything without a fresh allow decision (fail closed) |
| Targets / labs | Systems under test | Nothing | n/a. All their data is hostile |

Why a gateway: an application-level scope check can be bypassed by a bug in an adapter or a wrapped tool. The gateway enforces scope at the network layer using the engagement allowlist, resolves DNS itself and pins the resolved IP per connection (defeats DNS rebinding), and rejects redirects to unapproved hosts. See ADR-0002.

## 3. Modules (modular monolith)
| # | Module | Responsibility | Built |
|---|---|---|---|
| 1 | `policy/` Scope guard | Pure decision core over injected Resolver, Clock and RateLimitStore: engagement scope, exclusions, expiry, rate limits, deny list, decision + reason + rule id | S0 |
| 2 | `ledger/` | One hash chain per engagement + intake chain per org; signed checkpoints; verify detects edit/insert/reorder/fork/truncation (vs checkpoint) | S0 |
| 3 | `models/` | Pydantic + SQLAlchemy models, schema versions, migrations | S0 |
| 4 | `adapters/` | One interface for Nmap, ZAP, Nuclei, testssl; normalize output; hostile-output handling | S0 fake, S1 nmap |
| 5 | `discover/` | Subdomains, ports, services, OpenAPI inventory; asset lifecycle discovered -> approved -> assessed -> monitored | S1 |
| 6 | `validate/` | Read-only validators; identity-aware API authorization checks using assessor-supplied ownership rules | S1 one validator, P2+ more |
| 7 | `graph/` + `risk/` | Attack graph (NetworkX), min-cut fix, CVSS v4 (local), KEV/EPSS context, organizational priority | S1 minimal |
| 8 | `fix/` | Templated fix snippets, targeted retest, regression check that legit access still works | P2+ |
| 9 | `report/` | HTML (then PDF) report, JSON export, ledger verification section | S1 stub |
| 10 | `api/` + `worker/` | FastAPI control API; Celery tasks; cancellation; idempotency | S0 |

## 4. Core flows
**Scan:** request -> validation -> engagement created -> ledger `engagement.created` -> jobs queued with signed job tokens -> worker re-checks policy at start -> every network action: `policy.decide()` + gateway allow -> raw result -> adapter normalizes -> findings stored (status `candidate`) -> validators (read-only) -> status transitions logged -> graph + risk -> report.
**Revoke:** engagement revoked -> ledger event -> queued jobs dropped -> running jobs receive stop signal -> gateway allowlist removed within the configured lag -> worker acknowledges; test asserts maximum stop latency.
**Retest:** targeted re-run of the validators for one finding; result recorded as a new evidence record; finding status updated; original evidence never mutated.

## 5. Enterprise requirements
| Area | Requirement | Phase |
|---|---|---|
| AuthN/Z | Roles: admin, assessor, reviewer, viewer. Engagement-scoped permissions. API keys hashed at rest. OIDC/SSO interface defined, not built | Roles S0 design; OIDC P3 |
| Multi-tenancy | `org_id` + `engagement_id` on every row; row-level checks in the data layer; tests prove one org cannot read another's data | Schema S0, enforcement P2+ |
| Secrets | Referenced as `ref://...`; resolved by a `SecretStore` interface (dev: encrypted file; later: Vault/KMS). Never in logs, jobs, findings or reports | S0 interface |
| Audit | The ledger is the audit log: who, what, when, policy version, decision. Export + independent verification command | S0 |
| Data protection | TLS between zones; encrypted DB volume guidance; retention policy per engagement; redaction at ingestion, not at display | S1 |
| Isolation | Workers rootless, read-only root FS, dropped capabilities, seccomp default, CPU/mem/time/output limits per job; no shared volumes with control plane | S1 |
| Reliability | Stateless API; at-least-once jobs with idempotency keys; cancellation; retries with backoff; poison-job quarantine; graceful shutdown | S0-S1 |
| Observability | Structured JSON logs with correlation id per engagement/job; OpenTelemetry traces; Prometheus metrics (jobs, denials, latency, ledger length) | S1 |
| Supply chain | Images pinned by digest; lockfile; SBOM (CycloneDX); dependency + licence + secret scanning in CI; signed releases | S0 CI basics, P2+ signing |
| Versioning | API `/v1`; schema `schema_version` on every contract; DB migrations forward-only with tested rollback plan | S0 |
| Deployment | Docker Compose (dev, demo). Broker is Valkey (service `broker`). Helm chart + NetworkPolicies as a documented target | Compose S0; k8s [design] |
| Performance targets | Defined and measured in `benchmarks/`, not asserted: policy decision p99, ledger append throughput, API p95, cancellation latency | S1+ |
| Docs | Architecture, threat model, runbook, ADRs, contract reference, security policy (`SECURITY.md`) | rolling |

## 6. Deployment topology (compose, slice 0-1)
Services: `api`, `worker`, `scheduler`, `postgres`, `redis`, `egress-gateway` (S1), `labs/*` on the `scan` network. Networks: `control` (api, postgres, redis, scheduler) and `scan` (worker, gateway, labs). Workers get jobs through a broker endpoint exposed to both networks and nothing else.

## 7. Failure modes to design for
Worker killed mid-scan; broker restart; duplicate job delivery; DB failover mid-write; ledger append race; hostile huge responses; tool hangs; clock skew on expiry checks (use server time, monotonic for deadlines); revoked engagement with in-flight jobs; adapter crash leaving partial evidence. Each has a test in `docs/stress-tests.md`.

## 8. Clarifications from the decisions log
- Cancellation uses our own stop channel (per-job stop key + gateway allowlist removal + container kill after grace), not Celery revoke. Jobs carry control-plane-signed tokens (S1).
- The control plane makes no target traffic. Its only egress is the explicit threat-intel updater (CISA KEV, api.first.org) and build-time package registries; scoring uses offline snapshots by default.
- Nmap is never shipped in published images. The worker image is licence-clean; users install Nmap locally.
- Authorization is operator self-attested. The product records and enforces it; it cannot prove legal permission.
