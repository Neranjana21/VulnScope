# VulnScope

An open-source, authorization-first vulnerability assessment platform for web apps and APIs that the operator is permitted to test. **It is in early development and is not ready to assess any real system.**

## The problem
- A scanner can leave its permitted scope through a redirect, a DNS trick, URL parsing differences or a wrapped tool.
- A list of findings does not show which fix matters most.
- A reader needs to see what evidence supports a claim and what was permitted when it was collected.

## What VulnScope intends
Intended pipeline: find, prove with safe read-only validators, show the single fix that breaks the most attack paths, generate the fix, retest. Claims are to be backed by a hash-chained evidence ledger. Most of this pipeline is **planned, not built**.

Design principles: no network action without a policy decision; authorized targets only; read-only validators; minimal, redacted evidence; no exploit tooling; all target data is treated as hostile. These are goals for the finished system. The sections below say what is enforced today and how weakly.

The design is enterprise-grade in ambition; the implementation grows slice by slice.

## Status
| Capability | Status |
|---|---|
| Policy decision core (scope guard) and decision recording | Built (application code only) |
| Hash-chained ledger, verification, signed checkpoint support | Built, with limits (ADR-0003, ADR-0005) |
| Control API: API keys, idempotency, revoke | Built, with limits (ADR-0006); keep it on localhost |
| Database table grants applied by migrations | Built, with limits (ADR-0004) |
| One response-header check and an HTML report | Development spike only (ADR-0012, ADR-0013, ADR-0014) |
| Egress gateway, workers, broker, job tokens, isolation | Planned (ADR-0002) |
| Tool adapters, discovery, further validators | Planned |
| Attack graph, risk scoring, fix generation, retest, web UI, PDF report | Planned |

**Keep the API bound to localhost.** It has no rate limiter, including no throttle on failed authentication.

## Architecture
**Target design:** a modular monolith control plane (ADR-0001) with isolated scan workers. Workers have no direct egress; all target traffic passes through a gateway that holds the engagement allowlist, resolves and pins IPs, re-checks redirects and fails closed (ADR-0002).

```
Operator -> Control plane -> signed jobs -> Scan workers -> Egress gateway -> Authorized targets
            (API, policy, ledger, PostgreSQL, reports)
```

**What exists today:** control-plane Python code (policy, ledger, models, API) with PostgreSQL, plus the Step 1 spike. There is no scan plane and no gateway, so **no network-layer enforcement of scope exists**.

See [architecture](docs/architecture.md) (it marks capabilities by phase and describes the target, not only what is built), [contracts](docs/io-contracts.md), [threat model](docs/threat-model.md) and the ADRs in [docs/adr](docs/adr/).

## Step 1 demo
**STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.**

The demo takes no target, host or port. It starts its own local stubs. Its only option is `--out`.
1. Checks its configuration (refusing before any engine, stub or socket is created), then seeds an engagement directly, not through the API.
2. Sends one HEAD, after a recorded policy decision, to a stub on `127.0.0.1` that lacks security headers. It reports five headers as `present` or `absent` and records a finding (`candidate` to `confirmed`) with redacted evidence.
3. Repeats against a stub that redirects. The result is `inconclusive` (`redirect_not_followed`), with no finding.
4. Verifies the ledger chain, lists entry sequence numbers and kinds, cross-checks evidence and writes `report.html`.

Revoke is **not** part of the demo. The command exits 0 only if the outcomes above, ledger verification and the evidence checks are as expected; 1 on an unexpected result or error; 2 on a usage error or configuration refusal.

### Running it (WSL2 Linux)
Prerequisites:
- the repository virtual environment (Python 3.12) with dependencies installed;
- the local development PostgreSQL container, already set up and running;
- an untracked `.env` for that database (never commit it).

From the repository root, with the virtual environment active:

```bash
PYTHONPATH=src:. python scripts/with_task_db.py --mode task --task s --lock-wait 120 -- \
  env VULNSCOPE_ENABLE_LAB=1 python -m devpath.step1 --out .reports/step1
```

The lab flag is set inside the child command, after `--`. The default output directory, `.reports/step1`, is git-ignored.

Not verified while writing this README: first-time setup (installing dependencies, creating the container, filling in `.env`), what the wrapper script requires and does internally, and this command on a fresh checkout. These steps are not a complete setup guide.

## Step 1b: the same check against a local lab app
**STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.** A development spike, not a Slice 1 result or pre-gate pass ([ADR-0014](docs/adr/0014-dev-path-lab-target-allowlist.md)).

`python -m devpath.step1b` runs the five-header presence check (one `HEAD /`) against `127.0.0.1:3000`, meant for a local OWASP Juice Shop, a deliberately vulnerable lab app. Its only option is `--out` (default `.reports/step1b`, git-ignored). It takes no target, host or port, and it pulls and starts nothing. It does not check cookies, server banners or `/ftp`, sends no GET and reads no response body.

**Limits, read first**
- **Port 3000 cannot identify Juice Shop.** Whatever listens there receives the request, including your own development server. By running the command you attest that it is your local Juice Shop; the engagement statement records that.
- **Isolation:** lab isolation not verified. The settings below are lab hygiene, not the worker boundary.
- SEC-6 (structural log scrubbing) and GR-SEC-9 remain open.
- Only a fake listener bound by the tests has been exercised, not a real Juice Shop.

### Starting the lab app (you run these)
**All of these commands are unverified: they have not been tried.** Replace `<tag>` and `<digest>`: choose the release tag, take the digest from the inspect output, and check the image's licence yourself. First check that the container name `vulnscope-juice` and the network name `vulnscope-lab` are unused.

```bash
docker pull bkimminich/juice-shop:<tag>
docker image inspect --format '{{index .RepoDigests 0}}' bkimminich/juice-shop:<tag>
docker network create --driver bridge --opt com.docker.network.bridge.enable_ip_masquerade=false vulnscope-lab
docker run -d --rm --name vulnscope-juice --network vulnscope-lab -p 127.0.0.1:3000:3000 --cap-drop ALL --security-opt no-new-privileges --memory 1g --pids-limit 256 bkimminich/juice-shop@sha256:<digest>
docker port vulnscope-juice
```

`docker port` must print only `3000/tcp -> 127.0.0.1:3000`. If it prints anything else, stop the container. **Never publish on `0.0.0.0`.** Disabling IP masquerade is meant to block outbound NAT. Its effect on Docker Desktop and WSL2 and on port publishing is unverified, as are the hardening options with this image. It is not proof of isolation. If WSL cannot reach `127.0.0.1:3000`, stop; do not publish more widely.

When finished:

```bash
docker stop vulnscope-juice && docker network rm vulnscope-lab
```

### Running the check
With the same prerequisites as the Step 1 demo:

```bash
PYTHONPATH=src:. python scripts/with_task_db.py --mode task --task s --lock-wait 120 -- \
  env VULNSCOPE_ENABLE_LAB=1 python -m devpath.step1b --out .reports/step1b
```

This command has not been run against a real lab app. It exits 0 when the check completes (`issue` or `no_issue`) and the ledger and report checks are ok; 1 for anything else, such as nothing listening (`connection_error`, no finding) or a redirect; 2 on a usage error or configuration refusal.

## What this does not prove (development spike)
**Step 1 is a development spike. It is NOT the security boundary, NOT a Slice 1 result and NOT a Slice 1 pre-gate pass.** That pre-gate has been neither run nor passed, its blockers remain open, and the preceding Slice 0 is not closed by this work. `devpath/` is to be deleted when Step 2 lands (ADR-0013). It is a temporary exception to the target design: it opens a socket without a gateway, only to `127.0.0.1`, to its own stub or (ADR-0014) port 3000. The points below were written for the Step 1 demo; they apply to Step 1b too, except where they say only the stub is contacted.

**Enforcement and isolation**
- There is no gateway, worker, queue, job token, process isolation or network isolation.
- Enforcement is in-process code. A code bug or other in-process code can bypass it: by patching the sender or its helpers, calling the private send function, opening its own socket, putting a different `127.0.0.1` listener (including a swapped, duplicated or inherited one) into a real stub object, or injecting a fake ledger or engagement view, which would satisfy the "recorded decision" requirement without a real record (requests still go only to the stub).
- The policy engine does not restrict ports. The lab profile would allow any loopback service, including the database; the sender pins `127.0.0.1` and either the stub's own port or the constant 3000.

**What is checked**
- Five headers, one HEAD per check: `content-security-policy`, `x-frame-options`, `x-content-type-options`, `referrer-policy`, `permissions-policy`.
- Literal `present` or `absent` only. Weak, empty or wrong values count as `present`. CSP `frame-ancestors` does not count as `X-Frame-Options`. The check can miss weaknesses and can report an issue where an equivalent control exists.
- Redirects are not followed.
- `devpath.step1` contacts only its own local stub; `devpath.step1b` contacts only `127.0.0.1:3000`. DNS, TLS and real targets are not exercised, and no real lab app has been exercised by tests.
- Findings are unscored (ADR-0012): no CVSS score, and severity is not assessed.

**Evidence, ledger and operations**
- The demo creates no ledger checkpoint, so tail truncation or a rewritten chain is undetectable.
- The application database role can modify and delete evidence and finding rows, and can rewind chain heads.
- Structural log scrubbing is absent. The demo command disables logging and prints only an exception's class name on unexpected errors; other callers of the code receive raw exceptions.
- Revoke latency has not been measured. Revoke is covered only by tests, not the demo.
- Expiry of the authorization window while a request is in flight, or before findings are written, is not shown to be tested.
- Engagement creation bypasses the API. Authorization is self-attested; software cannot prove legal permission.
- That `devpath/` is excluded from the built package is shown from build configuration only; no wheel was built. The import-boundary scan does not detect non-literal dynamic imports.

**Review findings** (one review, one fix round and one verifier pass; none of these is independent proof of correctness)
- **F1, fixed with a remaining gap:** a request could be sent when a revoke committed while the allow decision was being recorded. The engagement status and window are now re-read after that record, just before any socket is created, and nothing is sent if the check refuses or fails. A revoke or expiry after that re-read but before the bytes leave is not prevented. A refusal at this point leaves the allow entry in the ledger, with nothing sent and no separate refusal entry. This is accepted for the development spike only; backlog BL-S1-F9: record the abort when Step 2 lands.
- **F2, fixed with limits:** the report now compares ledger and rows in both directions, shows a report-level mismatch, and says "check incomplete" when it cannot read enough of the ledger. Evidence hash, identifiers, policy version, adapter and finding status are compared with the ledger. Evidence kind, expected and observed text and the finding title are compared with fixed values in the code, because the ledger does not record them. Severity, CVSS, priority, asset ID, taxonomy, identity label, timestamps and other unlisted fields are not compared. Deletion is detected, not prevented. Rows and ledger are read separately, so a report made during a run can show a false mismatch.
- **Edited score fields:** editing the severity of an unscored finding stops report generation with a validation error instead of showing a mismatch; the code suggests some CVSS or priority edits do the same.
- **F3:** only the database name is checked, not the database host.
- **F4:** each run gets a new rate-limit store, so the request rate limit does not apply across runs.
- **F5:** ADR-0013 does not mention that a caller can inject a fake ledger or engagement view.
- **F6:** window-expiry coverage is thin. No committed real-database test covers window expiry, or a failed or timed-out re-read, before sending.
- **F7:** the invisible-character source guard does not cover `docs/` or `scripts/` (nor migrations or the project file).
- **F8:** ledger entries are written before the database commit. If the commit fails, "confirmed" can exist only in the ledger. The report should now show the missing row as a mismatch, but the write is still not atomic.
