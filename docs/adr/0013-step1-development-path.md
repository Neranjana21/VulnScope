# ADR-0013: Step 1 in-process development path
Status: accepted (owner rulings Q1, Q2 and the round 25 cuts). Implemented on the Step 1 branch.

**Q2 amended by ADR-0014:** `devpath/` may also connect to the sealed lab app target on `127.0.0.1` port 3000. Statements below that only the stub is contacted describe `devpath.step1`.

Label, used in code, command output and the report: **STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary**.

## Context
Slice 1 needs workers, a broker, job tokens and an egress gateway (ADR-0002), behind a pre-gate whose blockers are still open. We want an early end-to-end proof (policy decision to ledger to finding to report) without them.

## Decision
- **Q1.** Step 1 is a development spike that comes before Slice 1. The Slice 1 pre-gate is neither run nor passed, and nothing here is a Slice 1 result or passes any Slice 1 acceptance criterion as a gate. All Slice 1 blockers stay open and must clear before any Step 2 gateway or worker implementation. Slice 0 is not closed by this work.
- **Q2 (exception to architecture section 2).** The top-level package `devpath/` may open a socket, only to `127.0.0.1` on the port our own in-process stub is bound to. `devpath/` is not importable from the API (nothing under `src/` imports it) and is not in the built package (the wheel packages only `src/vulnscope`). A test proves both. `devpath/` is **deleted when Step 2 lands**.
- Every request goes through `decide_and_record` first. A send needs `allowed`, `rule_id ALLOW` and a ledger sequence number. The sender also refuses anything but scheme `http`, host and resolved address exactly `127.0.0.1`, and the stub's bound port. These checks can only refuse. No CLI argument names a target. `decide` is never imported and there is no bypass flag or environment variable.

## Fix round (review findings F1 and F2)
- **F1.** After the recorded ALLOW, and as the last await before a socket is created, engagement status and window are read again from the database. Not `active` gives `revoked` (`revoked_before_send`). Outside the window gives `denied` (`window_closed_before_send`). An error, an unusable result or no answer within 2 s gives `denied` (`recheck_failed`). In each case there is no connection and no finding. This check can only refuse. The ledger keeps the ALLOW decision and has no entry for the refusal (no new event kind), so it shows an allow with nothing sent. The owner accepted this gap for the development spike only; backlog BL-S1-F9: record the abort in the ledger when Step 2 lands. The in-flight watcher and the locked pre-write check are unchanged.
- **Remaining gap (F1).** The re-read takes no lock. A revoke that commits, or a window that expires, after the re-read's snapshot and before the request bytes are on the wire is not prevented. The watcher polls once the send starts and then every 0.25 s, so it can cancel too late and the stub can receive the HEAD. The pre-write check still blocks a finding if the engagement is not active or is outside its window. Closing the gap needs enforcement at the point of sending (the Step 2 gateway); it is not solved here. The 2 s bound relies on the read honouring cancellation, and a stuck driver could make the refusal later than that.
- **F2.** The report reconciles ledger and rows in both directions: each `evidence` entry and each `finding.transition` finding needs its row, each row needs its entry, and a finding last recorded as `confirmed` needs an evidence row. Any problem is shown at report level, also with zero rows, and makes `evidence_checks_ok=false`. Compared with the ledger: content hash, ids, policy version, adapter and finding status. Compared with fixed constants, because the ledger does not record them: evidence kind, expected, observed and finding title. Other fields are not compared.
- **Limits (F2).** The ledger read is bounded to 1000 entries. A bounded or short read, an empty chain or a failed verification is `incomplete`, never `ok`. The ledger and rows are read separately, so a report taken during a run can show a false mismatch. A truncated or rewritten chain is still undetectable without a checkpoint. This detects deletion; it does not prevent it (GR-SEC-9).

## Round 25 cuts
- Evidence is a fixed allowlist of exactly five header names (`content-security-policy`, `x-frame-options`, `x-content-type-options`, `referrer-policy`, `permissions-policy`), each `absent` or `present`. Values are never judged, stored or logged. No bodies.
- Redirects are not followed: a 3xx is `inconclusive(redirect_not_followed)`. There is no hop decision and `Location` is not read or stored.
- Revoke is covered by an integration test only; it is not in the demo.
- No independent stress-tester. The report uses the standard library with `html.escape`; no template engine.
- One combined reviewer, one verifier, at most one fix round.

## Stated limits
- Presence is literal. A header that is present with a weak, empty or wrong value counts as `present`. A control delivered another way is not recognised: for example CSP `frame-ancestors` does not make `X-Frame-Options` `present`. So the check can both miss real weaknesses and report an issue where an equivalent control exists.
- Enforcement is in-process code. There is no gateway, worker, queue, job token, process isolation or network isolation, so a code bug or other in-process code can bypass it. The sender takes no URL, host or port. It accepts only an exact `devpath.stub.RunningStub` (no subclass or look-alike), asks that object's real socket for the port, and requires it to be a `127.0.0.1` listener. This stops mistakes, not hostile in-process code, which can still patch the sender or its helpers, call the private send function, open its own socket, or put a different `127.0.0.1` listening socket that this process holds (including a duplicated or inherited descriptor) into a real stub object.
- The policy engine does not restrict ports: the lab profile would allow any loopback service, including the database. This is why the sender pins the port to the stub's own.
- DNS, TLS, redirect following, real labs and real targets are not exercised.
- SEC-6 (structural log scrubbing) and GR-SEC-9 (monotonic `chain_heads` trigger and DELETE-grant review) remain open.

## Accepted limits (round 26)
These three are accepted by the owner and are printed in the report under "Limits of this assessment":
- Headers are reported as `present` or `absent` only; a CSP `frame-ancestors` rule does not count as `X-Frame-Options`.
- No redirect is followed.
- That `devpath/` is excluded from the built package is proven from the build configuration only; no wheel was built.

## Alternatives rejected
- Waiting for the Slice 1 gateway and worker: no end-to-end feedback for a long time.
- Using `httpx` or a URL-taking sender: environment proxies, DNS and arbitrary targets would be one mistake away.
- Putting the path under `src/vulnscope`: it would ship in the package and be importable by the API.
