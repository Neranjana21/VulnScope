# ADR-0014: lab app target for the development path (amends ADR-0013 Q2)
Status: accepted (owner decisions for Step 1b, Phase A). A development spike only.

Label, unchanged: **STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary**.

## Context
ADR-0013 lets `devpath/` talk only to its own stub. We want to run the same presence check against one locally run, deliberately vulnerable lab app (OWASP Juice Shop), still without the gateway and workers.

This is not a Slice 1 result and not a Slice 1 pre-gate pass. That pre-gate has been neither run nor passed.

## Decision
**Q2, as amended.** `devpath/` connects only to the numeric address `127.0.0.1`, on one of two in-code targets: the real `RunningStub` (port read from its socket, as before) or the single `JUICE_SHOP` object (constant port 3000, defined once, in `devpath/targets.py`). No host, port or URL comes from the command line, the environment, configuration, the database or the API.

- **Sealed target.** The sender accepts an exact `RunningStub`, or an object that **is** `JUICE_SHOP`. A subclass, look-alike, copy, deep copy, new instance or equal instance is refused. The object has no state; the port is the code constant.
- **Pin.** In addition to the ADR-0013 checks, the action kind must be `http` and the target text must be exactly `http://127.0.0.1:<port>/`. The text check is needed because the target parser canonicalises forms such as `127.1` to `127.0.0.1`. These checks can only refuse.
- **Separate command.** `python -m devpath.step1b`; its only option is `--out`. `devpath.step1` behaves as before.
- **Phase A check only.** The existing five-header presence check, one HEAD of `/`. No cookies, server banner, `/ftp`, GET or body reading. Redirects are not followed.
- **Same guarded path.** Lab-profile configuration refusals, the recorded decision, the pre-send re-check, a watcher that starts after the record, the locked write, the two-way ledger and row check, and the rule that no header value is stored all apply to both targets.
- **No new data.** No migration, raw SQL, ledger event kind or ledger payload field. The target kind is passed in memory and only chooses fixed report wording. The seeded engagement uses a different fixed name and statement: the operator attests that port 3000 on `127.0.0.1` is their local Juice Shop.
- **Failure.** A failed connection is `inconclusive` with a fixed code, no finding and a non-zero exit.

## Running the lab app
The operator runs the container; no code here pulls or starts anything. The commands are in the README. The release tag and image digest are placeholders: the operator chooses the tag, pins the digest and checks the image's licence. This document makes no licence claim. The commands have not been tried.

## Stated limits
- **Port 3000 cannot identify Juice Shop.** The sender cannot prove what listens there. It could be another local server, such as your own development server, which would then receive the HEAD. The operator checks the published port and attests the identity.
- **Lab isolation not verified.** Container and network settings are lab hygiene, not the worker boundary. The effect of disabling IP masquerade (meant to block outbound NAT), on this or on port publishing, is unverified, as are the hardening options with this image. It does not show that the network is isolated.
- Only the presence of five header names is checked. All ADR-0013 limits on presence checks, enforcement, the re-check gap and the ledger still apply.
- The tests use a fake listener that the test process binds on port 3000. No real Juice Shop has been exercised by tests.
- Enforcement is still in-process code and does not stop hostile in-process code.
- SEC-6 (structural log scrubbing) and GR-SEC-9 (monotonic `chain_heads` trigger and DELETE-grant review) remain open, including while a lab app's responses are read.

## Alternatives rejected
- A `--target`, `--port` or `--url` option, or an environment variable: a one-word mistake could aim the sender at another service, such as the database.
- Letting the stub bind port 3000, or accepting any loopback port: weakens the pin.
- Probing the app to confirm its identity: needs more requests and body reads, and still proves nothing.

`devpath/` is still to be deleted when Step 2 lands.
