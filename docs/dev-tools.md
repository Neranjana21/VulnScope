# Dev tools (CI-only)

These tools run in CI (and locally, in development) against VulnScope's own source and dependency
tree. None of them is bundled, imported at runtime, or distributed in any image or package we ship
— they never touch `src/vulnscope/`'s runtime dependency graph. Per **OQ-6** (resolved by the
owner): **these tools are exempt from `docs/licence-allowlist.txt`**, which governs only runtime
dependencies. This file is the traceability record for that exemption — it is informational, not
enforced mechanically by `pip-licenses` (which checks the product's resolved runtime dependency
tree, not the CI toolchain).

Licences below were checked against each project's own repository or package-index page on
2026-11-16; the exact page fetched is cited per row. Anything not directly verified is marked
**unverified** rather than assumed.

| Tool | Purpose | Version policy | Licence |
|---|---|---|---|
| `ruff` | Python linter + formatter; the single code-quality gate named in `CLAUDE.md`'s stack (D14) | Pinned to an exact version in `pyproject.toml`'s dev-dependency group / `.github/workflows/ci.yml`; bumped only via a deliberate dependency PR, never a floating `latest` | **MIT**. Verified: `LICENSE` at `github.com/astral-sh/ruff` (raw file fetched 2026-11-16), first line "MIT License". |
| `mypy` | Static type checker; run in `--strict` mode on `policy/` and `ledger/` specifically (`CLAUDE.md`) | Pinned, same policy as `ruff` | **MIT**. Verified: `LICENSE` at `github.com/python/mypy` (raw file fetched 2026-11-16): "The MIT License / Copyright (c) 2012-2023 Jukka Lehtosalo and contributors / Copyright (c) 2015-2023 Dropbox, Inc." Note: a small number of files inside mypy's own repo (mypyc's `lib-rt/base64`) carry a separate BSD-style notice and a PSF-2.0-licensed file exist internally to mypy's own codebase — this does not change the licence of the `mypy` package we depend on as a tool, noted only for completeness. |
| `pytest` | Test runner for `tests/unit`, `tests/property`, `tests/integration`, `tests/acceptance`, `tests/stress` | Pinned, same policy | **MIT**. Verified: `LICENSE` at `github.com/pytest-dev/pytest` (raw file fetched 2026-11-16), first line "The MIT License (MIT)". |
| `hypothesis` | Property-based testing — the target parser corpus, the finding state-machine transition matrix, and the ledger canonical-JSON golden vectors all use it (`docs/stress-tests.md`) | Pinned, same policy | **MPL-2.0**. Verified: `LICENSE.txt` at `github.com/HypothesisWorks/hypothesis` (raw file fetched 2026-11-16): "All code in this repository except where explicitly noted otherwise is released under the Mozilla Public License v 2.0." Consistent with `CLAUDE.md`'s own stack listing. |
| `pip-audit` | Scans the resolved dependency tree against the PyPI/OSV advisory database in CI (D14) | Pinned, same policy | **Apache-2.0**. Verified: `LICENSE` at `github.com/pypa/pip-audit` (raw file fetched 2026-11-16), opens "Apache License". |
| `pip-licenses` | Enforces `docs/licence-allowlist.txt` against the product's resolved **runtime** dependency tree in CI (D14) — the tool that makes the distinction this file documents actually mechanical for runtime deps | Pinned, same policy | **MIT**. Verified: `LICENSE` at `github.com/raimon49/pip-licenses` (raw file fetched 2026-11-16), first line "MIT License". |
| `gitleaks` | Secret-pattern scanning of commits/diffs in CI (D14; supports the T6 mitigation alongside `SecretValue` redaction) | Pinned, same policy | **MIT**. Verified: `LICENSE` at `github.com/gitleaks/gitleaks` (raw file fetched 2026-11-16): "MIT License / Copyright (c) 2019 Zachary Rice". |
| `bandit` | Static analysis for common Python security anti-patterns in CI (D14) | Pinned, same policy | **Apache-2.0**. Verified: `LICENSE` at `github.com/PyCQA/bandit` (raw file fetched 2026-11-16), opens "Apache License / Version 2.0, January 2004". |
| `semgrep` | Static analysis via custom + registry rules in CI (D14) | Pinned, same policy — **and** the specific registry ruleset we invoke (see below) is pinned by name/version in `.github/workflows/ci.yml`, not left as `--config auto` | **Split licence — engine and rules are separately licensed; see note below.** |

## Semgrep: engine licence vs. rules licence (explicitly separate)

Semgrep ships two things under two different licences, and CI uses both:

1. **The engine/CLI** (the `semgrep` PyPI package and its `github.com/semgrep/semgrep` source) is
   **LGPL-2.1-or-later**. Verified two ways: (a) the PyPI project page's licence classifier reads
   `LGPL-2.1-or-later` with a link to the SPDX licence text (fetched 2026-11-16); (b) the
   repository's own `LICENSE` file (fetched 2026-11-16) opens with the GNU Lesser General Public
   License, Version 2.1, February 1999. We use the engine unmodified, as a CLI tool invoked in CI —
   not statically linked into any shipped binary — consistent with how `cvss` (LGPL-3.0-or-later,
   D16) is already treated as an unmodified dependency.
2. **The rules** (the public Semgrep Registry, `github.com/semgrep/semgrep-rules`) are licensed
   separately, under the **Semgrep Rules License v1.0** — not an OSI-approved licence. Verified:
   the `semgrep-rules` repository page (fetched 2026-11-16) states contributions are licensed under
   "the Semgrep Rules License v. 1.0" and that the rules are "Free to use under the Semgrep Rules
   License." This licence permits free use of the rules for scanning your own code but restricts
   redistributing or reselling the ruleset itself (e.g. as a competing rules product) — a
   restriction that does not apply to VulnScope's use (we run the rules against our own CI, we do
   not redistribute them).

**Which ruleset VulnScope's CI uses:** the public `p/ci` registry pack (not Semgrep Pro/App rules,
which require a paid account and are out of scope entirely). This should be pinned by name and, once
`.github/workflows/ci.yml` is written in Task G, by the registry pack's resolved version/commit —
not invoked as `--config auto`, so the exact ruleset in force for any given CI run is reproducible
and auditable, consistent with the project's "pin everything" convention (image digests, lockfiles).

Both licences are exempt from `docs/licence-allowlist.txt` under the same OQ-6 reasoning as every
other row in this file: neither the LGPL-2.1 engine nor the Rules-License-governed rule pack is
shipped in any image or package VulnScope distributes — both run only inside CI, against our own
source tree.

## `scripts/with_task_db.py` (local helper, not CI)

Runs one command against a disposable per-task database on the dev Postgres
(`docker compose -p vulnscope -f docker-compose.dev.yml up -d`, 127.0.0.1:5432 only). It does not
start the stack itself; if the database is down it exits 69 with `database_reachable=false`.

```
python3 scripts/with_task_db.py --mode scratch --task b [--with-test-url] [--keep] [--lock-wait S] -- pytest ...
python3 scripts/with_task_db.py --mode task    --task d [--keep] [--lock-wait S] -- pytest ...
```

- `scratch`: the child gets `VULNSCOPE_MIGRATION_DATABASE_URL` and `VULNSCOPE_TEST_APP_DATABASE_URL`
  (shared database `vulnscope`, as the R1 plugin requires) and `VULNSCOPE_REQUIRE_INTEGRATION=1`.
  With `--with-test-url` it also gets `VULNSCOPE_TEST_DATABASE_URL` for a fresh migrated
  `vulnscope_task<letter>_<hex8>`.
- `task`: the child gets only the app-role `VULNSCOPE_DATABASE_URL` and `VULNSCOPE_TEST_DATABASE_URL`
  for that database. Admin credentials never reach the child (task-d PD-17).
- The child environment is built from PATH, HOME, LANG, VIRTUAL_ENV, PYTHONPATH plus the variables
  above; nothing else is inherited. Passwords come from the untracked `.env` (main checkout when run
  from a worktree; parent environment as fallback) and travel by environment only.
- Boolean guards before the child starts: host 127.0.0.1, port 5432, database name
  `^vulnscope_task[a-z]_[0-9a-f]{8}$`, exact child-environment shape. Row counts of `ledger_entries`,
  `chain_heads`, `checkpoints` in the shared `vulnscope` database are compared before and after; a
  difference exits 72. One repo-wide flock (`<git common dir>/vulnscope-db.lock`) covers the whole
  session; if held it exits 75 immediately unless `--lock-wait` is given.
- Output is fixed `with_task_db: key=bool|int` lines on stderr; no URL or password is printed. The
  child's own output passes through (the R1 plugin scrubs its own reports). Exit codes: child's code
  (128+signal when killed), 2 usage, 66 credentials/config, 69 unreachable, 70 guard, 71 database
  error or drop failure, 72 shared ledger changed, 73 migration failed, 75 lock held.
- Uses `asyncpg` (already a pinned dependency) for the admin statements and `alembic` for migration.
  Leftover `vulnscope_task*` databases (for example after SIGKILL or `--keep`) are not swept.
- Fix round 1: the repo root comes from the script's own location (needs `alembic.ini` and
  `src/vulnscope`), never the CWD; the shared database's `vulnscope.env=dev-disposable` marker is
  checked before any CREATE/DROP/migrate (exit 70 otherwise); `.env` must be owned by you and not
  group/world readable (exit 66); the child `PYTHONPATH` is pinned to the repo `src` and the parent's
  is ignored. The shared-ledger check compares row counts plus an md5 over every row's chain position
  and hash. It is detective only: it cannot see DDL, grants, or a change reverted before the second
  snapshot, and in `scratch` mode the child holds the migrator URL for the shared database.
