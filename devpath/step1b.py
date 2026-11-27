"""STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.

ADR-0014 command (``python -m devpath.step1b``). It takes no target, host or port: the
only target is the sealed ``JUICE_SHOP`` object, 127.0.0.1 on its fixed port. The port
cannot identify the application, so the operator attests what listens there. It starts
no server, container or other process. One HEAD of ``/``, the same five-header presence
check and the same guarded path as ``devpath.step1``. Output follows that command's
rules: fixed keys, ids, counts, rule ids and constants only, never exception text.

Exit codes: 0 for a completed check (issue or no issue) with the ledger and report
checks ok; 1 for anything else, including a failed connection (no finding); 2 for a
usage error or configuration refusal.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from devpath import LABEL
from devpath.engagement import ConfigRefused, require_task_database, seed_engagement
from devpath.runner import collect_report, run_check
from devpath.step1 import _checks_ok, _joined, _Parser, _rule, _say, _UsageError
from devpath.targets import JUICE_SHOP
from vulnscope.config import Settings
from vulnscope.db.session import get_async_engine
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.report.render import render_report
from vulnscope.validate.types import HEADER_NAMES

DEFAULT_OUT = ".reports/step1b"  # git-ignored
REPORT_FILE = "report.html"


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="python -m devpath.step1b", description=LABEL, allow_abbrev=False)
    parser.add_argument("--out", default=DEFAULT_OUT, help="directory for the HTML report")
    return parser


async def _run(out: Path) -> int:
    settings = Settings()
    url = require_task_database(settings)  # before any engine or socket
    engine = get_async_engine(url)  # SQL echo is off by default
    try:
        seeded = await seed_engagement(settings=settings, engine=engine, target=JUICE_SHOP)
        ids: dict[str, Any] = {
            "settings": settings,
            "engine": engine,
            "engagement_id": seeded.engagement_id,
            "org_id": seeded.org_id,
        }
        _say(step="seed", engagement_id=seeded.engagement_id)
        _say(target_identity="not_verified", lab_isolation="not_verified")

        result = await run_check(stub=JUICE_SHOP, **ids)
        model = await collect_report(outcome=result.outcome, target_kind="lab_app", **ids)

        status = next((f.status for f in model.findings if f.id == result.finding_id), "none")
        _say(
            step="lab_app",
            outcome=result.outcome,
            finding_status=status if status in ("none", "confirmed") else "unexpected",
            finding_id=result.finding_id or "none",
            observation=result.detail or "none",
            decision_seq=_joined(result.decision_seqs),
            rule_id=_rule(model, result),
        )
        for item in model.evidence:
            if item.finding_id != result.finding_id:
                continue
            _say(evidence_id=item.id, ledger_seq=item.ledger_seq)
            # Print our own constants, never the stored text.
            lines = item.redacted_excerpt.split("\n")
            for name in HEADER_NAMES:
                verdict = next(
                    (v for v in ("absent", "present") if f"{name}: {v}" in lines), "mismatch"
                )
                _say(header=name, verdict=verdict)

        _say(step="verify", result=model.verify.result, records=model.verify.records)
        chain = f"engagement:{seeded.engagement_id}"
        async for entry in PostgresChainBackend(engine).read(chain):
            _say(ledger="entry", seq=entry.seq, kind=entry.kind)
        checks_ok = _checks_ok(model)
        _say(evidence_checks_ok=str(checks_ok).lower(), checked=len(model.evidence_checks))
        _say(report_check=model.integrity.status, report_problems=len(model.integrity.problems))

        out.mkdir(parents=True, exist_ok=True)
        (out / REPORT_FILE).write_text(render_report(model), encoding="utf-8")
        _say(report_written="true", report_file=REPORT_FILE)

        if result.outcome == "issue":
            completed = status == "confirmed" and checks_ok
        else:
            completed = result.outcome == "no_issue" and not model.findings
        ok = completed and model.verify.result == "ok" and model.integrity.status == "ok"
        return 0 if ok else 1
    finally:
        await engine.dispose()


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except _UsageError:
        _say(usage_error="true")
        return 2
    previous = logging.root.manager.disable
    logging.disable(logging.CRITICAL)
    print(LABEL)
    try:
        code = asyncio.run(_run(Path(args.out)))
    except ConfigRefused as refusal:
        _say(refused=refusal.code)
        return 2
    except BaseException as exc:  # noqa: B036 - class name only, whatever was raised
        _say(error=type(exc).__name__)
        return 1
    finally:
        logging.disable(previous)
    print(LABEL)
    return code


if __name__ == "__main__":
    sys.exit(main())
