"""STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.

Demo command (``python -m devpath.step1``). It takes no target, host or port: it starts
its own stubs. It prints only fixed keys, ids, counts, rule ids and constants from this
code base; on an unexpected error only the exception class name (SEC-6 is not delivered,
so exception text, which can echo database parameters, is never printed and logging is
switched off for the run).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, NoReturn

from devpath import LABEL
from devpath.engagement import ConfigRefused, require_task_database, seed_engagement
from devpath.runner import RunOutcome, collect_report, run_check
from devpath.stub import RunningStub
from vulnscope.config import Settings
from vulnscope.db.session import get_async_engine
from vulnscope.ledger.postgres_backend import PostgresChainBackend
from vulnscope.report.model import ReportModel
from vulnscope.report.render import render_report
from vulnscope.validate.types import HEADER_NAMES

DEFAULT_OUT = ".reports/step1"  # git-ignored
REPORT_FILE = "report.html"


class _UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:  # never echo argument values
        raise _UsageError


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="python -m devpath.step1", description=LABEL, allow_abbrev=False)
    parser.add_argument("--out", default=DEFAULT_OUT, help="directory for the HTML report")
    return parser


def _say(**fields: object) -> None:
    print(" ".join(f"{key}={value}" for key, value in fields.items()))


def _rule(model: ReportModel, result: RunOutcome) -> str:
    return next(
        (d.rule_id for d in model.decisions if d.ledger_seq in result.decision_seqs), "none"
    )


def _joined(seqs: Sequence[int]) -> str:
    return ",".join(str(seq) for seq in seqs) or "none"


async def _demo(out: Path) -> int:
    settings = Settings()
    url = require_task_database(settings)  # before any engine, stub or socket
    engine = get_async_engine(url)  # SQL echo is off by default
    try:
        seeded = await seed_engagement(settings=settings, engine=engine)
        ids: dict[str, Any] = {
            "settings": settings,
            "engine": engine,
            "engagement_id": seeded.engagement_id,
            "org_id": seeded.org_id,
        }
        _say(step="seed", engagement_id=seeded.engagement_id)

        with RunningStub("insecure") as stub:
            first = await run_check(stub=stub, **ids)
            first_requests = stub.request_count
        with RunningStub("redirect") as stub:
            second = await run_check(stub=stub, **ids)
            second_requests = stub.request_count

        model = await collect_report(outcome=first.outcome, **ids)

        status = next((f.status for f in model.findings if f.id == first.finding_id), "none")
        _say(
            step="insecure",
            outcome=first.outcome,
            finding_status="confirmed" if status == "confirmed" else "unexpected",
            finding_id=first.finding_id or "none",
            decision_seq=_joined(first.decision_seqs),
            rule_id=_rule(model, first),
            stub_requests=first_requests,
        )
        for item in model.evidence:
            if item.finding_id != first.finding_id:
                continue
            _say(evidence_id=item.id, ledger_seq=item.ledger_seq)
            # Print our own constants, never the stored text.
            lines = item.redacted_excerpt.split("\n")
            for name in HEADER_NAMES:
                verdict = next(
                    (v for v in ("absent", "present") if f"{name}: {v}" in lines), "mismatch"
                )
                _say(header=name, verdict=verdict)
        _say(
            step="redirect",
            outcome=second.outcome,
            observation=second.detail or "none",
            finding=second.finding_id or "none",
            decision_seq=_joined(second.decision_seqs),
            rule_id=_rule(model, second),
            stub_requests=second_requests,
        )

        _say(step="verify", result=model.verify.result, records=model.verify.records)
        chain = f"engagement:{seeded.engagement_id}"
        async for entry in PostgresChainBackend(engine).read(chain):
            _say(ledger="entry", seq=entry.seq, kind=entry.kind)
        checks_ok = bool(model.evidence_checks) and all(model.evidence_checks.values())
        _say(evidence_checks_ok=str(checks_ok).lower(), checked=len(model.evidence_checks))

        out.mkdir(parents=True, exist_ok=True)
        (out / REPORT_FILE).write_text(render_report(model), encoding="utf-8")
        _say(report_written="true", report_file=REPORT_FILE)

        expected = (
            first.outcome == "issue"
            and status == "confirmed"
            and (second.outcome, second.detail, second.finding_id)
            == ("inconclusive", "redirect_not_followed", None)
            and model.verify.result == "ok"
            and checks_ok
        )
        return 0 if expected else 1
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
        code = asyncio.run(_demo(Path(args.out)))
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
