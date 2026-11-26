"""The demo command end to end (sync test: the command owns its event loop)."""

from __future__ import annotations

import importlib
import os
from pathlib import Path

import pytest
from devpath import LABEL

from vulnscope.config import Settings

pytestmark = pytest.mark.integration


def test_demo_prints_fixed_keys_and_writes_the_report(
    settings: Settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    demo = importlib.import_module("devpath.step1")
    assert demo.main(["--out", str(tmp_path)]) == 0
    out = capsys.readouterr()
    assert out.err == ""
    lines = out.out.splitlines()
    assert lines[0] == LABEL and lines[-1] == LABEL
    for needle in (
        "step=insecure outcome=issue finding_status=confirmed",
        "rule_id=ALLOW",
        "header=x-frame-options verdict=absent",
        "step=redirect outcome=inconclusive observation=redirect_not_followed finding=none",
        "step=verify result=ok",
        "evidence_checks_ok=true",
        "report_check=ok report_problems=0",
        "kind=engagement.created",
        "report_written=true",
    ):
        assert needle in out.out, needle
    for forbidden in ("REVOKED", "postgresql", "169.254", "http://", str(tmp_path)):
        assert forbidden not in out.out, forbidden
    url = os.environ["VULNSCOPE_DATABASE_URL"]
    assert url not in out.out
    document = (tmp_path / "report.html").read_text(encoding="utf-8")
    assert LABEL in document and "Limits of this assessment" in document
    assert "MISMATCH" not in document
