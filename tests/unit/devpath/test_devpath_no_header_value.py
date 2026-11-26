"""The tiny no-value test: stub bytes never reach evidence, ledger payload, logs or errors."""

from __future__ import annotations

import logging

import pytest
from devpath.stub import RunningStub
from test_devpath_transport import Harness

from vulnscope.validate.evidence import build_evidence
from vulnscope.validate.security_headers import evaluate
from vulnscope.validate.types import HEADER_NAMES

CANARY = "canary-7f3a9c"


def _hostile(status_line: str) -> bytes:
    lines = [status_line.replace("REASON", CANARY)]
    lines += [f"{name}: {CANARY}" for name in HEADER_NAMES[:3]]
    lines += [f"Location: http://{CANARY}.invalid/{CANARY}", f"Set-Cookie: s={CANARY}"]
    lines += [f"X-{CANARY}: {CANARY}", "Content-Length: 0"]
    return ("\r\n".join(lines) + "\r\n\r\n" + CANARY).encode()


@pytest.mark.parametrize(
    "status_line",
    ["HTTP/1.1 200 REASON", "HTTP/1.1 302 REASON", "HTTP/1.1 500 REASON"],
)
async def test_no_target_text_reaches_evidence_ledger_logs_or_output(
    status_line: str, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
) -> None:
    caplog.set_level(logging.DEBUG)
    harness = Harness()
    with RunningStub(raw_response=_hostile(status_line)) as stub:
        decision, response = await harness.head(stub)
    assert response is not None
    result = evaluate(response)
    evidence = build_evidence(result)
    captured = capsys.readouterr()
    everything = "".join(
        [
            repr(decision),
            repr(response),
            repr(response.headers),
            repr(result),
            evidence.excerpt,
            repr(harness.ledger.entries),
            caplog.text,
            captured.out,
            captured.err,
        ]
    )
    assert CANARY not in everything
