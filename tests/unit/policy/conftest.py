"""Unit-test conftest for policy/: puts the hostile corpus on sys.path."""

from __future__ import annotations

import sys
from pathlib import Path

_CORPUS = Path(__file__).resolve().parents[2] / "fixtures" / "target_corpus"
if str(_CORPUS) not in sys.path:
    sys.path.insert(0, str(_CORPUS))
