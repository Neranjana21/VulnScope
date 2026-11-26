"""Make the repository root importable: ``devpath`` lives outside ``src``."""

from __future__ import annotations

import sys
from pathlib import Path

_ROOT = str(Path(__file__).resolve().parents[3])
if _ROOT not in sys.path:
    sys.path.append(_ROOT)
