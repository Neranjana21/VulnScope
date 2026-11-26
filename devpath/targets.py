"""STEP 1 DEVELOPMENT PATH: no gateway, no worker, not the security boundary.

ADR-0014: the one lab app target besides our own stub. It is a sealed marker with no
state. The sender compares it by identity and takes the port from the constant below,
never from the object, the command line, the environment, a file or the database.

The port cannot identify the application: whatever listens on it receives the request.
"""

from __future__ import annotations

from typing import Final

JUICE_SHOP_PORT: Final = 3000


class LabTarget:
    """Only the object ``JUICE_SHOP`` is accepted; any other instance is refused."""

    __slots__ = ()


JUICE_SHOP: Final = LabTarget()
