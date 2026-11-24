"""Short, bounded database transactions (PD-24, PD-10). A transaction is NEVER held open across a
ledger call: every helper here is one self-contained unit."""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.exc import TimeoutError as SaTimeoutError
from sqlalchemy.ext.asyncio import AsyncSession

from vulnscope.api.problem import Detail, ProblemError
from vulnscope.api.state import AppState
from vulnscope.errors import ReasonCode

_TIMEOUT_SQLSTATES = {"55P03", "57014"}  # lock_not_available, query_canceled (statement timeout)


def _unavailable() -> ProblemError:
    return ProblemError(503, ReasonCode.UNAVAILABLE, Detail.UNAVAILABLE,
                        headers={"Retry-After": "1"})


@asynccontextmanager
async def db_tx(state: AppState) -> AsyncIterator[AsyncSession]:
    """One transaction with ``SET LOCAL`` lock and statement timeouts and a wall-clock budget."""
    t = state.timeouts
    try:
        async with asyncio.timeout(t.db_op_budget_s):
            async with state.sessionmaker() as session:
                async with session.begin():
                    # literal integers from trusted constants: no bind parameters needed
                    await session.execute(
                        text(f"SET LOCAL lock_timeout = '{int(t.lock_timeout_ms)}ms'"))
                    await session.execute(
                        text(f"SET LOCAL statement_timeout = '{int(t.statement_timeout_ms)}ms'"))
                    yield session
    except DBAPIError as exc:
        # class and SQLSTATE only: the exception text can carry statement parameters
        if getattr(getattr(exc, "orig", None), "sqlstate", None) in _TIMEOUT_SQLSTATES:
            raise _unavailable() from None
        raise
    except SaTimeoutError:
        raise _unavailable() from None
    except TimeoutError:
        raise _unavailable() from None


@asynccontextmanager
async def db_read(state: AppState) -> AsyncIterator[AsyncSession]:
    """A read-only unit (one implicit transaction, rolled back on exit) with a budget."""
    try:
        async with asyncio.timeout(state.timeouts.db_op_budget_s):
            async with state.sessionmaker() as session:
                yield session
    except SaTimeoutError:
        raise _unavailable() from None
    except TimeoutError:
        raise _unavailable() from None
