# ruff: noqa: E501
"""Pure check (no database) that ``_dbkit.assert_pg_error`` is as strict as it claims.

Builds the same shape SQLAlchemy's asyncpg adapter produces: a ``DBAPIError`` whose ``.orig`` is
a wrapper and whose real asyncpg error is ``.orig.__cause__``. It must accept the right class and
SQLSTATE and reject a wrong SQLSTATE, a wrong class, a missing message, and a non-asyncpg cause.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from asyncpg.exceptions import InsufficientPrivilegeError, RaiseError, UniqueViolationError
from sqlalchemy.exc import DBAPIError

_INTEGRATION_DIR = Path(__file__).resolve().parents[1]
if str(_INTEGRATION_DIR) not in sys.path:
    sys.path.insert(0, str(_INTEGRATION_DIR))

from _dbkit import assert_pg_error  # noqa: E402


class _AdapterWrapper(Exception):
    """Stand-in for SQLAlchemy's AsyncAdapt_asyncpg_dbapi wrapper."""


def _wrapped(cause: BaseException) -> DBAPIError:
    wrapper = _AdapterWrapper("wrapper")
    wrapper.__cause__ = cause
    return DBAPIError("stmt", None, wrapper)


def test_accepts_matching_class_sqlstate_and_message() -> None:
    assert_pg_error(
        _wrapped(InsufficientPrivilegeError("permission denied for table x")),
        sqlstate="42501",
        exc_name="InsufficientPrivilegeError",
    )
    assert_pg_error(
        _wrapped(RaiseError("ledger_entries are append-only; UPDATE is not permitted")),
        sqlstate="P0001",
        exc_name="RaiseError",
        message="append-only",
    )


def test_rejects_wrong_sqlstate_or_class() -> None:
    with pytest.raises(AssertionError):
        assert_pg_error(
            _wrapped(UniqueViolationError("dup")), sqlstate="42501", exc_name="InsufficientPrivilegeError"
        )
    with pytest.raises(AssertionError):  # right class name, wrong expected SQLSTATE
        assert_pg_error(
            _wrapped(InsufficientPrivilegeError("x")), sqlstate="P0001", exc_name="InsufficientPrivilegeError"
        )
    with pytest.raises(AssertionError):  # right SQLSTATE family, wrong class
        assert_pg_error(_wrapped(RaiseError("x")), sqlstate="P0001", exc_name="InsufficientPrivilegeError")


def test_rejects_missing_message_and_non_asyncpg_cause() -> None:
    with pytest.raises(AssertionError):
        assert_pg_error(
            _wrapped(RaiseError("something else")), sqlstate="P0001", exc_name="RaiseError", message="append-only"
        )
    with pytest.raises(AssertionError):
        assert_pg_error(_wrapped(ValueError("nope")), sqlstate="42501", exc_name="InsufficientPrivilegeError")
    with pytest.raises(AssertionError):
        assert_pg_error(ValueError("not a DBAPIError"), sqlstate="42501", exc_name="InsufficientPrivilegeError")
