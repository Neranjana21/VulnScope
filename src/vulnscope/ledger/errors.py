"""Ledger exception types (pure, stdlib only).

Every message is FIXED text. Nothing in this module (or any exception built from it) ever carries
SQL, bound parameters, payload content, file paths, key material or caller input: a target-derived
string must not reach logs or tracebacks through an error (CLAUDE.md rules 6 and 9, threat T6).
"""
from __future__ import annotations

from typing import Literal

from vulnscope.ledger.types import VerifyResult

StorageOperation = Literal[
    "append", "read", "head", "count", "checkpoint_save", "checkpoint_load"
]
StorageCode = Literal[
    "lock_timeout",
    "statement_timeout",
    "unique_violation",
    "insufficient_privilege",
    "append_only_violation",
    "serialization",
    "connection",
    "seq_overflow",
    "pool_timeout",
    "head_diverged",
    "other",
]
RejectReason = Literal["no_verifier", "wrong_chain", "bad_signature", "malformed"]
RefuseReason = Literal["chain_not_verified"]


class LedgerError(Exception):
    """Base class of every error raised by ``vulnscope.ledger``."""


class CanonicalizationError(LedgerError, ValueError):
    """A value cannot be canonicalised: bad type, float, depth/size cap, bad ts, bad id grammar."""

    def __init__(self, message: str = "value cannot be canonicalised") -> None:
        super().__init__(message)


class LedgerStorageError(LedgerError):
    """A storage backend failed. Carries only an operation, a code and a SQLSTATE (never SQL,
    parameters or payload)."""

    def __init__(
        self, operation: StorageOperation, code: StorageCode, sqlstate: str | None = None
    ) -> None:
        self.operation: StorageOperation = operation
        self.code: StorageCode = code
        self.sqlstate: str | None = sqlstate
        super().__init__(f"ledger storage error: operation={operation} code={code}")


class CheckpointRejected(LedgerError):
    """A caller-supplied checkpoint is not trustworthy (a caller error, not a chain finding)."""

    def __init__(self, reason: RejectReason) -> None:
        self.reason: RejectReason = reason
        super().__init__(f"checkpoint rejected: {reason}")


class CheckpointRefused(LedgerError):
    """``maybe_checkpoint`` will not sign: the chain did not verify."""

    def __init__(self, reason: RefuseReason, result: VerifyResult | None = None) -> None:
        self.reason: RefuseReason = reason
        self.result: VerifyResult | None = result
        super().__init__(f"checkpoint refused: {reason}")


class SignerKeyError(LedgerError):
    """The signing key is missing, unsafe or malformed. ``check`` names only the failed check."""

    def __init__(self, check: str = "invalid") -> None:
        self.check = check
        super().__init__(f"signing key unusable: {check}")
