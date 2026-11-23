"""Ed25519 checkpoint signing. Imports ``cryptography`` only (no sqlalchemy, no env, no config).

Key handling by reference (rule 6, threat T6): ``Ed25519FileSigner.load`` takes a PATH, never key
bytes. Every check uses the OPENED file descriptor (``fstat``), never ``stat(path)``, so there is no
check-then-open race. The key object is never logged, never repr'd, never pickled or copied, and no
error message carries key material, file content or the path. Verification-only callers use
``Ed25519PublicVerifier`` so the private key never enters a process that only verifies.
"""
from __future__ import annotations

import os
import re
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, Protocol, Self

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from vulnscope.ledger.errors import SignerKeyError

_MAX_KEY_FILE_BYTES = 4096
_PUBKEY_RE = re.compile(r"[0-9a-f]{64}")


class SignatureVerifier(Protocol):
    @property
    def public_key_hex(self) -> str: ...

    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class LedgerSigner(SignatureVerifier, Protocol):
    def sign(self, payload: bytes) -> bytes: ...


def _raw_public_hex(key: Ed25519PublicKey) -> str:
    return key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def _verify_with(key: Ed25519PublicKey, payload: bytes, signature: bytes) -> bool:
    try:
        key.verify(signature, payload)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


class Ed25519PublicVerifier:
    """Verification only."""

    __slots__ = ("_key", "_hex")

    def __init__(self, key: Ed25519PublicKey) -> None:
        self._key = key
        self._hex = _raw_public_hex(key)

    @classmethod
    def from_hex(cls, public_key_hex: str) -> Self:
        if (
            type(public_key_hex) is not str
            or not public_key_hex.isascii()
            or _PUBKEY_RE.fullmatch(public_key_hex) is None
        ):
            raise SignerKeyError("bad_public_key")
        key: Ed25519PublicKey | None = None
        try:
            key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        except ValueError:
            pass
        if key is None:  # raised outside the handler: no __context__ (PB-8)
            raise SignerKeyError("bad_public_key")
        return cls(key)

    @property
    def public_key_hex(self) -> str:
        return self._hex

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return _verify_with(self._key, payload, signature)

    def __repr__(self) -> str:
        return f"Ed25519PublicVerifier(public_key={self._hex})"


class MultiKeyVerifier:
    """Accepts a signature from ANY of several keys (rotation does not strand old checkpoints)."""

    __slots__ = ("_keys",)

    def __init__(self, keys: Sequence[SignatureVerifier]) -> None:
        if not keys:
            raise SignerKeyError("no_keys")
        self._keys = tuple(keys)

    @property
    def public_key_hex(self) -> str:
        return ",".join(k.public_key_hex for k in self._keys)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return any(k.verify(payload, signature) for k in self._keys)

    def __repr__(self) -> str:
        return f"MultiKeyVerifier(public_keys={self.public_key_hex})"


def _refuse(*_: object, **__: object) -> NoReturn:
    raise TypeError("signer key material cannot be copied or pickled")


class Ed25519FileSigner:
    """Signs with a key loaded from a file; also verifies (its own public key)."""

    __slots__ = ("_key", "_hex")

    def __init__(self, key: Ed25519PrivateKey) -> None:
        self._key = key
        self._hex = _raw_public_hex(key.public_key())

    @classmethod
    def load(cls, key_path: Path) -> Self:
        """Fails closed (``SignerKeyError``, fixed text naming only the failed check)."""
        parent = os.path.dirname(os.fspath(key_path)) or "."
        fd = -1
        try:
            fd = os.open(os.fspath(key_path), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            pass
        if fd < 0:
            raise SignerKeyError("open_failed")
        try:
            data = cls._read_checked(fd, parent)
        finally:
            os.close(fd)
        key: object = None
        try:
            key = serialization.load_pem_private_key(data, password=None)
        except (ValueError, TypeError, UnsupportedAlgorithm):
            pass
        if key is None:
            raise SignerKeyError("malformed")
        if not isinstance(key, Ed25519PrivateKey):
            raise SignerKeyError("wrong_key_type")
        return cls(key)

    @staticmethod
    def _read_checked(fd: int, parent: str) -> bytes:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise SignerKeyError("not_regular_file")
        if st.st_uid != os.geteuid():
            raise SignerKeyError("wrong_owner")
        if st.st_mode & 0o077:
            raise SignerKeyError("unsafe_mode")
        if not st.st_mode & stat.S_IRUSR:
            raise SignerKeyError("not_readable")
        if st.st_size == 0 or st.st_size > _MAX_KEY_FILE_BYTES:
            raise SignerKeyError("bad_size")
        dfd = -1
        try:
            dfd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        except OSError:
            pass
        if dfd < 0:
            raise SignerKeyError("parent_unreadable")
        try:
            if os.fstat(dfd).st_mode & 0o022:
                raise SignerKeyError("unsafe_parent")
        finally:
            os.close(dfd)
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, _MAX_KEY_FILE_BYTES + 1 - total)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_KEY_FILE_BYTES:
                raise SignerKeyError("bad_size")
        return b"".join(chunks)

    @classmethod
    def generate_to_file(cls, key_path: Path) -> Self:
        """Dev tooling only: ``O_EXCL``, mode 0600, never overwrites, never implicit on load."""
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        fd = -1
        try:
            fd = os.open(
                os.fspath(key_path),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
            )
        except OSError:
            pass
        if fd < 0:
            raise SignerKeyError("create_failed")
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, pem)
            os.fsync(fd)
        finally:
            os.close(fd)
        return cls(key)

    @property
    def public_key_hex(self) -> str:
        return self._hex

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return _verify_with(self._key.public_key(), payload, signature)

    def __repr__(self) -> str:
        return f"Ed25519FileSigner(public_key={self._hex})"

    __reduce__ = _refuse
    __reduce_ex__ = _refuse
    __getstate__ = _refuse
    __copy__ = _refuse
    __deepcopy__ = _refuse
