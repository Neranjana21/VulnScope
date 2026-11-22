# ruff: noqa: E501
"""Signing key loading (path only, fstat on the opened descriptor, never logged) and rotation."""
from __future__ import annotations

import copy
import logging
import os
import pickle
import stat
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vulnscope.ledger.errors import SignerKeyError
from vulnscope.ledger.signer import Ed25519FileSigner, Ed25519PublicVerifier, MultiKeyVerifier

SEED = bytes(range(32))
SEED_HEX = SEED.hex()


def _pem(key: object | None = None) -> bytes:
    key = key or Ed25519PrivateKey.from_private_bytes(SEED)
    return key.private_bytes(  # type: ignore[attr-defined,no-any-return]
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _write(tmp_path: Path, data: bytes, mode: int = 0o600, name: str = "k.pem") -> Path:
    d = tmp_path / "keys"
    d.mkdir(mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    p = d / name
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.chmod(p, mode)
    return p


def _fails(path: Path, check: str) -> None:
    with pytest.raises(SignerKeyError) as info:
        Ed25519FileSigner.load(path)
    assert info.value.check == check


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_owner_only_modes_load(tmp_path: Path, mode: int) -> None:
    s = Ed25519FileSigner.load(_write(tmp_path, _pem(), mode))
    assert s.public_key_hex == Ed25519PublicVerifier.from_hex(s.public_key_hex).public_key_hex


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o660, 0o604, 0o606])
def test_group_or_other_bits_are_refused(tmp_path: Path, mode: int) -> None:
    _fails(_write(tmp_path, _pem(), mode), "unsafe_mode")


def test_symlink_is_refused(tmp_path: Path) -> None:
    real = _write(tmp_path, _pem())
    link = real.parent / "link.pem"
    link.symlink_to(real)
    _fails(link, "open_failed")


def test_missing_and_directory_and_oversize_and_empty_are_refused(tmp_path: Path) -> None:
    _fails(tmp_path / "nope.pem", "open_failed")
    d = tmp_path / "dir"
    d.mkdir()
    _fails(d, "not_regular_file")
    _fails(_write(tmp_path, b"A" * 5000, name="big.pem"), "bad_size")
    _fails(_write(tmp_path, b"", name="empty.pem"), "bad_size")


def test_wrong_key_types_and_garbage_are_refused(tmp_path: Path) -> None:
    _fails(_write(tmp_path, _pem(rsa.generate_private_key(65537, 2048)), name="rsa.pem"), "wrong_key_type")
    _fails(_write(tmp_path, _pem(ec.generate_private_key(ec.SECP256R1())), name="ec.pem"), "wrong_key_type")
    _fails(_write(tmp_path, b"not a pem", name="junk.pem"), "malformed")


def test_group_writable_parent_directory_is_refused(tmp_path: Path) -> None:
    p = _write(tmp_path, _pem())
    os.chmod(p.parent, 0o770)
    try:
        _fails(p, "unsafe_parent")
    finally:
        os.chmod(p.parent, 0o700)


def test_checks_use_the_opened_descriptor_not_a_path_stat(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    p = _write(tmp_path, _pem())

    def no_path_stat(*_: object, **__: object) -> os.stat_result:
        raise AssertionError("path-based stat used")

    monkeypatch.setattr(os, "stat", no_path_stat)
    monkeypatch.setattr(Path, "stat", no_path_stat)
    assert Ed25519FileSigner.load(p).public_key_hex


@pytest.mark.skipif(os.geteuid() == 0, reason="needs a non-root uid to test ownership")
def test_file_owned_by_someone_else_is_refused_when_not_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    p = _write(tmp_path, _pem())
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(p).st_uid + 1)
    _fails(p, "wrong_owner")


def test_generate_to_file_is_exclusive_and_owner_only(tmp_path: Path) -> None:
    d = tmp_path / "gen"
    d.mkdir(mode=0o700)
    p = d / "new.pem"
    s = Ed25519FileSigner.generate_to_file(p)
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert Ed25519FileSigner.load(p).public_key_hex == s.public_key_hex
    with pytest.raises(SignerKeyError):
        Ed25519FileSigner.generate_to_file(p)  # never overwrites


def test_load_never_generates_a_key(tmp_path: Path) -> None:
    p = tmp_path / "absent.pem"
    with pytest.raises(SignerKeyError):
        Ed25519FileSigner.load(p)
    assert not p.exists()


def test_sign_and_verify_round_trip_and_wrong_key(tmp_path: Path) -> None:
    s = Ed25519FileSigner.load(_write(tmp_path, _pem()))
    sig = s.sign(b"m")
    assert len(sig) == 64 and s.verify(b"m", sig) and not s.verify(b"n", sig)
    other = Ed25519PublicVerifier.from_hex(
        Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33))).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex())
    assert not other.verify(b"m", sig)
    assert not s.verify(b"m", b"short") and not s.verify(b"m", b"")


def test_key_material_never_appears_in_repr_str_dict_errors_or_logs(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG)
    p = _write(tmp_path, _pem())
    pem_text = _pem().decode()
    body = [ln for ln in pem_text.splitlines() if "-----" not in ln][0]
    s = Ed25519FileSigner.load(p)
    s.sign(b"x")
    texts = [repr(s), str(s), repr(Ed25519PublicVerifier.from_hex(s.public_key_hex)), caplog.text]
    for bad in (_write(tmp_path, b"junk" + SEED, name="j.pem", mode=0o600),):
        with pytest.raises(SignerKeyError) as info:
            Ed25519FileSigner.load(bad)
        texts += [str(info.value), repr(info.value)]
    assert not hasattr(s, "__dict__")
    for t in texts:
        assert SEED_HEX not in t and body not in t and str(p) not in t


def test_pickling_and_copying_the_signer_are_refused(tmp_path: Path) -> None:
    s = Ed25519FileSigner.load(_write(tmp_path, _pem()))
    for fn in (pickle.dumps, copy.copy, copy.deepcopy):
        with pytest.raises(TypeError):
            fn(s)


def test_multi_key_verifier_rotation(tmp_path: Path) -> None:
    old = Ed25519FileSigner.load(_write(tmp_path, _pem(), name="old.pem"))
    new_key = Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
    new = Ed25519FileSigner.load(_write(tmp_path, _pem(new_key), name="new.pem"))
    third = Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))
    multi = MultiKeyVerifier([new, old])
    assert multi.verify(b"m", old.sign(b"m")) and multi.verify(b"m", new.sign(b"m"))
    assert not multi.verify(b"m", third.sign(b"m"))
    with pytest.raises(SignerKeyError):
        MultiKeyVerifier([])


def test_public_verifier_rejects_malformed_hex() -> None:
    for bad in ("", "zz" * 32, "ab" * 31, "AB" * 32, "ab" * 32 + "\n"):
        with pytest.raises(SignerKeyError):
            Ed25519PublicVerifier.from_hex(bad)
