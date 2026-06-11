"""Vault stub: create/unlock round-trip, wrong passphrase rejected."""

import pytest

from scatterbox import keys, vault
from scatterbox.errors import ScatterboxError, WrongPassphraseError

# cheap KDF params to keep tests fast; defaults are for real use
FAST_KDF = {"time_cost": 1, "memory_cost": 8 * 1024, "parallelism": 1}


def test_create_and_unlock(tmp_path):
    path = tmp_path / "vault.json"
    created = vault.create_vault(path, "correct horse battery", **FAST_KDF)
    unlocked = vault.unlock_vault(path, "correct horse battery")
    assert unlocked.master_key == created.master_key
    assert len(unlocked.master_key) == 32


def test_wrong_passphrase(tmp_path):
    path = tmp_path / "vault.json"
    vault.create_vault(path, "right", **FAST_KDF)
    with pytest.raises(WrongPassphraseError):
        vault.unlock_vault(path, "wrong")


def test_no_double_create(tmp_path):
    path = tmp_path / "vault.json"
    vault.create_vault(path, "pw", **FAST_KDF)
    with pytest.raises(ScatterboxError):
        vault.create_vault(path, "pw", **FAST_KDF)


def test_missing_vault(tmp_path):
    with pytest.raises(ScatterboxError):
        vault.unlock_vault(tmp_path / "nope.json", "pw")


def test_wrap_unwrap_key():
    master = bytes(range(32))
    file_key = bytes(reversed(range(32)))
    blob = keys.wrap_key(master, file_key)
    assert keys.unwrap_key(master, blob) == file_key
    with pytest.raises(ScatterboxError):
        keys.unwrap_key(b"\x01" * 32, blob)
