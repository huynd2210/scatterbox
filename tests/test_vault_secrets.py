"""Vault v2: the encrypted secrets section (TASKS.md Phase 2 §1)."""

import base64
import json

import pytest

from scatterbox.errors import ScatterboxError, WrongPassphraseError
from scatterbox.vault import create_vault, unlock_vault

PASS = "correct horse battery staple"


@pytest.fixture
def vault_path(tmp_path):
    return tmp_path / "vault.json"


def test_secrets_roundtrip_across_unlocks(vault_path):
    v = create_vault(vault_path, PASS)
    blob = {"access_token": "tok", "refresh_token": "ref", "expires_at": 123.0}
    v.set_secret("provider:gd", blob)
    v.set_secret("provider:od", {"refresh_token": "other"})

    v2 = unlock_vault(vault_path, PASS)
    assert v2.get_secret("provider:gd") == blob
    assert v2.get_secret("provider:od") == {"refresh_token": "other"}
    assert v2.has_secret("provider:gd")

    v2.delete_secret("provider:gd")
    v3 = unlock_vault(vault_path, PASS)
    assert not v3.has_secret("provider:gd")
    with pytest.raises(ScatterboxError, match="no secret named"):
        v3.get_secret("provider:gd")
    # delete is idempotent
    v3.delete_secret("provider:gd")


def test_vault_file_never_contains_plaintext_secrets(vault_path):
    v = create_vault(vault_path, PASS)
    v.set_secret("provider:gd", {"refresh_token": "SUPERSECRETTOKENVALUE"})
    raw = vault_path.read_text(encoding="utf-8")
    assert "SUPERSECRETTOKENVALUE" not in raw
    assert "provider:gd" not in raw  # even names are inside the blob


def test_v1_vault_upgrades_on_first_write(vault_path):
    create_vault(vault_path, PASS)
    # Regress the file to its Phase 0 shape: version 1, no secrets section.
    doc = json.loads(vault_path.read_text(encoding="utf-8"))
    doc["version"] = 1
    doc.pop("secrets", None)
    vault_path.write_text(json.dumps(doc), encoding="utf-8")

    v = unlock_vault(vault_path, PASS)  # v1 unlocks fine, no secrets
    assert not v.has_secret("anything")
    v.set_secret("k", "v")
    doc = json.loads(vault_path.read_text(encoding="utf-8"))
    assert doc["version"] == 2 and "secrets" in doc
    assert unlock_vault(vault_path, PASS).get_secret("k") == "v"


def test_corrupt_secrets_section_fails_loudly(vault_path):
    v = create_vault(vault_path, PASS)
    v.set_secret("k", "v")
    doc = json.loads(vault_path.read_text(encoding="utf-8"))
    blob = bytearray(base64.b64decode(doc["secrets"]))
    blob[-1] ^= 0xFF  # flip a tag byte
    doc["secrets"] = base64.b64encode(bytes(blob)).decode()
    vault_path.write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(ScatterboxError, match="secrets section is corrupt"):
        unlock_vault(vault_path, PASS)


def test_wrong_passphrase_still_rejected(vault_path):
    v = create_vault(vault_path, PASS)
    v.set_secret("k", "v")
    with pytest.raises(WrongPassphraseError):
        unlock_vault(vault_path, "not the passphrase")
