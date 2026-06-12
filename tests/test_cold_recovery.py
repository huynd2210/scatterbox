"""Cold recovery (PLAN.md §9, the path Phase 4 deferred): rebuild EVERYTHING
from the passphrase plus one re-authenticated provider — no vault file, no
register, no exports. Enabled by v2 snapshots (embedded KDF params) and the
adapters' find() method."""

import asyncio
import json
import os

import pytest

from scatterbox import onboarding, pipeline, portability, vault
from scatterbox.errors import ScatterboxError
from scatterbox.placement import Policy
from scatterbox.providers import create_provider
from scatterbox.register import Register
from scatterbox.vault import MemorySecretStore

PASS = "correct horse battery staple"
CHEAP_KDF = {"time_cost": 1, "memory_cost": 8 * 1024, "parallelism": 1}


@pytest.fixture
def home(tmp_path):
    """A full 'machine A': vault, 3 localfs providers, a file, a snapshot."""
    home = tmp_path / "home"
    home.mkdir()
    v = vault.create_vault(home / "vault.json", PASS, **CHEAP_KDF)
    reg = Register(home / "register.db")
    for i in range(3):
        reg.add_provider(f"p{i}", "localfs", {"root": str(tmp_path / f"prov{i}")})
    data = os.urandom(150_000)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    asyncio.run(pipeline.put_file(reg, v.master_key, src, "/docs/f.bin", secrets=v))
    asyncio.run(portability.snapshot_to_providers(reg, v))
    reg.close()
    return {"home": home, "tmp": tmp_path, "data": data, "vault": v}


# -- snapshot v2 format ---------------------------------------------------------


def test_v2_snapshot_embeds_kdf_and_decrypts_from_passphrase(home):
    snap = (home["tmp"] / "prov0" / "sc" / portability.SNAPSHOT_OBJECT_NAME).read_bytes()
    assert portability.is_snapshot(snap)
    kdf = portability.snapshot_kdf(snap)
    assert kdf == home["vault"].kdf and kdf["algo"] == "argon2id"
    db_bytes, kdf2 = portability.decrypt_snapshot_with_passphrase(snap, PASS)
    assert db_bytes.startswith(b"SQLite format 3\x00") and kdf2 == kdf

    with pytest.raises(ScatterboxError, match="wrong passphrase"):
        portability.decrypt_snapshot_with_passphrase(snap, "nope")


def test_v1_snapshot_refuses_cold_path(home):
    v1 = portability.encrypt_snapshot(b"x" * 100, home["vault"].master_key)  # no kdf
    assert portability.snapshot_kdf(v1) is None
    with pytest.raises(ScatterboxError, match="predates cold recovery"):
        portability.decrypt_snapshot_with_passphrase(v1, PASS)
    # ...but the warm (vault) path still reads it
    assert portability.decrypt_snapshot(v1, home["vault"].master_key) == b"x" * 100


def test_fixed_name_survives_resnapshot(home):
    """Same-name rewrites must not be deleted as 'previous generation'."""
    reg = Register(home["home"] / "register.db")
    try:
        asyncio.run(portability.snapshot_to_providers(reg, home["vault"]))
        asyncio.run(portability.snapshot_to_providers(reg, home["vault"]))
    finally:
        reg.close()
    snaps = [
        f
        for i in range(3)
        for f in (home["tmp"] / f"prov{i}").rglob(portability.SNAPSHOT_OBJECT_NAME)
    ]
    assert len(snaps) == 2  # the two most-reliable targets, each intact
    for snap in snaps:
        portability.decrypt_snapshot_with_passphrase(snap.read_bytes(), PASS)


# -- the cold gate ----------------------------------------------------------------


def test_cold_recovery_gate(home):
    """Wipe the ENTIRE home — vault included — and come back from the
    passphrase + one provider. The salt round-trip is the crux: the
    recreated vault must unwrap the restored register's file keys."""
    os.remove(home["home"] / "vault.json")
    os.remove(home["home"] / "register.db")

    provider = create_provider("localfs", {"root": str(home["tmp"] / "prov1")})
    v, files = asyncio.run(
        portability.recover_register_cold(home["home"], PASS, provider)
    )
    assert files == 1
    assert v.kdf == home["vault"].kdf  # original salt preserved
    assert v.master_key == home["vault"].master_key

    # the recreated vault unlocks normally and the file restores end to end
    v2 = vault.unlock_vault(home["home"] / "vault.json", PASS)
    reg = Register(home["home"] / "register.db")
    try:
        assert onboarding.pending_reauth(reg, v2) == []  # localfs: no creds
        out = home["tmp"] / "restored.bin"
        asyncio.run(pipeline.get_file(reg, v2.master_key, "/docs/f.bin", out, secrets=v2))
        assert out.read_bytes() == home["data"]
    finally:
        reg.close()


def test_cold_recovery_guards(home, tmp_path):
    provider = create_provider("localfs", {"root": str(home["tmp"] / "prov0")})
    # an initialized home is protected
    with pytest.raises(ScatterboxError, match="already has a vault"):
        asyncio.run(portability.recover_register_cold(home["home"], PASS, provider))
    # wrong passphrase fails before anything is written
    fresh = tmp_path / "fresh"
    with pytest.raises(ScatterboxError, match="wrong passphrase"):
        asyncio.run(portability.recover_register_cold(fresh, "nope", provider))
    assert not (fresh / "vault.json").exists()
    # a provider that never held a snapshot says so
    empty = create_provider("localfs", {"root": str(tmp_path / "never-used")})
    with pytest.raises(ScatterboxError, match="no .* object found"):
        asyncio.run(portability.recover_register_cold(fresh, PASS, empty))
    # an adapter without find() is rejected with guidance
    class NoFind:
        pass

    with pytest.raises(ScatterboxError, match="find"):
        asyncio.run(portability.find_snapshot(NoFind()))


def test_adopt_recovered_credentials(home):
    reg = Register(home["home"] / "register.db")
    try:
        reg.add_provider("gd", "gdrive", {"secret": "provider:gd"})
        blob = {"access_token": "at", "refresh_token": "rt", "client_id": "cid"}
        store = MemorySecretStore()
        v = vault.Vault(master_key=bytes(32))
        assert (
            portability.adopt_recovered_credentials(reg, v, "gdrive", blob) == "gd"
        )
        assert v.get_secret("provider:gd") == blob
        assert store is not None  # silence unused warning paths

        # ambiguity requires a name; unknown type is loud
        reg.add_provider("gd2", "gdrive", {"secret": "provider:gd2"})
        with pytest.raises(ScatterboxError, match="several"):
            portability.adopt_recovered_credentials(reg, v, "gdrive", blob)
        assert (
            portability.adopt_recovered_credentials(reg, v, "gdrive", blob, name="gd2")
            == "gd2"
        )
        with pytest.raises(ScatterboxError, match="no 'onedrive' provider"):
            portability.adopt_recovered_credentials(reg, v, "onedrive", blob)
        assert onboarding.pending_reauth(reg, v) == []
    finally:
        reg.close()


# -- entry points -----------------------------------------------------------------


def test_cli_cold_recovery(home, tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from scatterbox_cli.main import app

    os.remove(home["home"] / "vault.json")
    os.remove(home["home"] / "register.db")
    monkeypatch.setenv("SCATTERBOX_HOME", str(home["home"]))
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", PASS)

    runner = CliRunner()
    # prov2 was not a snapshot target (only the 2 most reliable are) — the
    # error must say so, then prov0 works
    result = runner.invoke(
        app, ["recover", "--type", "localfs", "--root", str(home["tmp"] / "prov2")]
    )
    assert result.exit_code == 1
    result = runner.invoke(
        app, ["recover", "--type", "localfs", "--root", str(home["tmp"] / "prov0")]
    )
    assert result.exit_code == 0, result.output
    assert "recovered register with 1 file(s)" in result.output

    dst = tmp_path / "out.bin"
    result = runner.invoke(app, ["get", "/docs/f.bin", str(dst)])
    assert result.exit_code == 0, result.output
    assert dst.read_bytes() == home["data"]


def test_daemon_recover_endpoint_and_snapshot_only_import(home, tmp_path):
    from fastapi.testclient import TestClient

    from scatterbox_daemon import create_app

    snap_bytes = (
        home["tmp"] / "prov0" / "sc" / portability.SNAPSHOT_OBJECT_NAME
    ).read_bytes()
    os.remove(home["home"] / "vault.json")
    os.remove(home["home"] / "register.db")

    # /api/recover on the wiped home (wizard's third choice)
    with TestClient(create_app(home["home"])) as client:
        assert client.get("/api/status").json()["initialized"] is False
        resp = client.post(
            "/api/recover",
            json={"passphrase": "nope", "type": "localfs", "root": str(home["tmp"] / "prov0")},
        )
        assert resp.status_code == 400  # wrong passphrase, home untouched
        resp = client.post(
            "/api/recover",
            json={"passphrase": PASS, "type": "localfs", "root": str(home["tmp"] / "prov0")},
        )
        assert resp.status_code == 200, resp.text
        assert resp.json() == {"files": 1, "adopted": None, "pending_reauth": []}
        status = client.get("/api/status").json()
        assert status["initialized"] is True and status["locked"] is False
        assert client.get("/api/download", params={"path": "/docs/f.bin"}).content == home["data"]
        assert client.post("/api/recover", json={"passphrase": PASS, "type": "localfs", "root": "x"}).status_code == 409

    # a lone v2 .sbsnap through /api/import does the same on another machine
    home_b = tmp_path / "home_b"
    home_b.mkdir()
    with TestClient(create_app(home_b)) as client:
        resp = client.post(
            "/api/import",
            files={"files": ("register.sbsnap", snap_bytes)},
            data={"passphrase": PASS},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["files"] == 1 and body["restored_from"] == "snapshot"
        listing = client.get("/api/files", params={"path": "/docs"}).json()
        assert [f["name"] for f in listing["files"]] == ["f.bin"]


def test_reauth_provider(home, monkeypatch):
    """reauth writes fresh tokens under the EXISTING secret name, reusing
    stored client credentials, and never touches the register row."""
    calls = {}

    def fake_flow(**kwargs):
        calls.update(kwargs)
        return {"access_token": "new", "refresh_token": "new-r", "client_id": kwargs["client_id"]}

    from scatterbox import oauth

    monkeypatch.setattr(oauth, "run_loopback_flow", fake_flow)

    class StubProvider:
        async def quota(self):
            from scatterbox.providers.base import Quota

            return Quota(total_bytes=10, used_bytes=1, confidence="exact")

    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: StubProvider())

    v = home["vault"]
    reg = Register(home["home"] / "register.db")
    try:
        reg.add_provider("gd", "gdrive", {"secret": "provider:gd"})
        # no stored credentials and none supplied -> clear guidance
        with pytest.raises(ScatterboxError, match="client id"):
            onboarding.reauth_provider(reg, v, "gd")
        # explicit credentials work...
        onboarding.reauth_provider(reg, v, "gd", client_id="cid", client_secret="shh")
        assert v.get_secret("provider:gd")["access_token"] == "new"
        assert calls["client_id"] == "cid" and calls["client_secret"] == "shh"
        # ...and are reused on the next reauth without retyping
        calls.clear()
        onboarding.reauth_provider(reg, v, "gd")
        assert calls["client_id"] == "cid"
        # non-OAuth providers are refused
        with pytest.raises(ScatterboxError, match="does not use OAuth"):
            onboarding.reauth_provider(reg, v, "p0")
    finally:
        reg.close()
