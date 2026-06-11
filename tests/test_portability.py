"""Phase 4: export/import and provider-snapshot recovery (PLAN.md §9/§12).

Covers both phase gates:
1. export on machine A → import into a clean home → byte-identical restore;
2. destroy the local register → recover from passphrase + provider snapshot.
"""

import asyncio
import os

import pytest

from scatterbox import pipeline, portability, vault
from scatterbox.errors import ScatterboxError, WrongPassphraseError
from scatterbox.register import Register

PASS = "correct horse battery staple"


@pytest.fixture
def home(tmp_path):
    """An initialized 'machine A': vault, register, 3 providers, one file."""
    home = tmp_path / "home_a"
    home.mkdir()
    v = vault.create_vault(
        home / "vault.json", PASS, time_cost=1, memory_cost=8 * 1024, parallelism=1
    )
    reg = Register(home / "register.db")
    for i in range(3):
        reg.add_provider(f"p{i}", "localfs", {"root": str(tmp_path / f"prov{i}")})
    data = os.urandom(200_000)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    asyncio.run(pipeline.put_file(reg, v.master_key, src, "/docs/f.bin", secrets=v))
    yield {"home": home, "vault": v, "register": reg, "data": data, "tmp": tmp_path}
    reg.close()


def _restore_and_check(home_dir, passphrase, expected):
    v = vault.unlock_vault(home_dir / "vault.json", passphrase)
    reg = Register(home_dir / "register.db")
    try:
        out = home_dir / "restored.bin"
        asyncio.run(pipeline.get_file(reg, v.master_key, "/docs/f.bin", out, secrets=v))
        assert out.read_bytes() == expected
    finally:
        reg.close()


def test_encrypted_export_import_roundtrip(home, tmp_path):
    """Phase gate 1, encrypted register flavor."""
    reg_file, vault_file = portability.export_archive(
        home["register"], home["home"] / "vault.json", tmp_path / "backup",
        master_key=home["vault"].master_key,
    )
    assert reg_file.name == "register.sbsnap"
    assert reg_file.read_bytes().startswith(b"SBSNAP1\n")
    # the export leaks nothing: vpaths must not appear in the snapshot
    assert b"/docs/f.bin" not in reg_file.read_bytes()

    home_b = tmp_path / "home_b"
    v2, count = portability.import_archive(
        home_b,
        vault_bytes=vault_file.read_bytes(),
        register_blob=reg_file.read_bytes(),
        passphrase=PASS,
    )
    assert count == 1
    _restore_and_check(home_b, PASS, home["data"])


def test_plain_export_import_roundtrip(home, tmp_path):
    reg_file, vault_file = portability.export_archive(
        home["register"], home["home"] / "vault.json", tmp_path / "backup"
    )
    assert reg_file.name == "register.db"
    assert reg_file.read_bytes().startswith(b"SQLite format 3\x00")
    home_b = tmp_path / "home_b"
    _, count = portability.import_archive(
        home_b,
        vault_bytes=vault_file.read_bytes(),
        register_blob=reg_file.read_bytes(),
        passphrase=PASS,
    )
    assert count == 1
    _restore_and_check(home_b, PASS, home["data"])


def test_import_guards(home, tmp_path):
    reg_file, vault_file = portability.export_archive(
        home["register"], home["home"] / "vault.json", tmp_path / "backup",
        master_key=home["vault"].master_key,
    )
    # wrong passphrase fails before anything is installed
    home_b = tmp_path / "home_b"
    with pytest.raises(WrongPassphraseError):
        portability.import_archive(
            home_b,
            vault_bytes=vault_file.read_bytes(),
            register_blob=reg_file.read_bytes(),
            passphrase="nope",
        )
    assert not (home_b / "vault.json").exists()
    assert not (home_b / "register.db").exists()

    # garbage register refuses and leaves the home untouched
    with pytest.raises(ScatterboxError, match="neither"):
        portability.import_archive(
            home_b,
            vault_bytes=vault_file.read_bytes(),
            register_blob=b"definitely not a database",
            passphrase=PASS,
        )
    assert not (home_b / "vault.json").exists()

    # an initialized home is protected
    with pytest.raises(ScatterboxError, match="already initialized"):
        portability.import_archive(
            home["home"],
            vault_bytes=vault_file.read_bytes(),
            register_blob=reg_file.read_bytes(),
            passphrase=PASS,
        )


def test_snapshot_and_restore_from_providers(home, tmp_path):
    """Phase gate 2: destroy the register, recover from passphrase + vault."""
    reg, v = home["register"], home["vault"]
    names = asyncio.run(portability.snapshot_to_providers(reg, v))
    assert len(names) == 2  # >=2 of the most reliable providers
    assert v.has_secret(portability.SNAPSHOT_SECRET)
    locations = v.get_secret(portability.SNAPSHOT_SECRET)["locations"]
    assert len(locations) == 2

    # a second snapshot supersedes the first: old objects are deleted
    asyncio.run(portability.snapshot_to_providers(reg, v))
    snapshot_objects = [
        f
        for i in range(3)
        for f in (tmp_path / f"prov{i}").rglob("register-snapshot-*")
    ]
    assert len(snapshot_objects) == 2

    # disaster: the register is gone
    reg.close()
    os.remove(home["home"] / "register.db")

    # recovery needs only the vault + passphrase
    v2 = vault.unlock_vault(home["home"] / "vault.json", PASS)
    files, provider = asyncio.run(
        portability.restore_register_from_snapshot(home["home"], v2)
    )
    assert files == 1 and provider in ("p0", "p1", "p2")
    _restore_and_check(home["home"], PASS, home["data"])
    # keep the fixture teardown happy (it closes the register)
    home["register"] = Register(home["home"] / "register.db")


def test_restore_refuses_existing_register(home):
    asyncio.run(portability.snapshot_to_providers(home["register"], home["vault"]))
    with pytest.raises(ScatterboxError, match="already exists"):
        asyncio.run(
            portability.restore_register_from_snapshot(home["home"], home["vault"])
        )


def test_restore_without_snapshot_pointers(home, tmp_path):
    fresh = vault.create_vault(
        tmp_path / "fresh-vault.json", PASS, time_cost=1, memory_cost=8 * 1024, parallelism=1
    )
    with pytest.raises(ScatterboxError, match="no register-snapshot"):
        asyncio.run(
            portability.restore_register_from_snapshot(tmp_path / "nowhere", fresh)
        )


def test_snapshot_with_single_provider_is_best_effort(tmp_path):
    home = tmp_path / "single"
    home.mkdir()
    v = vault.create_vault(
        home / "vault.json", PASS, time_cost=1, memory_cost=8 * 1024, parallelism=1
    )
    reg = Register(home / "register.db")
    try:
        reg.add_provider("only", "localfs", {"root": str(tmp_path / "prov-only")})
        names = asyncio.run(portability.snapshot_to_providers(reg, v))
        assert names == ["only"]  # one copy beats zero
    finally:
        reg.close()


def test_cli_export_import_roundtrip(home, tmp_path, monkeypatch):
    """The CLI wrappers around the same core path."""
    from typer.testing import CliRunner

    from scatterbox_cli.main import app

    runner = CliRunner()
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", PASS)

    monkeypatch.setenv("SCATTERBOX_HOME", str(home["home"]))
    result = runner.invoke(app, ["export", str(tmp_path / "cli-backup")])
    assert result.exit_code == 0, result.output

    home_b = tmp_path / "cli-home-b"
    monkeypatch.setenv("SCATTERBOX_HOME", str(home_b))
    result = runner.invoke(
        app,
        [
            "import",
            str(tmp_path / "cli-backup" / "register.sbsnap"),
            str(tmp_path / "cli-backup" / "vault.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    _restore_and_check(home_b, PASS, home["data"])
