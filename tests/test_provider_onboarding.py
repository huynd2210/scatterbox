"""CLI provider onboarding/management (TASKS.md Phase 2 §5–6).

The OAuth dance and the real adapter are stubbed at the CLI module's seams
(run_loopback_flow / create_provider); what's under test is the wiring:
secrets land in the vault, config lands in the register, failures roll back.
"""

import json
import os
import time

import pytest
from typer.testing import CliRunner

import scatterbox_cli.main as cli
from scatterbox import oauth, onboarding
from scatterbox.errors import ScatterboxError
from scatterbox.providers import create_provider, requires_secrets
from scatterbox.providers.base import Quota
from scatterbox.register import Register
from scatterbox.vault import unlock_vault

runner = CliRunner()
PASS = "correct horse battery staple"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SCATTERBOX_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", PASS)
    assert runner.invoke(cli.app, ["init"]).exit_code == 0
    return tmp_path


def _ok(result):
    assert result.exit_code == 0, result.output
    return result


FAKE_BLOB = {
    "access_token": "at",
    "refresh_token": "rt",
    "expires_at": time.time() + 3600,
    "client_id": "cid",
    "token_url": "https://token.example/",
}


class StubProvider:
    """What the CLI needs from an adapter at onboarding time."""

    def __init__(self, quota_exc=None):
        self._quota_exc = quota_exc

    async def quota(self):
        if self._quota_exc:
            raise self._quota_exc
        return Quota(total_bytes=1000, used_bytes=100, confidence="exact")

    async def prepare(self):
        pass

    def learned_config(self):
        return {"folder_id": "fold42"}


@pytest.fixture
def stub_oauth(monkeypatch):
    calls = {}

    def fake_flow(**kwargs):
        calls.update(kwargs)
        return dict(FAKE_BLOB)

    # onboarding (shared by CLI and daemon) calls oauth.run_loopback_flow
    monkeypatch.setattr(oauth, "run_loopback_flow", fake_flow)
    return calls


def test_gdrive_onboarding_happy_path(env, stub_oauth, monkeypatch):
    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: StubProvider())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "gd", "--type", "gdrive", "--client-id", "cid"],
            input="shh\n",  # client secret prompt
        )
    )
    # tokens + client app credentials are in the vault...
    home = env / "home"
    v = unlock_vault(home / "vault.json", PASS)
    assert v.get_secret("provider:gd")["refresh_token"] == "rt"
    # ...and the register row carries only non-secret config
    reg = Register(home / "register.db")
    row = reg.get_provider_by_name("gd")
    config = json.loads(row["config"])
    reg.close()
    assert row["type"] == "gdrive"
    assert config["secret"] == "provider:gd"
    assert config["folder_id"] == "fold42"  # learned at onboarding
    assert "rt" not in row["config"] and "shh" not in row["config"]
    # the flow was driven with the adapter's endpoints
    assert stub_oauth["client_id"] == "cid"
    assert stub_oauth["client_secret"] == "shh"
    assert "drive.file" in stub_oauth["scopes"]


def test_onedrive_onboarding_has_no_client_secret(env, stub_oauth, monkeypatch):
    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: StubProvider())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "od", "--type", "onedrive", "--client-id", "cid"],
        )
    )
    assert stub_oauth["client_secret"] is None
    assert "Files.ReadWrite.AppFolder" in stub_oauth["scopes"]


def test_failed_connection_test_rolls_back_the_secret(env, stub_oauth, monkeypatch):
    monkeypatch.setattr(
        onboarding,
        "create_provider",
        lambda t, c, s=None: StubProvider(quota_exc=ScatterboxError("boom")),
    )
    result = runner.invoke(
        cli.app,
        ["provider", "add", "gd", "--type", "gdrive", "--client-id", "cid"],
        input="shh\n",
    )
    assert result.exit_code == 1
    home = env / "home"
    assert not unlock_vault(home / "vault.json", PASS).has_secret("provider:gd")
    reg = Register(home / "register.db")
    with pytest.raises(ScatterboxError):
        reg.get_provider_by_name("gd")
    reg.close()


def test_duplicate_name_fails_before_oauth(env, stub_oauth, monkeypatch):
    _ok(runner.invoke(cli.app, ["provider", "add", "p", "--root", str(env / "p")]))
    result = runner.invoke(
        cli.app, ["provider", "add", "p", "--type", "gdrive", "--client-id", "x"]
    )
    assert result.exit_code == 1
    assert stub_oauth == {}  # never reached the browser


def test_unknown_type_fails(env):
    result = runner.invoke(cli.app, ["provider", "add", "x", "--type", "dropbox"])
    assert result.exit_code == 1


def test_provider_remove_guards_live_replicas(env):
    for i in range(3):
        _ok(
            runner.invoke(
                cli.app, ["provider", "add", f"p{i}", "--root", str(env / f"p{i}")]
            )
        )
    src = env / "f.bin"
    src.write_bytes(os.urandom(50_000))
    _ok(runner.invoke(cli.app, ["put", str(src), "/f.bin"]))

    result = runner.invoke(cli.app, ["provider", "remove", "p0"])
    assert result.exit_code == 1  # refuses: replicas live there

    _ok(runner.invoke(cli.app, ["provider", "remove", "p0", "--force"]))
    home = env / "home"
    reg = Register(home / "register.db")
    with pytest.raises(ScatterboxError):
        reg.get_provider_by_name("p0")
    below = reg.chunks_below_floor()
    reg.close()
    assert below  # dropped replicas show up as repair work, not silence


def test_provider_set_updates_and_clears_limits(env):
    _ok(runner.invoke(cli.app, ["provider", "add", "p", "--root", str(env / "p")]))
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "set", "p", "--max-object-bytes", "1048576", "--capacity-bytes", "5000000"],
        )
    )
    home = env / "home"
    reg = Register(home / "register.db")
    config = json.loads(reg.get_provider_by_name("p")["config"])
    assert config["max_object_bytes"] == 1048576
    assert config["capacity_bytes"] == 5000000
    reg.close()

    _ok(runner.invoke(cli.app, ["provider", "set", "p", "--max-object-bytes", "0"]))
    reg = Register(home / "register.db")
    config = json.loads(reg.get_provider_by_name("p")["config"])
    reg.close()
    assert "max_object_bytes" not in config
    assert config["capacity_bytes"] == 5000000

    result = runner.invoke(cli.app, ["provider", "set", "p"])
    assert result.exit_code == 1  # nothing to change


def test_max_object_bytes_limit_shrinks_chunks(env):
    """Phase gate: a 1 MiB per-object cap is respected by the write path."""
    for i in range(3):
        _ok(
            runner.invoke(
                cli.app,
                [
                    "provider", "add", f"p{i}", "--root", str(env / f"p{i}"),
                    "--max-object-bytes", str(1024 * 1024),
                ],
            )
        )
    src = env / "big.bin"
    data = os.urandom(3 * 1024 * 1024)  # 3 MiB -> must split into >2 chunks
    src.write_bytes(data)
    _ok(runner.invoke(cli.app, ["put", str(src), "/big.bin"]))

    # every stored object on every provider fits the cap
    for i in range(3):
        for f in (env / f"p{i}").rglob("*"):
            if f.is_file():
                assert f.stat().st_size <= 1024 * 1024
    dst = env / "restored.bin"
    _ok(runner.invoke(cli.app, ["get", "/big.bin", str(dst)]))
    assert dst.read_bytes() == data


def test_secret_typed_provider_requires_unlocked_vault():
    """Library-level guard: instantiating gdrive/onedrive without the vault
    fails with guidance instead of a KeyError deep inside an adapter."""
    assert requires_secrets("gdrive") and requires_secrets("onedrive")
    assert not requires_secrets("localfs")
    with pytest.raises(ScatterboxError, match="unlock"):
        create_provider("gdrive", {"secret": "provider:x"})
