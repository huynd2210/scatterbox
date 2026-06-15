"""CLI provider onboarding/management (TASKS.md Phase 2 §5–6).

The OAuth dance and the real adapter are stubbed at the CLI module's seams
(run_loopback_flow / create_provider); what's under test is the wiring:
secrets land in the vault, config lands in the register, failures roll back.
"""

import base64
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
    assert stub_oauth["fixed_port"] is None  # any loopback port matches


def test_dropbox_onboarding_pins_the_redirect_port(env, stub_oauth, monkeypatch):
    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: StubProvider())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "db", "--type", "dropbox", "--client-id", "appkey"],
        )
    )
    assert stub_oauth["client_secret"] is None  # public client + PKCE
    assert "files.content.write" in stub_oauth["scopes"]
    # Dropbox checks redirect URIs against exact registered values
    assert stub_oauth["fixed_port"] == 8421
    assert stub_oauth["extra_auth_params"] == {"token_access_type": "offline"}


def test_pcloud_onboarding_is_confidential_and_non_refreshing(env, stub_oauth, monkeypatch):
    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: StubProvider())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "pc", "--type", "pcloud", "--client-id", "appid"],
            input="shh\n",  # confidential client: secret prompt, like gdrive
        )
    )
    assert stub_oauth["client_secret"] == "shh"
    assert stub_oauth["scopes"] == ""  # pCloud has no scope parameter
    # pCloud pins its redirect port, issues no refresh token, and region-resolves
    assert stub_oauth["fixed_port"] == 8422
    assert stub_oauth["require_refresh_token"] is False
    assert stub_oauth["token_url_resolver"] is not None
    # folder id learned at onboarding lands in the register row
    home = env / "home"
    reg = Register(home / "register.db")
    config = json.loads(reg.get_provider_by_name("pc")["config"])
    reg.close()
    assert config["folder_id"] == "fold42"


def test_koofr_onboarding_stores_a_basic_app_password(env, monkeypatch):
    """Koofr is secret-backed but not OAuth: the CLI prompts for an email +
    app password (no browser), stores it as a Basic credential, and registers
    the row with only non-secret config."""

    class KoofrStub:
        async def quota(self):
            return Quota(total_bytes=1000, used_bytes=100, confidence="exact")

        async def prepare(self):
            pass

        def learned_config(self):
            return {"mount_id": "m1"}

    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: KoofrStub())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "kf", "--type", "koofr"],
            input="alice@koofr.test\napp-pw-123\n",  # email, then app password
        )
    )
    home = env / "home"
    v = unlock_vault(home / "vault.json", PASS)
    blob = v.get_secret("provider:kf")
    # the app password is stored as a precomputed HTTP Basic credential,
    # not OAuth tokens — nothing to expire or refresh
    assert base64.b64decode(blob["access_token"]).decode() == "alice@koofr.test:app-pw-123"
    assert "refresh_token" not in blob and "expires_at" not in blob
    # ...and the register row carries only non-secret config
    reg = Register(home / "register.db")
    row = reg.get_provider_by_name("kf")
    config = json.loads(row["config"])
    reg.close()
    assert row["type"] == "koofr"
    assert config["secret"] == "provider:kf"
    assert config["mount_id"] == "m1"  # learned at onboarding
    assert "app-pw-123" not in row["config"]  # the secret never hits the register


def test_r2_onboarding_stores_keys_in_vault_and_bucket_in_register(env, monkeypatch):
    """Cloudflare R2 is secret-backed but not OAuth: the CLI prompts for the
    account id + bucket (non-secret) and the S3 access key/secret (vault), and
    registers a row whose config carries the bucket but never the secret."""

    class R2Stub:
        async def quota(self):
            return Quota(total_bytes=None, used_bytes=0, confidence="unknown")

    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: R2Stub())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "r2", "--type", "r2"],
            input="acct123\nmybucket\nAKIDXYZ\nSECRETXYZ\n",  # account, bucket, key, secret
        )
    )
    home = env / "home"
    v = unlock_vault(home / "vault.json", PASS)
    blob = v.get_secret("provider:r2")
    # only the S3 key/secret are stored, and nothing OAuth-shaped
    assert blob == {"access_key_id": "AKIDXYZ", "secret_access_key": "SECRETXYZ"}
    assert "refresh_token" not in blob and "expires_at" not in blob
    reg = Register(home / "register.db")
    row = reg.get_provider_by_name("r2")
    config = json.loads(row["config"])
    reg.close()
    assert row["type"] == "r2"
    assert config["secret"] == "provider:r2"
    # non-secret location lands in the register (extra_config), the secret never
    assert config["account_id"] == "acct123" and config["bucket"] == "mybucket"
    assert "SECRETXYZ" not in row["config"]


def test_oracle_onboarding_stores_keys_in_vault_and_bucket_in_register(env, monkeypatch):
    """Oracle Object Storage is secret-backed but not OAuth: the CLI prompts for
    the namespace/region/bucket (non-secret) and the S3 access key/secret
    (vault), and registers a row whose config carries the bucket but never the
    secret."""

    class OracleStub:
        async def quota(self):
            return Quota(total_bytes=None, used_bytes=0, confidence="unknown")

    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: OracleStub())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "or", "--type", "oracle"],
            # namespace, region, bucket, access key, secret
            input="myns\nus-ashburn-1\nmybucket\nAKIDXYZ\nSECRETXYZ\n",
        )
    )
    home = env / "home"
    v = unlock_vault(home / "vault.json", PASS)
    blob = v.get_secret("provider:or")
    assert blob == {"access_key_id": "AKIDXYZ", "secret_access_key": "SECRETXYZ"}
    assert "refresh_token" not in blob and "expires_at" not in blob
    reg = Register(home / "register.db")
    row = reg.get_provider_by_name("or")
    config = json.loads(row["config"])
    reg.close()
    assert row["type"] == "oracle"
    assert config["secret"] == "provider:or"
    # non-secret location lands in the register (extra_config), the secret never
    assert config["namespace"] == "myns" and config["region"] == "us-ashburn-1"
    assert config["bucket"] == "mybucket"
    assert "SECRETXYZ" not in row["config"]


def test_tigris_onboarding_stores_keys_in_vault_and_bucket_in_register(env, monkeypatch):
    """Tigris is secret-backed but not OAuth: the CLI prompts for the bucket
    (non-secret) and the S3 access key/secret (vault), and registers a row whose
    config carries the bucket but never the secret."""

    class TigrisStub:
        async def quota(self):
            return Quota(total_bytes=None, used_bytes=0, confidence="unknown")

    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: TigrisStub())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "tg", "--type", "tigris"],
            input="mybucket\nAKIDXYZ\nSECRETXYZ\n",  # bucket, access key, secret
        )
    )
    home = env / "home"
    v = unlock_vault(home / "vault.json", PASS)
    blob = v.get_secret("provider:tg")
    assert blob == {"access_key_id": "AKIDXYZ", "secret_access_key": "SECRETXYZ"}
    assert "refresh_token" not in blob and "expires_at" not in blob
    reg = Register(home / "register.db")
    row = reg.get_provider_by_name("tg")
    config = json.loads(row["config"])
    reg.close()
    assert row["type"] == "tigris"
    assert config["secret"] == "provider:tg"
    assert config["bucket"] == "mybucket"  # non-secret location (extra_config)
    assert "SECRETXYZ" not in row["config"]


def test_vercel_blob_onboarding_stores_a_bearer_token(env, monkeypatch):
    """Vercel Blob is secret-backed but not OAuth: the CLI prompts for a single
    read-write token (no browser), stores it as a static bearer credential, and
    registers a row with only non-secret config."""

    class VercelStub:
        async def quota(self):
            return Quota(total_bytes=None, used_bytes=0, confidence="unknown")

    monkeypatch.setattr(onboarding, "create_provider", lambda t, c, s=None: VercelStub())
    _ok(
        runner.invoke(
            cli.app,
            ["provider", "add", "vb", "--type", "vercel_blob"],
            input="vercel_rw_tok_123\n",  # the read-write token
        )
    )
    home = env / "home"
    v = unlock_vault(home / "vault.json", PASS)
    blob = v.get_secret("provider:vb")
    # the token is stored as a static bearer credential, not OAuth tokens
    assert blob == {"access_token": "vercel_rw_tok_123"}
    assert "refresh_token" not in blob and "expires_at" not in blob
    reg = Register(home / "register.db")
    row = reg.get_provider_by_name("vb")
    config = json.loads(row["config"])
    reg.close()
    assert row["type"] == "vercel_blob"
    assert config["secret"] == "provider:vb"
    assert "vercel_rw_tok_123" not in row["config"]  # the token never hits the register


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
