"""End-to-end CLI flow via Typer's test runner."""

import os

import pytest
from typer.testing import CliRunner

from scatterbox_cli.main import app

runner = CliRunner()


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("SCATTERBOX_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", "correct horse battery staple")
    return tmp_path


def _ok(result):
    assert result.exit_code == 0, result.output
    return result


def _text(result):
    """stdout + stderr regardless of how this click version captures them."""
    out = result.output
    try:
        out += result.stderr
    except (ValueError, AttributeError):
        pass
    return out


def test_cli_full_flow(env):
    tmp = env
    _ok(runner.invoke(app, ["init"]))

    for i in range(3):
        _ok(
            runner.invoke(
                app,
                ["provider", "add", f"p{i}", "--root", str(tmp / f"prov{i}")],
            )
        )
    listing = _ok(runner.invoke(app, ["provider", "list"]))
    assert "p0" in listing.output and "p2" in listing.output

    data = os.urandom(200_000)
    src = tmp / "report.bin"
    src.write_bytes(data)

    _ok(runner.invoke(app, ["put", str(src), "/docs/"]))
    listing = _ok(runner.invoke(app, ["ls", "/docs"]))
    assert "report.bin" in listing.output

    dst = tmp / "restored.bin"
    _ok(runner.invoke(app, ["get", "/docs/report.bin", str(dst)]))
    assert dst.read_bytes() == data

    _ok(runner.invoke(app, ["rm", "/docs/report.bin"]))
    result = runner.invoke(app, ["ls", "/docs"])
    assert result.exit_code == 1  # directory gone with its only file


def test_cli_uninitialized(env):
    result = runner.invoke(app, ["ls"])
    assert result.exit_code == 1
    assert "init" in _text(result)


def test_cli_wrong_passphrase(env, monkeypatch):
    _ok(runner.invoke(app, ["init"]))
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", "not the passphrase")
    src = env / "f.bin"
    src.write_bytes(b"data")
    result = runner.invoke(app, ["put", str(src), "/f.bin"])
    assert result.exit_code == 1
    assert "passphrase" in _text(result).lower()


def test_cli_replicas_option(env):
    tmp = env
    _ok(runner.invoke(app, ["init"]))
    for i in range(2):
        _ok(
            runner.invoke(
                app, ["provider", "add", f"p{i}", "--root", str(tmp / f"prov{i}")]
            )
        )
    src = tmp / "f.bin"
    src.write_bytes(b"hello world")

    # default of 3 replicas can't be met with 2 providers
    result = runner.invoke(app, ["put", str(src), "/f.bin"])
    assert result.exit_code == 1

    _ok(runner.invoke(app, ["put", str(src), "/f.bin", "--replicas", "2"]))


def test_cli_status_shows_health(env):
    tmp = env
    _ok(runner.invoke(app, ["init"]))
    for i in range(3):
        _ok(
            runner.invoke(
                app, ["provider", "add", f"p{i}", "--root", str(tmp / f"prov{i}")]
            )
        )
    src = tmp / "f.bin"
    src.write_bytes(os.urandom(10_000))
    _ok(runner.invoke(app, ["put", str(src), "/f.bin"]))

    result = _ok(runner.invoke(app, ["status", "/f.bin"]))
    assert "healthy" in result.output and "3/3" in result.output

    # silently delete one provider's replicas -> degraded after observation
    import sqlite3

    db = sqlite3.connect(tmp / "home" / "register.db")
    db.execute("UPDATE replicas SET state = 'suspect' WHERE provider_id = 1")
    db.commit()
    db.close()
    result = _ok(runner.invoke(app, ["status", "/f.bin"]))
    assert "degraded" in result.output and "2/3" in result.output

    result = runner.invoke(app, ["status", "/nope.bin"])
    assert result.exit_code == 1


def test_cli_rejects_nonlocalfs_provider(env):
    _ok(runner.invoke(app, ["init"]))
    result = runner.invoke(
        app, ["provider", "add", "g", "--type", "gdrive", "--root", str(env / "x")]
    )
    assert result.exit_code == 1
