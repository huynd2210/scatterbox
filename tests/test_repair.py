"""Repair: below-floor chunks are re-replicated onto different providers;
unrepairable chunks are reported loudly."""

import asyncio
import json
import os

from typer.testing import CliRunner

from scatterbox import scrubber
from scatterbox.providers import ChaosProvider, LocalFSProvider

from conftest import MASTER_KEY, add_chaos_providers, get, put

CHUNK = 1024


def _store(register, tmp_path, n=5, size=2 * CHUNK + 100):
    pids = add_chaos_providers(register, tmp_path, n=n)
    data = os.urandom(size)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    put(register, src, "/f.bin", chunk_size=CHUNK)
    return pids, data


def _twin(register, provider_id) -> ChaosProvider:
    config = json.loads(register.get_provider(provider_id)["config"])
    return ChaosProvider(LocalFSProvider(config["root"]), seed=config.get("seed", 0))


def _scrub_repair(register, **kwargs):
    return asyncio.run(scrubber.scrub(register, repair=True, **kwargs))


def _live_providers_per_chunk(register) -> dict[int, set[int]]:
    rows = register.conn.execute(
        "SELECT chunk_id, provider_id FROM replicas WHERE state = 'stored'"
    ).fetchall()
    out: dict[int, set[int]] = {}
    for row in rows:
        out.setdefault(row["chunk_id"], set()).add(row["provider_id"])
    return out


def test_repair_restores_floor_on_different_providers(tmp_path, register):
    pids, data = _store(register, tmp_path, n=5)
    before = _live_providers_per_chunk(register)
    used = set().union(*before.values())
    # delete replicas down to one copy: wipe all but the first used provider
    keep = min(used)
    for pid in used - {keep}:
        _twin(register, pid).drop_chunks(1.0)

    report = _scrub_repair(register)
    assert report.repaired > 0 and not report.unrepairable
    assert register.chunks_below_floor() == []

    after = _live_providers_per_chunk(register)
    for chunk_id, providers in after.items():
        assert len(providers) >= 3  # floor met...
        assert keep in providers
        assert providers - {keep} <= set(pids) - (used - {keep})  # ...on new homes

    dst = tmp_path / "dst.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data


def test_repair_skips_corrupt_source_replicas(tmp_path, register):
    pids, data = _store(register, tmp_path, n=4)
    used = sorted(set().union(*_live_providers_per_chunk(register).values()))
    _twin(register, used[0]).corrupt_chunks(1.0)  # bad bytes, still "exists"
    _twin(register, used[1]).drop_chunks(1.0)

    # deep scrub: corrupt -> lost, dropped -> suspect; repair from the clean copy
    report = _scrub_repair(register, deep=True)
    assert not report.unrepairable
    assert register.chunks_below_floor() == []
    dst = tmp_path / "dst.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data


def test_unrepairable_chunks_reported_loudly(tmp_path, register):
    pids, _ = _store(register, tmp_path, n=3, size=CHUNK // 2)
    for pid in set().union(*_live_providers_per_chunk(register).values()):
        _twin(register, pid).drop_chunks(1.0)  # zero surviving replicas

    report = _scrub_repair(register)
    assert report.repaired == 0
    assert len(report.unrepairable) == 1
    assert "no surviving replica" in report.unrepairable[0]
    assert "/f.bin" in report.unrepairable[0]


def test_scrub_cli_repair_and_loud_failure(tmp_path, monkeypatch):
    from scatterbox_cli.main import app

    runner = CliRunner()
    monkeypatch.setenv("SCATTERBOX_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", "pw")
    assert runner.invoke(app, ["init"]).exit_code == 0
    for i in range(4):
        assert (
            runner.invoke(
                app,
                ["provider", "add", f"c{i}", "--type", "localfs", "--root", str(tmp_path / f"p{i}")],
            ).exit_code
            == 0
        )
    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(4096))
    assert runner.invoke(app, ["put", str(src), "/f.bin"]).exit_code == 0

    result = runner.invoke(app, ["scrub", "--repair"])
    assert result.exit_code == 0, result.output
    assert "scrubbed" in result.output

    # wipe every provider -> scrub --repair fails loudly
    for i in range(4):
        for p in (tmp_path / f"p{i}").rglob("*"):
            if p.is_file():
                p.unlink()
    runner.invoke(app, ["scrub"])  # stored -> suspect
    result = runner.invoke(app, ["scrub", "--repair"])
    assert result.exit_code == 1
