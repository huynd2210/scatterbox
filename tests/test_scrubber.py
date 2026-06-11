"""Scrubber: injected failures are detected within one cycle and the right
provider's reliability score decays."""

import asyncio
import json
import os
from pathlib import Path

from scatterbox import scrubber
from scatterbox.providers import ChaosProvider, LocalFSProvider

from conftest import add_chaos_providers, put

CHUNK = 1024


def _store(register, tmp_path, size=3 * CHUNK, n=3, name="/f.bin"):
    pids = add_chaos_providers(register, tmp_path, n=n)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(size))
    put(register, src, name, chunk_size=CHUNK)
    return pids


def _twin(register, provider_id) -> ChaosProvider:
    """ChaosProvider over the same root, for injecting damage."""
    config = json.loads(register.get_provider(provider_id)["config"])
    return ChaosProvider(LocalFSProvider(config["root"]), seed=config.get("seed", 0))


def _scrub(register, **kwargs) -> scrubber.ScrubReport:
    return asyncio.run(scrubber.scrub(register, **kwargs))


def _states_on(register, provider_id) -> set[str]:
    rows = register.conn.execute(
        "SELECT state FROM replicas WHERE provider_id = ?", (provider_id,)
    ).fetchall()
    return {row["state"] for row in rows}


def test_clean_cheap_pass_confirms_everything(tmp_path, register):
    _store(register, tmp_path)
    report = _scrub(register)
    assert report.probed == report.confirmed == 9  # 3 chunks x 3 replicas
    assert report.marked_suspect == report.marked_lost == 0
    verified = register.conn.execute(
        "SELECT COUNT(*) AS n FROM replicas WHERE last_verified IS NOT NULL"
    ).fetchone()["n"]
    assert verified == 9


def test_cheap_pass_marks_dropped_replicas_suspect(tmp_path, register):
    pids = _store(register, tmp_path)
    dropped = _twin(register, pids[1]).drop_chunks(1.0)  # silent delete, all of c1
    assert dropped

    report = _scrub(register)
    assert report.marked_suspect == 3
    assert _states_on(register, pids[1]) == {"suspect"}
    assert _states_on(register, pids[0]) == {"stored"}

    # the damaged provider's score decayed sharply; the clean ones rose
    prior = 0.99
    assert register.get_reliability(pids[1], prior=prior) < 0.5
    assert register.get_reliability(pids[0], prior=prior) > prior

    # second missed cycle: suspect -> lost
    report = _scrub(register)
    assert report.marked_lost == 3
    assert _states_on(register, pids[1]) == {"lost"}


def test_killed_provider_demoted_within_one_cycle(tmp_path, register):
    pids = _store(register, tmp_path)
    config = json.loads(register.get_provider(pids[2])["config"])
    register.update_provider_config(pids[2], {**config, "killed": True})

    report = _scrub(register)
    assert report.marked_suspect == 3
    assert _states_on(register, pids[2]) == {"suspect"}
    assert register.get_reliability(pids[2], prior=0.99) < 0.5


def test_deep_pass_catches_corruption_cheap_pass_misses(tmp_path, register):
    pids = _store(register, tmp_path)
    corrupted = _twin(register, pids[0]).corrupt_chunks(1.0)  # flip bytes in place
    assert corrupted

    cheap = _scrub(register)
    assert cheap.marked_suspect == cheap.marked_lost == 0  # exists() can't see it

    deep = _scrub(register, deep=True)
    assert deep.marked_lost == 3  # corruption is definitive
    assert _states_on(register, pids[0]) == {"lost"}
    assert register.get_reliability(pids[0], prior=0.99) < 0.5
    assert deep.deep_verified == 6  # the other two providers hash clean


def test_deep_verify_rehabilitates_suspect_replica(tmp_path, register):
    pids = _store(register, tmp_path, size=CHUNK // 2)
    rec = register.get_file_with_manifest("/f.bin")
    replica = register.get_replicas(register.get_chunks(rec["manifest_id"])[0]["id"])[0]
    register.set_replica_state(replica["id"], "suspect")

    cheap = _scrub(register)  # probe passes but suspicion stays
    assert _states_on(register, replica["provider_id"]) == {"suspect"}
    deep = _scrub(register, deep=True)
    assert _states_on(register, replica["provider_id"]) == {"stored"}


def test_deep_budget_falls_back_to_probes(tmp_path, register):
    _store(register, tmp_path, size=4 * CHUNK)  # 4 chunks x 3 replicas
    one_replica = register.replicas_for_scrub()[0]["stored_size"]
    report = _scrub(register, deep=True, deep_budget_bytes=3 * one_replica)
    assert report.deep_verified == 3
    assert report.confirmed == 9
    assert report.probed == 12


def test_probe_limit_rotates_oldest_first(tmp_path, register):
    _store(register, tmp_path)
    report = _scrub(register, probe_limit=4)
    assert report.probed == 4
    # next cycle picks the 5 never-verified replicas before re-probing
    ids_second = [r["id"] for r in register.replicas_for_scrub(limit=5)]
    never = {
        r["id"]
        for r in register.conn.execute(
            "SELECT id FROM replicas WHERE last_verified IS NULL"
        ).fetchall()
    }
    assert set(ids_second) == never
