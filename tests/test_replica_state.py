"""Replica lifecycle, provider reliability EMA, and file durability state."""

import os

import pytest

from scatterbox import pipeline
from scatterbox.errors import ScatterboxError
from scatterbox.register import (
    RELIABILITY_ALPHA_DOWN,
    RELIABILITY_ALPHA_UP,
    derive_health,
)

from conftest import add_localfs_providers, put

CHUNK = 1024


def _store_one(register, tmp_path, n_providers=3, size=CHUNK // 2):
    add_localfs_providers(register, tmp_path, n=n_providers)
    src = tmp_path / "src.bin"
    src.write_bytes(os.urandom(size))
    put(register, src, "/f.bin", chunk_size=CHUNK)
    rec = register.get_file_with_manifest("/f.bin")
    return rec, register.get_chunks(rec["manifest_id"])


# -- replica state machine ----------------------------------------------------


def test_new_replicas_start_stored(tmp_path, register):
    rec, chunks = _store_one(register, tmp_path)
    states = {r["state"] for c in chunks for r in register.get_replicas(c["id"])}
    assert states == {"stored"}


def test_valid_lifecycle_path(tmp_path, register):
    rec, chunks = _store_one(register, tmp_path)
    replica = register.get_replicas(chunks[0]["id"])[0]
    register.set_replica_state(replica["id"], "suspect")
    register.set_replica_state(replica["id"], "stored")  # re-verified
    register.set_replica_state(replica["id"], "suspect")
    register.set_replica_state(replica["id"], "lost")


def test_invalid_transitions_rejected(tmp_path, register):
    rec, chunks = _store_one(register, tmp_path)
    replicas = register.get_replicas(chunks[0]["id"])
    register.set_replica_state(replicas[0]["id"], "lost")
    with pytest.raises(ScatterboxError):  # lost is terminal
        register.set_replica_state(replicas[0]["id"], "stored")
    with pytest.raises(ScatterboxError):
        register.set_replica_state(replicas[1]["id"], "bogus")


def test_same_state_is_noop(tmp_path, register):
    rec, chunks = _store_one(register, tmp_path)
    replica = register.get_replicas(chunks[0]["id"])[0]
    register.set_replica_state(replica["id"], "stored")  # no-op, no error


def test_mark_verified_sets_timestamp(tmp_path, register):
    rec, chunks = _store_one(register, tmp_path)
    replica = register.get_replicas(chunks[0]["id"])[0]
    assert replica["last_verified"] is None
    register.set_replica_state(replica["id"], "suspect")
    register.mark_replica_verified(replica["id"])
    row = register.get_replicas(chunks[0]["id"])[0]
    assert row["state"] == "stored" and row["last_verified"] is not None


# -- reliability EMA ----------------------------------------------------------


def test_score_starts_at_prior_and_moves(register, tmp_path):
    (pid,) = add_localfs_providers(register, tmp_path, n=1)
    assert register.get_reliability(pid, prior=0.9) == 0.9

    up = register.update_reliability(pid, True, prior=0.9)
    assert up == pytest.approx((1 - RELIABILITY_ALPHA_UP) * 0.9 + RELIABILITY_ALPHA_UP)
    down = register.update_reliability(pid, False, prior=0.9)
    assert down == pytest.approx((1 - RELIABILITY_ALPHA_DOWN) * up)


def test_failure_hits_harder_than_success_helps(register, tmp_path):
    (pid,) = add_localfs_providers(register, tmp_path, n=1)
    up_gain = register.update_reliability(pid, True, prior=0.9) - 0.9
    register.update_reliability(pid, False, prior=0.9)
    # one failure undoes far more than one success gained
    assert RELIABILITY_ALPHA_DOWN > 4 * RELIABILITY_ALPHA_UP
    assert up_gain < 0.01


def test_learned_score_feeds_placement(register, tmp_path):
    pids = add_localfs_providers(register, tmp_path, n=2)
    register.update_reliability(pids[0], False, prior=0.99)
    handles = {h.id: h for h in pipeline.load_providers(register)}
    assert handles[pids[0]].reliability < handles[pids[1]].reliability
    assert handles[pids[1]].reliability == 0.99  # untouched -> prior


def test_get_file_observations_update_states_and_scores(tmp_path, register):
    rec, chunks = _store_one(register, tmp_path)
    replica = register.get_replicas(chunks[0]["id"])[0]
    root = tmp_path / "prov0"
    # silently delete the first provider's replica
    for p in root.rglob("*"):
        if p.is_file():
            p.unlink()

    dst = tmp_path / "dst.bin"
    from conftest import get

    get(register, "/f.bin", dst)
    row = register.conn.execute(
        "SELECT state FROM replicas WHERE id = ?", (replica["id"],)
    ).fetchone()
    assert row["state"] == "suspect"
    assert register.get_reliability(replica["provider_id"], prior=0.99) < 0.99


# -- file durability ----------------------------------------------------------


def test_derive_health_thresholds():
    assert derive_health(3, 3) == "healthy"
    assert derive_health(4, 3) == "healthy"
    assert derive_health(2, 3) == "degraded"
    assert derive_health(1, 3) == "at-risk"
    assert derive_health(0, 3) == "lost"
    assert derive_health(1, 1) == "healthy"


def test_file_status_degrades_with_replica_states(tmp_path, register):
    rec, chunks = _store_one(register, tmp_path)
    assert pipeline.file_status(register, "/f.bin").health == "healthy"

    replicas = register.get_replicas(chunks[0]["id"])
    register.set_replica_state(replicas[0]["id"], "suspect")
    st = pipeline.file_status(register, "/f.bin")
    assert st.health == "degraded" and st.min_live == 2

    register.set_replica_state(replicas[1]["id"], "lost")
    assert pipeline.file_status(register, "/f.bin").health == "at-risk"

    register.set_replica_state(replicas[0]["id"], "lost")
    register.set_replica_state(replicas[2]["id"], "lost")
    st = pipeline.file_status(register, "/f.bin")
    assert st.health == "lost"
    assert st.replica_states == {"lost": 3}
