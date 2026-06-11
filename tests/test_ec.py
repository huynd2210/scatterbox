"""Erasure coding ec(k,n) — unit level and the Phase 5 chaos gate
(PLAN.md §12: lose n−k providers, restore; repair regenerates shares)."""

import asyncio
import itertools
import os
import shutil

import pytest

from conftest import MASTER_KEY, add_localfs_providers, get, put
from scatterbox import ec, scrubber
from scatterbox.errors import ChunkUnavailableError, ScatterboxError
from scatterbox.placement import Policy
from scatterbox.pipeline import file_status
from scatterbox.register import derive_health

EC_POLICY = Policy(scheme="ec", ec_k=3, ec_n=5)


# -- unit: the zfec wrapper ----------------------------------------------------


@pytest.mark.parametrize("size", [1, 5, 300, 3 * 1000, 3 * 1000 + 1, 100_000])
def test_split_join_roundtrip_any_k_shares(size):
    data = os.urandom(size)
    shares = ec.split(data, 3, 5)
    assert len(shares) == 5
    assert len({len(s) for s in shares}) == 1  # equal share sizes
    for combo in itertools.combinations(range(5), 3):
        assert ec.join({i: shares[i] for i in combo}, 3, 5, size) == data


def test_regenerate_matches_originals():
    data = os.urandom(10_000)
    shares = ec.split(data, 2, 4)
    fresh = ec.regenerate({0: shares[0], 3: shares[3]}, 2, 4, len(data), [1, 2])
    assert fresh[1] == shares[1] and fresh[2] == shares[2]


def test_param_validation():
    for k, n in ((0, 3), (3, 3), (5, 3), (1, 300)):
        with pytest.raises(ScatterboxError, match="erasure coding parameters"):
            ec.validate_params(k, n)
    with pytest.raises(ScatterboxError, match="need 3 shares"):
        ec.join({0: b"x"}, 3, 5, 1)


def test_ec_health_thresholds():
    # ec(3,5): 5 healthy, 4 degraded, 3 at-risk (one more loss kills it), <3 lost
    assert derive_health(5, 5, ec_k=3) == "healthy"
    assert derive_health(4, 5, ec_k=3) == "degraded"
    assert derive_health(3, 5, ec_k=3) == "at-risk"
    assert derive_health(2, 5, ec_k=3) == "lost"


# -- pipeline integration -------------------------------------------------------


def shares_per_chunk(reg):
    """chunk_row_id -> [(share_index, provider_id, state)]"""
    rows = reg.conn.execute(
        """SELECT r.chunk_id, r.share_index, r.provider_id, r.state
           FROM replicas r ORDER BY r.chunk_id, r.share_index"""
    ).fetchall()
    out: dict[int, list] = {}
    for row in rows:
        out.setdefault(row["chunk_id"], []).append(
            (row["share_index"], row["provider_id"], row["state"])
        )
    return out


def test_ec_put_get_roundtrip(register, tmp_path):
    add_localfs_providers(register, tmp_path, 5)
    data = os.urandom(300_000)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    result = put(register, src, "/f.bin", policy=EC_POLICY, chunk_size=64 * 1024)
    assert result.scheme == "ec" and result.replicas == 5
    assert result.chunk_count >= 4

    for shares in shares_per_chunk(register).values():
        assert [s[0] for s in shares] == [0, 1, 2, 3, 4]  # all indices present
        assert len({s[1] for s in shares}) == 5  # on 5 distinct providers

    st = file_status(register, "/f.bin")
    assert (st.scheme, st.ec_k, st.replica_target, st.health) == ("ec", 3, 5, "healthy")

    dst = tmp_path / "out.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data

    # storage cost is ~n/k of the data, not n copies
    stored = sum(
        f.stat().st_size
        for i in range(5)
        for f in (tmp_path / f"prov{i}").rglob("*")
        if f.is_file()
    )
    assert stored < len(data) * 2  # 5/3 ≈ 1.67x, far below 5x replication


def test_ec_chaos_gate(register, tmp_path):
    """Phase gate: lose n−k providers entirely → every file restores;
    with spares, scrub+repair regenerates the missing shares."""
    add_localfs_providers(register, tmp_path, 7)  # 5 EC homes + 2 spares
    files = {}
    for i in range(8):
        data = os.urandom(80_000 + i * 7919)
        src = tmp_path / f"src{i}.bin"
        src.write_bytes(data)
        put(
            register, src, f"/files/f{i}.bin",
            policy=Policy(scheme="ec", ec_k=3, ec_n=5, excluded=frozenset({"p5", "p6"})),
            chunk_size=32 * 1024,
        )
        files[f"/files/f{i}.bin"] = data

    # apocalypse: two of the five providers vanish completely
    for name in ("p0", "p1"):
        row = register.get_provider_by_name(name)
        import json
        shutil.rmtree(json.loads(row["config"])["root"])

    # gate part 1: everything still restores from the surviving 3 shares
    for vpath, data in files.items():
        dst = tmp_path / "restored.bin"
        get(register, vpath, dst)
        assert dst.read_bytes() == data, vpath

    # gate part 2: scrub demotes the dead shares, repair regenerates them
    # onto the spares, and health returns to full
    report = asyncio.run(scrubber.scrub(register, repair=True))
    assert report.repaired >= 1 and not report.unrepairable
    assert register.chunks_below_floor() == []
    for vpath, data in files.items():
        st = file_status(register, vpath)
        assert st.health == "healthy", vpath
        dst = tmp_path / "restored2.bin"
        get(register, vpath, dst)
        assert dst.read_bytes() == data
    # every chunk again has all 5 indices live on 5 distinct providers
    for shares in shares_per_chunk(register).values():
        live = [(i, p) for i, p, state in shares if state == "stored"]
        assert sorted(i for i, _ in live) == [0, 1, 2, 3, 4]
        assert len({p for _, p in live}) == 5


def test_ec_corrupted_share_is_caught_and_repaired(register, tmp_path):
    add_localfs_providers(register, tmp_path, 6)
    data = os.urandom(50_000)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    put(register, src, "/f.bin", policy=EC_POLICY)

    # flip bytes in one stored share
    victim = register.conn.execute(
        "SELECT * FROM replicas ORDER BY id LIMIT 1"
    ).fetchone()
    import json
    root = json.loads(register.get_provider(victim["provider_id"])["config"])["root"]
    share_path = os.path.join(root, victim["remote_ref"])
    blob = bytearray(open(share_path, "rb").read())
    blob[: 4] = b"\xff\xff\xff\xff"
    open(share_path, "wb").write(bytes(blob))

    # deep scrub: share_hash mismatch is definitive -> lost; repair regenerates
    report = asyncio.run(scrubber.scrub(register, deep=True, repair=True))
    assert report.marked_lost == 1 and report.repaired == 1
    dst = tmp_path / "out.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data


def test_ec_read_survives_missing_share_and_marks_it(register, tmp_path):
    add_localfs_providers(register, tmp_path, 5)
    data = os.urandom(40_000)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    put(register, src, "/f.bin", policy=EC_POLICY)

    victim = register.conn.execute(
        "SELECT * FROM replicas ORDER BY id LIMIT 1"
    ).fetchone()
    import json
    root = json.loads(register.get_provider(victim["provider_id"])["config"])["root"]
    os.remove(os.path.join(root, victim["remote_ref"]))

    dst = tmp_path / "out.bin"
    get(register, "/f.bin", dst)  # 4 shares left, k=3 — fine
    assert dst.read_bytes() == data
    assert (
        register.conn.execute(
            "SELECT state FROM replicas WHERE id = ?", (victim["id"],)
        ).fetchone()["state"]
        == "suspect"
    )


def test_ec_below_k_fails_loudly(register, tmp_path):
    add_localfs_providers(register, tmp_path, 5)
    data = os.urandom(30_000)
    src = tmp_path / "f.bin"
    src.write_bytes(data)
    put(register, src, "/f.bin", policy=EC_POLICY)
    import json
    for name in ("p0", "p1", "p2"):  # only 2 shares left < k=3
        row = register.get_provider_by_name(name)
        shutil.rmtree(json.loads(row["config"])["root"])
    with pytest.raises(ChunkUnavailableError, match="shares"):
        get(register, "/f.bin", tmp_path / "out.bin")


def test_ec_needs_n_providers(register, tmp_path):
    add_localfs_providers(register, tmp_path, 4)  # ec(3,5) wants 5
    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(1000))
    from scatterbox.errors import NotEnoughProvidersError

    with pytest.raises(NotEnoughProvidersError):
        put(register, src, "/f.bin", policy=EC_POLICY)
