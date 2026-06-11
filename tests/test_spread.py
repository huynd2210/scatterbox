"""Anti-colocation (Policy.min_spread): no single provider may ever hold a
complete copy of a file — not at put time, not after years of repair.

Providers here are localfs (reliability prior 0.99), so a floor of 2 already
meets the durability target and placement adds no extra copies — group sizes
are deterministic.
"""

import asyncio
import json
import os
import sqlite3

import pytest
from typer.testing import CliRunner

from conftest import MASTER_KEY, add_localfs_providers, get, put
from scatterbox import register as register_mod
from scatterbox import scrubber
from scatterbox.errors import NotEnoughProvidersError, ScatterboxError
from scatterbox.placement import Policy
from scatterbox.register import Register


def provider_chunk_map(reg) -> dict[int, set[str]]:
    """provider_id -> set of chunk hashes it holds (non-lost replicas)."""
    rows = reg.conn.execute(
        """SELECT r.provider_id, c.chunk_hash FROM replicas r
           JOIN chunks c ON c.id = r.chunk_id WHERE r.state != 'lost'"""
    ).fetchall()
    out: dict[int, set[str]] = {}
    for row in rows:
        out.setdefault(row["provider_id"], set()).add(row["chunk_hash"])
    return out


def group_providers(reg) -> dict[int, set[int]]:
    """spread_group -> provider ids holding any of its chunks (non-lost)."""
    rows = reg.conn.execute(
        """SELECT c.spread_group, r.provider_id FROM replicas r
           JOIN chunks c ON c.id = r.chunk_id WHERE r.state != 'lost'"""
    ).fetchall()
    out: dict[int, set[int]] = {}
    for row in rows:
        out.setdefault(row["spread_group"], set()).add(row["provider_id"])
    return out


def all_chunk_hashes(reg) -> set[str]:
    return {r["chunk_hash"] for r in reg.conn.execute("SELECT chunk_hash FROM chunks")}


def test_no_provider_holds_a_complete_copy(register, tmp_path):
    add_localfs_providers(register, tmp_path, 4)
    src = tmp_path / "f.bin"
    data = os.urandom(300_000)
    src.write_bytes(data)
    result = put(
        register, src, "/f.bin",
        policy=Policy(replicas=2, min_spread=2),
        chunk_size=64 * 1024,  # ~5 chunks
    )
    assert result.spread == 2 and result.chunk_count >= 2

    every = all_chunk_hashes(register)
    for provider_id, held in provider_chunk_map(register).items():
        assert held < every, f"provider {provider_id} holds a complete copy"

    # the groups' provider sets are disjoint
    groups = group_providers(register)
    assert len(groups) == 2
    assert groups[0] & groups[1] == set()

    # and the file still restores byte-identically
    dst = tmp_path / "restored.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data


def test_small_file_is_forced_into_enough_chunks(register, tmp_path):
    """A sub-chunk-size file must still split: a 1-chunk file would hand
    every replica holder the whole thing regardless of spread."""
    add_localfs_providers(register, tmp_path, 4)
    src = tmp_path / "small.bin"
    src.write_bytes(os.urandom(100_000))  # far below the 8 MiB default chunk
    result = put(register, src, "/small.bin", policy=Policy(replicas=2, min_spread=2))
    assert result.chunk_count >= 2
    every = all_chunk_hashes(register)
    for held in provider_chunk_map(register).values():
        assert held < every


def test_insufficient_providers_tells_user_their_options(register, tmp_path):
    add_localfs_providers(register, tmp_path, 3)  # spread 2 x floor 2 needs 4
    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(10_000))
    with pytest.raises(NotEnoughProvidersError, match="[Aa]dd providers.*lowering --spread"):
        put(register, src, "/f.bin", policy=Policy(replicas=2, min_spread=2))
    # nothing half-stored
    assert register.get_file("/f.bin") is None


def test_tiny_file_cannot_spread(register, tmp_path):
    add_localfs_providers(register, tmp_path, 4)
    src = tmp_path / "one.bin"
    src.write_bytes(b"x")
    with pytest.raises(ScatterboxError, match="too small to split"):
        put(register, src, "/one.bin", policy=Policy(replicas=2, min_spread=2))


def test_spread_one_is_unchanged_behavior(register, tmp_path):
    """Default min_spread=1: all chunks share one target set (trust mode)."""
    add_localfs_providers(register, tmp_path, 3)
    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(200_000))
    result = put(register, src, "/f.bin", chunk_size=64 * 1024)
    assert result.spread == 1
    every = all_chunk_hashes(register)
    # every replica provider holds the complete file — explicitly allowed
    for held in provider_chunk_map(register).values():
        assert held == every


def test_repair_respects_spread(register, tmp_path):
    """Losing a replica must not let repair place it on the other group's
    providers — the guarantee survives healing."""
    ids = add_localfs_providers(register, tmp_path, 5)  # 2x2 groups + 1 spare
    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(256_000))
    put(
        register, src, "/f.bin",
        policy=Policy(replicas=2, min_spread=2),
        chunk_size=64 * 1024,
    )
    groups_before = group_providers(register)
    spare = set(ids) - groups_before[0] - groups_before[1]
    assert len(spare) == 1

    # destroy one group-0 replica's bytes on disk
    victim = register.conn.execute(
        """SELECT r.id, r.provider_id, r.remote_ref FROM replicas r
           JOIN chunks c ON c.id = r.chunk_id
           WHERE c.spread_group = 0 ORDER BY r.id LIMIT 1"""
    ).fetchone()
    prow = register.get_provider(victim["provider_id"])
    root = json.loads(prow["config"])["root"]
    os.remove(os.path.join(root, victim["remote_ref"]))

    report = asyncio.run(scrubber.scrub(register, repair=True))
    assert report.repaired >= 1 and not report.unrepairable

    # the chunk is back at its floor...
    assert register.chunks_below_floor() == []
    # ...and no group-1 provider gained group-0 chunks (or vice versa)
    groups_after = group_providers(register)
    assert groups_after[0] & groups_after[1] == set()
    assert groups_after[0] & groups_before[1] == set()
    every = all_chunk_hashes(register)
    for held in provider_chunk_map(register).values():
        assert held < every

    dst = tmp_path / "restored.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == src.read_bytes()


def test_v2_database_upgrades_with_defaults(tmp_path):
    """Pre-spread registers (user_version 2) gain the new columns with
    no-constraint defaults."""
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    for script in register_mod._MIGRATIONS[:2]:
        conn.executescript(script)
    conn.execute("PRAGMA user_version = 2")
    conn.commit()
    conn.close()

    reg = Register(db)
    cols = {r[1] for r in reg.conn.execute("PRAGMA table_info(manifests)")}
    assert "min_spread" in cols
    cols = {r[1] for r in reg.conn.execute("PRAGMA table_info(chunks)")}
    assert "spread_group" in cols
    reg.close()


def test_cli_spread_flag(tmp_path, monkeypatch):
    from scatterbox_cli.main import app

    runner = CliRunner()
    monkeypatch.setenv("SCATTERBOX_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SCATTERBOX_PASSPHRASE", "pw")
    assert runner.invoke(app, ["init"]).exit_code == 0
    for i in range(4):
        assert (
            runner.invoke(
                app, ["provider", "add", f"p{i}", "--root", str(tmp_path / f"p{i}")]
            ).exit_code
            == 0
        )
    src = tmp_path / "f.bin"
    src.write_bytes(os.urandom(100_000))

    result = runner.invoke(
        app, ["put", str(src), "/f.bin", "--replicas", "2", "--spread", "2"]
    )
    assert result.exit_code == 0, result.output
    assert "split across 2 disjoint provider groups" in result.output

    # infeasible: spread 3 x floor 2 needs 6 providers, only 4 exist
    src2 = tmp_path / "g.bin"
    src2.write_bytes(os.urandom(10_000))
    result = runner.invoke(
        app, ["put", str(src2), "/g.bin", "--replicas", "2", "--spread", "3"]
    )
    assert result.exit_code == 1
    combined = result.output
    try:
        combined += result.stderr
    except (ValueError, AttributeError):
        pass
    assert "Add providers" in combined and "--spread" in combined
