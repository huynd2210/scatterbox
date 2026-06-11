"""Corruption: a flipped byte in one replica is detected; get falls back."""

import asyncio
import json
import os
from pathlib import Path

import pytest

from scatterbox import pipeline
from scatterbox.errors import ChunkUnavailableError

from conftest import MASTER_KEY, add_localfs_providers, get, put

CHUNK = 4096


def _replica_paths(register, chunk_row):
    """Replica file paths for a chunk, in the order get_file tries them."""
    paths = []
    for replica in register.get_replicas(chunk_row["id"]):
        prow = register.get_provider(replica["provider_id"])
        root = Path(json.loads(prow["config"])["root"])
        paths.append((replica["id"], root / replica["remote_ref"]))
    return paths


def _flip_byte(path: Path, offset: int = 100) -> None:
    data = bytearray(path.read_bytes())
    data[offset % len(data)] ^= 0xFF
    path.write_bytes(bytes(data))


def test_corrupt_replica_detected_and_fallback(tmp_path, register):
    add_localfs_providers(register, tmp_path, n=3)
    data = os.urandom(3 * CHUNK + 123)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    put(register, src, "/f.bin", chunk_size=CHUNK)

    rec = register.get_file_with_manifest("/f.bin")
    first_chunk = register.get_chunks(rec["manifest_id"])[0]
    replica_id, replica_path = _replica_paths(register, first_chunk)[0]
    _flip_byte(replica_path)

    dst = tmp_path / "dst.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data  # fell back to a healthy replica

    state = register.conn.execute(
        "SELECT state FROM replicas WHERE id = ?", (replica_id,)
    ).fetchone()["state"]
    assert state == "suspect"


def test_all_replicas_corrupt_fails_loudly(tmp_path, register):
    add_localfs_providers(register, tmp_path, n=3)
    data = os.urandom(CHUNK)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    put(register, src, "/f.bin", chunk_size=CHUNK)

    rec = register.get_file_with_manifest("/f.bin")
    chunk = register.get_chunks(rec["manifest_id"])[0]
    for _, path in _replica_paths(register, chunk):
        _flip_byte(path)

    with pytest.raises(ChunkUnavailableError):
        asyncio.run(
            pipeline.get_file(register, MASTER_KEY, "/f.bin", tmp_path / "dst.bin")
        )
    assert not (tmp_path / "dst.bin").exists()


def test_missing_replica_falls_back(tmp_path, register):
    add_localfs_providers(register, tmp_path, n=3)
    data = os.urandom(2 * CHUNK)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    put(register, src, "/f.bin", chunk_size=CHUNK)

    rec = register.get_file_with_manifest("/f.bin")
    chunk = register.get_chunks(rec["manifest_id"])[0]
    replica_id, path = _replica_paths(register, chunk)[0]
    path.unlink()

    dst = tmp_path / "dst.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data
    state = register.conn.execute(
        "SELECT state FROM replicas WHERE id = ?", (replica_id,)
    ).fetchone()["state"]
    assert state == "suspect"
