"""Provider max_object_bytes forces chunks small enough to fit."""

import os
from pathlib import Path

import pytest

from scatterbox import pipeline
from scatterbox.errors import NotEnoughProvidersError

from conftest import add_localfs_providers, get, put

MIB = 1024 * 1024


def test_chunks_respect_max_object_bytes(tmp_path, register):
    add_localfs_providers(register, tmp_path, n=3, max_object_bytes=MIB)
    data = os.urandom(3 * MIB + 500_000)
    src = tmp_path / "src.bin"
    src.write_bytes(data)

    result = put(register, src, "/f.bin")  # default 8 MiB chunk size requested
    assert result.chunk_size == MIB - pipeline.CHUNK_OVERHEAD

    stored = [
        p for p in Path(tmp_path).rglob("*") if p.is_file() and "prov" in str(p.parent)
    ]
    assert stored, "no chunk objects written"
    assert all(p.stat().st_size <= MIB for p in stored)

    dst = tmp_path / "dst.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data


def test_not_enough_providers(tmp_path, register):
    add_localfs_providers(register, tmp_path, n=2)
    src = tmp_path / "src.bin"
    src.write_bytes(b"hello")
    with pytest.raises(NotEnoughProvidersError):
        put(register, src, "/f.bin", replicas=3)
    # works once the replica count matches what's available
    put(register, src, "/f.bin", replicas=2)
