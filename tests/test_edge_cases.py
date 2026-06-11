"""Edge cases: 0-byte, sub-chunk, exact chunk multiples, many chunks."""

import os

import pytest

from conftest import add_localfs_providers, get, put

CHUNK = 4096


@pytest.mark.parametrize(
    "size",
    [
        0,  # empty file
        1,  # smallest non-empty
        CHUNK - 1,  # just under one chunk
        CHUNK,  # exactly one chunk
        CHUNK + 1,  # one chunk + 1 byte
        8 * CHUNK,  # exact chunk multiple
        50 * CHUNK + 7,  # many chunks + remainder
    ],
)
def test_roundtrip_sizes(tmp_path, register, size):
    add_localfs_providers(register, tmp_path, n=3)
    data = os.urandom(size)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    result = put(register, src, "/f.bin", chunk_size=CHUNK)
    expected_chunks = -(-size // CHUNK)  # ceil; 0 for empty file
    assert result.chunk_count == expected_chunks
    assert result.size == size
    dst = tmp_path / "dst.bin"
    get(register, "/f.bin", dst)
    assert dst.read_bytes() == data


def test_zero_byte_file_has_no_chunks(tmp_path, register):
    add_localfs_providers(register, tmp_path, n=3)
    src = tmp_path / "empty.bin"
    src.write_bytes(b"")
    put(register, src, "/empty")
    rec = register.get_file_with_manifest("/empty")
    assert register.get_chunks(rec["manifest_id"]) == []
    dst = tmp_path / "empty.out"
    get(register, "/empty", dst)
    assert dst.read_bytes() == b""
