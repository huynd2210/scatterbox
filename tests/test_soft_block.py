"""Files over the 10 GB soft cap are refused unless forced."""

import pytest

from scatterbox import pipeline
from scatterbox.errors import FileTooLargeError

from conftest import add_localfs_providers, get, put


def test_soft_block_over_10gb(tmp_path, register, monkeypatch):
    add_localfs_providers(register, tmp_path, n=3)
    src = tmp_path / "src.bin"
    src.write_bytes(b"actually tiny")
    # pretend the file is 11 GB without writing 11 GB
    monkeypatch.setattr(pipeline, "_file_size", lambda path: 11 * 1024**3)

    with pytest.raises(FileTooLargeError):
        put(register, src, "/big.bin")

    put(register, src, "/big.bin", force_large=True)
    dst = tmp_path / "dst.bin"
    get(register, "/big.bin", dst)
    assert dst.read_bytes() == b"actually tiny"


def test_under_cap_not_blocked(tmp_path, register):
    add_localfs_providers(register, tmp_path, n=3)
    src = tmp_path / "src.bin"
    src.write_bytes(b"x" * 1000)
    put(register, src, "/ok.bin")  # no error
