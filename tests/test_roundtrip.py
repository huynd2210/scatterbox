"""Round-trip property tests: put → get → byte-identical."""

import random
import shutil
import tempfile
from pathlib import Path

from blake3 import blake3
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from scatterbox.register import Register

from conftest import MASTER_KEY, add_localfs_providers, get, put

CHUNK = 64 * 1024  # small chunk size so multi-chunk files stay fast


def _make_data(size: int, kind: str, seed: int) -> bytes:
    rnd = random.Random(seed)
    if kind == "random":
        return rnd.randbytes(size)
    if kind == "zeros":
        return b"\x00" * size
    return (b"the quick brown fox jumps over the lazy dog " * (size // 44 + 1))[:size]


@settings(max_examples=30, deadline=None, suppress_health_check=[HealthCheck.too_slow])
@given(
    size=st.integers(min_value=0, max_value=4 * CHUNK + 17),
    kind=st.sampled_from(["random", "zeros", "text"]),
    seed=st.integers(min_value=0, max_value=2**32 - 1),
)
def test_roundtrip_property(size: int, kind: str, seed: int):
    base = Path(tempfile.mkdtemp(prefix="sbx-prop-"))
    reg = Register(base / "register.db")
    try:
        add_localfs_providers(reg, base, n=3)
        data = _make_data(size, kind, seed)
        src = base / "src.bin"
        src.write_bytes(data)
        put(reg, src, "/f.bin", chunk_size=CHUNK)
        dst = base / "dst.bin"
        get(reg, "/f.bin", dst)
        assert dst.read_bytes() == data
    finally:
        reg.close()
        shutil.rmtree(base, ignore_errors=True)


def test_roundtrip_100mib(tmp_path, register):
    """Gate: large random file through the default 8 MiB pipeline, 3 replicas."""
    import os

    add_localfs_providers(register, tmp_path, n=3)
    data = os.urandom(100 * 1024 * 1024)
    src = tmp_path / "big.bin"
    src.write_bytes(data)
    result = put(register, src, "/big.bin")
    assert result.chunk_count == 13  # ceil(100 MiB / 8 MiB)
    dst = tmp_path / "big.out"
    get(register, "/big.bin", dst)
    assert blake3(dst.read_bytes()).digest() == blake3(data).digest()
