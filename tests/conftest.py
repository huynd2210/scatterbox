import asyncio
from pathlib import Path

import pytest

from scatterbox import pipeline
from scatterbox.register import Register

# Library tests use a fixed raw master key; vault/KDF has its own tests.
MASTER_KEY = bytes(range(32))


@pytest.fixture
def register(tmp_path):
    reg = Register(tmp_path / "register.db")
    yield reg
    reg.close()


def add_localfs_providers(reg: Register, base: Path, n: int = 3, **config) -> list[int]:
    return [
        reg.add_provider(f"p{i}", "localfs", {"root": str(base / f"prov{i}"), **config})
        for i in range(n)
    ]


def add_chaos_providers(reg: Register, base: Path, n: int = 3, **config) -> list[int]:
    return [
        reg.add_provider(
            f"c{i}", "chaos", {"root": str(base / f"chaos{i}"), "seed": i, **config}
        )
        for i in range(n)
    ]


def put(reg, src, vpath, **kwargs):
    return asyncio.run(pipeline.put_file(reg, MASTER_KEY, src, vpath, **kwargs))


def get(reg, vpath, dst):
    asyncio.run(pipeline.get_file(reg, MASTER_KEY, vpath, dst))
