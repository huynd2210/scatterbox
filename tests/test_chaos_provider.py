"""ChaosProvider failure modes, each deterministic under a fixed seed."""

import asyncio
import time

import pytest

from scatterbox.errors import ProviderKilledError
from scatterbox.providers import ChaosProvider, LocalFSProvider
from scatterbox.providers.base import RemoteRef


def _make(tmp_path, name="chaos", **kwargs) -> ChaosProvider:
    return ChaosProvider(LocalFSProvider(tmp_path / name), **kwargs)


def _store(provider, n=20) -> list[RemoteRef]:
    async def fill():
        return [
            await provider.put(f"{i:02d}aabb", bytes([i]) * 100) for i in range(n)
        ]

    return asyncio.run(fill())


def test_hard_kill_fails_all_operations(tmp_path):
    chaos = _make(tmp_path)
    refs = _store(chaos, n=1)
    chaos.kill()
    for coro in (
        chaos.put("ff00", b"x"),
        chaos.get(refs[0]),
        chaos.delete(refs[0]),
        chaos.exists(refs[0]),
        chaos.quota(),
    ):
        with pytest.raises(ProviderKilledError):
            asyncio.run(coro)
    chaos.revive()
    assert asyncio.run(chaos.get(refs[0])) == bytes([0]) * 100


def test_not_found_probability_extremes(tmp_path):
    always = _make(tmp_path, "a", p_not_found=1.0)
    refs = _store(always, n=3)
    for ref in refs:
        assert not asyncio.run(always.exists(ref))
        with pytest.raises(FileNotFoundError):
            asyncio.run(always.get(ref))

    never = _make(tmp_path, "b", p_not_found=0.0)
    refs = _store(never, n=3)
    assert all(asyncio.run(never.exists(ref)) for ref in refs)


def test_not_found_deterministic_per_seed(tmp_path):
    chaos = _make(tmp_path, seed=7, p_not_found=0.5)
    refs = _store(chaos)
    missing = {r.value for r in refs if not asyncio.run(chaos.exists(r))}
    assert 0 < len(missing) < len(refs)  # roughly half fail

    # same seed on a fresh instance over the same store → identical outcome
    again = ChaosProvider(chaos.inner, seed=7, p_not_found=0.5)
    assert {r.value for r in refs if not asyncio.run(again.exists(r))} == missing
    # get agrees with exists on which refs are "gone"
    for ref in refs:
        if ref.value in missing:
            with pytest.raises(FileNotFoundError):
                asyncio.run(chaos.get(ref))
        else:
            asyncio.run(chaos.get(ref))

    other_seed = ChaosProvider(chaos.inner, seed=8, p_not_found=0.5)
    other = {r.value for r in refs if not asyncio.run(other_seed.exists(r))}
    assert other != missing


def test_corrupt_on_get_is_deterministic(tmp_path):
    chaos = _make(tmp_path, seed=3, p_corrupt=1.0)
    (ref,) = _store(chaos, n=1)
    stored = (chaos.inner.root / ref.value).read_bytes()
    got = asyncio.run(chaos.get(ref))
    assert got != stored and len(got) == len(stored)
    assert asyncio.run(chaos.get(ref)) == got  # reproducible corruption


def test_drop_chunks_silently_deletes_seeded_sample(tmp_path):
    chaos = _make(tmp_path, seed=11)
    refs = _store(chaos, n=20)
    dropped = chaos.drop_chunks(0.25)
    assert len(dropped) == 5
    for ref in refs:
        assert asyncio.run(chaos.exists(ref)) == (ref.value not in dropped)

    twin = _make(tmp_path, "twin", seed=11)
    _store(twin, n=20)
    assert twin.drop_chunks(0.25) == dropped  # seeded runs reproduce


def test_corrupt_chunks_flips_byte_in_place(tmp_path):
    chaos = _make(tmp_path, seed=5)
    refs = _store(chaos, n=10)
    before = {r.value: (chaos.inner.root / r.value).read_bytes() for r in refs}
    corrupted = chaos.corrupt_chunks(0.3)
    assert len(corrupted) == 3
    for ref in refs:
        data = asyncio.run(chaos.get(ref))
        if ref.value in corrupted:
            assert data != before[ref.value] and len(data) == len(before[ref.value])
        else:
            assert data == before[ref.value]


def test_latency_delays_operations(tmp_path):
    chaos = _make(tmp_path, latency_s=0.05)
    start = time.monotonic()
    _store(chaos, n=2)
    assert time.monotonic() - start >= 0.1


def test_profile_overrides(tmp_path):
    chaos = _make(tmp_path, reliability_prior=0.5, latency_class="warm")
    profile = chaos.profile()
    assert profile.reliability_prior == 0.5
    assert profile.latency_class == "warm"
