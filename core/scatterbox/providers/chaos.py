"""Failure-injecting wrapper around LocalFSProvider, for tests (Phase 1).

Failure modes, all deterministic for a given seed:

- ``p_not_found``: get/exists report the object missing. The draw is a hash
  of (seed, ref), not a stateful RNG, so a given ref fails consistently and
  runs reproduce identically regardless of operation order.
- ``p_corrupt``: get returns the stored bytes with one byte flipped at a
  seed-determined position.
- ``latency_s``: every operation sleeps first.
- ``killed``: every operation raises ProviderKilledError (hard-kill).
- Test actions: drop_chunks() silently deletes a seeded sample of stored
  objects; corrupt_chunks() flips a byte in place on a seeded sample.
"""

from __future__ import annotations

import asyncio
import random

from blake3 import blake3

from scatterbox.errors import ProviderKilledError
from scatterbox.providers.base import ProviderProfile, Quota, RemoteRef, Transform
from scatterbox.providers.localfs import LocalFSProvider


class ChaosProvider:
    transform: Transform | None = None

    def __init__(
        self,
        inner: LocalFSProvider,
        *,
        seed: int = 0,
        p_not_found: float = 0.0,
        p_corrupt: float = 0.0,
        latency_s: float = 0.0,
        killed: bool = False,
        reliability_prior: float | None = None,
        latency_class: str | None = None,
    ) -> None:
        self.inner = inner
        self.seed = seed
        self.p_not_found = p_not_found
        self.p_corrupt = p_corrupt
        self.latency_s = latency_s
        self.killed = killed
        self.reliability_prior = reliability_prior
        self.latency_class = latency_class
        self._rng = random.Random(seed)  # for drop/corrupt sampling actions

    # -- failure machinery ----------------------------------------------------

    def _digest(self, op: str, key: str) -> int:
        raw = blake3(f"{self.seed}:{op}:{key}".encode()).digest()
        return int.from_bytes(raw[:8], "big")

    def _draw(self, op: str, key: str) -> float:
        return self._digest(op, key) / 2**64

    async def _gate(self) -> None:
        if self.killed:
            raise ProviderKilledError(f"provider at {self.inner.root} is hard-killed")
        if self.latency_s:
            await asyncio.sleep(self.latency_s)

    def kill(self) -> None:
        self.killed = True

    def revive(self) -> None:
        self.killed = False

    # -- test actions (silent damage on stored objects) ------------------------

    def _stored_refs(self) -> list[str]:
        return sorted(
            str(p.relative_to(self.inner.root)).replace("\\", "/")
            for p in self.inner.root.rglob("*")
            if p.is_file()
        )

    def drop_chunks(self, fraction: float) -> list[str]:
        """Silently delete a seeded sample of stored objects; returns their refs."""
        refs = self._stored_refs()
        sample = self._rng.sample(refs, round(fraction * len(refs)))
        for ref in sample:
            (self.inner.root / ref).unlink()
        return sample

    def corrupt_chunks(self, fraction: float) -> list[str]:
        """Flip one byte in place on a seeded sample of stored objects."""
        refs = [r for r in self._stored_refs() if (self.inner.root / r).stat().st_size]
        sample = self._rng.sample(refs, round(fraction * len(refs)))
        for ref in sample:
            path = self.inner.root / ref
            data = bytearray(path.read_bytes())
            data[self._digest("corrupt-at", ref) % len(data)] ^= 0xFF
            path.write_bytes(bytes(data))
        return sample

    # -- Provider interface -----------------------------------------------------

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        await self._gate()
        return await self.inner.put(chunk_id, data)

    async def get(self, ref: RemoteRef) -> bytes:
        await self._gate()
        if self._draw("notfound", ref.value) < self.p_not_found:
            raise FileNotFoundError(f"chaos: {ref.value} not found")
        data = await self.inner.get(ref)
        if data and self._draw("corrupt", ref.value) < self.p_corrupt:
            flipped = bytearray(data)
            flipped[self._digest("corrupt-at", ref.value) % len(flipped)] ^= 0xFF
            return bytes(flipped)
        return data

    async def delete(self, ref: RemoteRef) -> None:
        await self._gate()
        await self.inner.delete(ref)

    async def exists(self, ref: RemoteRef) -> bool:
        await self._gate()
        if self._draw("notfound", ref.value) < self.p_not_found:
            return False
        return await self.inner.exists(ref)

    async def quota(self) -> Quota:
        await self._gate()
        return await self.inner.quota()

    def profile(self) -> ProviderProfile:
        base = self.inner.profile()
        return ProviderProfile(
            latency_class=self.latency_class or base.latency_class,
            throughput_class=base.throughput_class,
            max_object_bytes=base.max_object_bytes,
            reliability_prior=(
                self.reliability_prior
                if self.reliability_prior is not None
                else base.reliability_prior
            ),
            exposure_risk=base.exposure_risk,
            rate_limited=base.rate_limited,
        )
