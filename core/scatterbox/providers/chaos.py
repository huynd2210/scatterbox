"""Failure-injecting wrapper around LocalFSProvider, for tests (Phase 1).

Real providers lose data, return 404s, corrupt bytes, and go offline. The
ChaosProvider simulates all of that on top of a LocalFSProvider so the
scrubber/repair machinery can be tested against every disaster scenario,
reproducibly.

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
    """LocalFSProvider wrapped in configurable disasters (module docstring
    has the failure-mode catalog)."""

    transform: Transform | None = None

    def __init__(
        self,
        inner: LocalFSProvider,  # the real storage; chaos is layered on top
        *,
        seed: int = 0,  # same seed => identical failures on every run
        p_not_found: float = 0.0,  # probability a ref 404s on get/exists
        p_corrupt: float = 0.0,  # probability get returns flipped bytes
        latency_s: float = 0.0,  # artificial delay per operation
        killed: bool = False,  # start dead (all ops raise)
        reliability_prior: float | None = None,  # override profile prior,
        latency_class: str | None = None,  # e.g. to fake a Discord-class profile
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
    #
    # Probabilistic failures must be reproducible, but a normal RNG gives
    # different answers depending on *call order*, which differs run to run
    # (parallel uploads, retries...). Instead, each (operation, ref) pair is
    # hashed together with the seed into a number in [0, 1): the "random"
    # outcome for a given object is fixed for the lifetime of the seed.

    def _digest(self, op: str, key: str) -> int:
        raw = blake3(f"{self.seed}:{op}:{key}".encode()).digest()
        return int.from_bytes(raw[:8], "big")

    def _draw(self, op: str, key: str) -> float:
        # Map the 64-bit hash onto [0, 1) so it can be compared against a
        # probability like p_not_found.
        return self._digest(op, key) / 2**64

    async def _gate(self) -> None:
        """Common entry check for every operation: dead? slow?"""
        if self.killed:
            raise ProviderKilledError(f"provider at {self.inner.root} is hard-killed")
        if self.latency_s:
            await asyncio.sleep(self.latency_s)

    def kill(self) -> None:
        self.killed = True

    def revive(self) -> None:
        self.killed = False

    # -- test actions (silent damage on stored objects) ------------------------
    #
    # These bypass the Provider interface entirely and vandalize the files on
    # disk directly — exactly like a cloud provider quietly deleting or
    # bit-rotting data behind our back. The register still believes the
    # replicas are fine until a scrub discovers otherwise.

    def _stored_refs(self) -> list[str]:
        # Sorted for determinism: rglob order varies by filesystem, and
        # rng.sample over a stable list is what makes runs reproducible.
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
        # Skip empty files — there is no byte to flip.
        refs = [r for r in self._stored_refs() if (self.inner.root / r).stat().st_size]
        sample = self._rng.sample(refs, round(fraction * len(refs)))
        for ref in sample:
            path = self.inner.root / ref
            data = bytearray(path.read_bytes())
            # XOR with 0xFF at a seed-determined offset: guaranteed to change
            # the byte, position reproducible per ref.
            data[self._digest("corrupt-at", ref) % len(data)] ^= 0xFF
            path.write_bytes(bytes(data))
        return sample

    # -- Provider interface -----------------------------------------------------
    # Each method runs the gate (kill/latency), maybe injects its failure
    # mode, then delegates to the wrapped LocalFSProvider.

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        await self._gate()
        return await self.inner.put(chunk_id, data)

    async def get(self, ref: RemoteRef) -> bytes:
        await self._gate()
        # Same draw key as exists() below, so get and exists always agree on
        # whether a given ref is "gone".
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

    async def find(self, name: str) -> RemoteRef | None:
        """Discovery passthrough (kill/latency gated like everything else)."""
        await self._gate()
        return await self.inner.find(name)

    async def quota(self) -> Quota:
        await self._gate()
        return await self.inner.quota()

    def profile(self) -> ProviderProfile:
        # Pass the inner profile through, optionally overriding the fields
        # tests use to fake different provider classes (Drive vs Discord).
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
