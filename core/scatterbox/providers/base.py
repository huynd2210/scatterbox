"""Provider abstraction (PLAN.md §6).

A "provider" is one storage backend instance — a Google Drive account, a
local directory, a Discord channel. Every adapter implements the same small
async interface (Provider, below), so the rest of the system never cares
what is actually behind it. All data handed to a provider is already
encrypted ciphertext with a random-looking name; providers are assumed
hostile and are trusted with nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

# How much to trust a provider's free-space number (PLAN.md §6):
#   exact     — the provider's API reports real numbers (e.g. Drive)
#   estimated — we only know a configured cap minus what we've stored
#   unknown   — no idea (Discord-class); placement keeps a safety margin
QuotaConfidence = Literal["exact", "estimated", "unknown"]


@dataclass(frozen=True)
class RemoteRef:
    """Provider-scoped handle to a stored object.

    Opaque to everyone but the adapter that issued it — for localfs it is a
    relative file path, for Drive it would be a file ID, etc. The register
    stores it so the object can be fetched/deleted later.
    """

    value: str


@dataclass(frozen=True)
class Quota:
    """A provider's capacity snapshot. total_bytes is None when the provider
    cannot report a cap at all (confidence is then 'unknown')."""

    total_bytes: int | None
    used_bytes: int
    confidence: QuotaConfidence


@dataclass(frozen=True)
class ProviderProfile:
    """Static description of what a provider class is like.

    These are priors/defaults (per PLAN.md §6's table) — the *learned*
    reliability score lives in the register and starts from
    reliability_prior. The placement engine reads this to decide where
    chunks should go.
    """

    latency_class: str  # hot | warm | glacial — how fast retrieval feels
    throughput_class: str  # high | low | very_low
    max_object_bytes: int | None  # biggest single object it accepts (None = no limit)
    reliability_prior: float  # 0..1, starting guess for "will my data survive here"
    exposure_risk: str  # low | high — how publicly visible stored objects are
    rate_limited: bool


class Transform(Protocol):
    """Pluggable encoder/decoder pair applied between encryption and upload
    (YouTube/Discord-class providers — e.g. bytes -> video frames).

    Interface only in Phase 0/1; the pipeline treats it as a black box with
    declared cost properties. Implementations come in Phase 5.
    """

    size_overhead_ratio: float

    def encode(self, data: bytes) -> bytes: ...

    def decode(self, data: bytes) -> bytes: ...


class Provider(Protocol):
    """The adapter interface every backend implements.

    This is a typing.Protocol: there is no inheritance — any class with
    these methods *is* a Provider (structural typing). All I/O methods are
    async because real backends are network calls.
    """

    transform: Transform | None  # optional YouTube-class hook, usually None

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef: ...

    async def get(self, ref: RemoteRef) -> bytes: ...

    async def delete(self, ref: RemoteRef) -> None: ...

    async def exists(self, ref: RemoteRef) -> bool: ...  # cheap health probe

    async def quota(self) -> Quota: ...

    def profile(self) -> ProviderProfile: ...

    # OPTIONAL (recovery duck-types via getattr): locate an object by the
    # name it was put() under, without a stored ref — what makes cold
    # recovery (passphrase + one re-authed provider) possible. Adapters
    # that cannot search by name may omit it; they then simply cannot
    # serve as a cold-recovery source.
    async def find(self, name: str) -> RemoteRef | None: ...
