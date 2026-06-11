"""Provider abstraction (PLAN.md §6)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

QuotaConfidence = Literal["exact", "estimated", "unknown"]


@dataclass(frozen=True)
class RemoteRef:
    """Provider-scoped handle to a stored object."""

    value: str


@dataclass(frozen=True)
class Quota:
    """total_bytes is None when the provider cannot report a cap."""

    total_bytes: int | None
    used_bytes: int
    confidence: QuotaConfidence


@dataclass(frozen=True)
class ProviderProfile:
    latency_class: str  # hot | warm | glacial
    throughput_class: str  # high | low | very_low
    max_object_bytes: int | None
    reliability_prior: float
    exposure_risk: str  # low | high
    rate_limited: bool


class Transform(Protocol):
    """Pluggable encoder/decoder pair applied between encryption and upload
    (YouTube/Discord-class providers). Interface only in Phase 0; the pipeline
    treats it as a black box with declared cost properties.
    """

    size_overhead_ratio: float

    def encode(self, data: bytes) -> bytes: ...

    def decode(self, data: bytes) -> bytes: ...


class Provider(Protocol):
    transform: Transform | None

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef: ...

    async def get(self, ref: RemoteRef) -> bytes: ...

    async def delete(self, ref: RemoteRef) -> None: ...

    async def exists(self, ref: RemoteRef) -> bool: ...

    async def quota(self) -> Quota: ...

    def profile(self) -> ProviderProfile: ...
