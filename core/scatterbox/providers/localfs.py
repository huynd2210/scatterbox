"""LocalFS mock provider: chunks as files in a directory."""

from __future__ import annotations

import os
from pathlib import Path

from scatterbox.errors import ObjectTooLargeError, ProviderFullError
from scatterbox.providers.base import ProviderProfile, Quota, RemoteRef, Transform


class LocalFSProvider:
    transform: Transform | None = None

    def __init__(
        self,
        root: Path | str,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,
    ) -> None:
        self.root = Path(root)
        self.max_object_bytes = max_object_bytes
        self.capacity_bytes = capacity_bytes
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, ref: RemoteRef) -> Path:
        return self.root / ref.value

    def _used_bytes(self) -> int:
        return sum(
            os.path.getsize(os.path.join(dirpath, f))
            for dirpath, _, files in os.walk(self.root)
            for f in files
        )

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        if self.max_object_bytes is not None and len(data) > self.max_object_bytes:
            raise ObjectTooLargeError(
                f"object of {len(data)} bytes exceeds provider max of "
                f"{self.max_object_bytes} bytes"
            )
        if (
            self.capacity_bytes is not None
            and self._used_bytes() + len(data) > self.capacity_bytes
        ):
            raise ProviderFullError(
                f"provider at {self.root} has no capacity for {len(data)} bytes"
            )
        rel = f"{chunk_id[:2]}/{chunk_id}"
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        return RemoteRef(rel)

    async def get(self, ref: RemoteRef) -> bytes:
        return self._path(ref).read_bytes()

    async def delete(self, ref: RemoteRef) -> None:
        self._path(ref).unlink(missing_ok=True)

    async def exists(self, ref: RemoteRef) -> bool:
        return self._path(ref).is_file()

    async def quota(self) -> Quota:
        used = self._used_bytes()
        if self.capacity_bytes is not None:
            return Quota(self.capacity_bytes, used, "estimated")
        return Quota(None, used, "unknown")

    def profile(self) -> ProviderProfile:
        return ProviderProfile(
            latency_class="hot",
            throughput_class="high",
            max_object_bytes=self.max_object_bytes,
            reliability_prior=0.99,
            exposure_risk="low",
            rate_limited=False,
        )
