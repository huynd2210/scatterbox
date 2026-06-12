"""LocalFS mock provider: chunks as files in a directory.

The simplest possible Provider implementation — it "uploads" by writing
files under a root directory. It exists so the whole pipeline can be built
and tested end-to-end before any real cloud adapter (Phase 2). It still
honors the knobs real providers have (max object size, capacity cap) so
those code paths get exercised.
"""

from __future__ import annotations

import os
from pathlib import Path

from scatterbox.errors import ObjectTooLargeError, ProviderFullError
from scatterbox.providers.base import ProviderProfile, Quota, RemoteRef, Transform


class LocalFSProvider:
    """Provider adapter for a plain local directory (module docstring
    explains why it exists and what it simulates)."""

    transform: Transform | None = None  # no encode/decode stage for plain files

    def __init__(
        self,
        root: Path | str,
        max_object_bytes: int | None = None,  # simulate e.g. Discord's 10 MB cap
        capacity_bytes: int | None = None,  # simulate a quota; None = unlimited
    ) -> None:
        self.root = Path(root)
        self.max_object_bytes = max_object_bytes
        self.capacity_bytes = capacity_bytes
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, ref: RemoteRef) -> Path:
        # ref.value is a path relative to our root (set in put below)
        return self.root / ref.value

    def _used_bytes(self) -> int:
        # Walk everything under root and sum file sizes. O(n) per call, which
        # is fine for a test mock.
        return sum(
            os.path.getsize(os.path.join(dirpath, f))
            for dirpath, _, files in os.walk(self.root)
            for f in files
        )

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        # Enforce the same failure modes a real provider would have, so the
        # pipeline's error handling is tested honestly.
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
        # Fan out into subdirectories by the first two hex chars of the chunk
        # id ("ab/abcdef...") so no single directory collects millions of files.
        rel = f"{chunk_id[:2]}/{chunk_id}"
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        # Write-to-temp + atomic rename: a crash mid-write can never leave a
        # half-written file that looks like a valid chunk.
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        os.replace(tmp, path)
        return RemoteRef(rel)

    async def get(self, ref: RemoteRef) -> bytes:
        return self._path(ref).read_bytes()

    async def delete(self, ref: RemoteRef) -> None:
        # missing_ok: deleting something already gone is fine, not an error
        self._path(ref).unlink(missing_ok=True)

    async def exists(self, ref: RemoteRef) -> bool:
        return self._path(ref).is_file()

    async def find(self, name: str) -> RemoteRef | None:
        """Locate an object by its put-time name (cold recovery uses this
        for the well-known register snapshot). put() is deterministic, so
        this is a single path probe."""
        rel = f"{name[:2]}/{name}"
        return RemoteRef(rel) if (self.root / rel).is_file() else None

    async def quota(self) -> Quota:
        """Configured cap = 'estimated' confidence; no cap = 'unknown'."""
        used = self._used_bytes()
        if self.capacity_bytes is not None:
            # We know the cap only because the user configured it -> 'estimated'
            return Quota(self.capacity_bytes, used, "estimated")
        return Quota(None, used, "unknown")

    def profile(self) -> ProviderProfile:
        # A local directory is the best storage we will ever talk to:
        # instant, fast, and as reliable as the disk it sits on.
        return ProviderProfile(
            latency_class="hot",
            throughput_class="high",
            max_object_bytes=self.max_object_bytes,
            reliability_prior=0.99,
            exposure_risk="low",
            rate_limited=False,
        )
