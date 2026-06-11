"""Google Drive adapter (Phase 2, PLAN.md §6/§12).

Talks to the Drive v3 REST API directly over httpx — no Google SDK; the
four operations we need are a handful of endpoints, and staying SDK-free
keeps the adapter testable with an injected mock transport.

Scope is `drive.file`: the app sees only files it created itself. Objects
land in a *visible* `scatterbox/` folder at the Drive root (not the hidden
appDataFolder) deliberately — the user must be able to manually delete a
chunk in the Drive UI and watch the scrubber heal it (the Phase 2 verify
gate), and visible storage is honest about where the bytes are.

The folder is found-or-created lazily; the adapter remembers the id for its
own lifetime and reports it via `learned_config()` so the CLI can persist it
back to the register (saving a lookup per command).

Uploads use the resumable protocol (uploadType=resumable): one POST opens a
session, one PUT sends the bytes — chunks are ≤8 MiB so a single PUT always
suffices; a failed PUT is retried by re-opening a session (simpler than
range-resume and equivalent at our object sizes).
"""

from __future__ import annotations

import urllib.parse

import httpx

from scatterbox.errors import ObjectTooLargeError, ProviderFullError, ScatterboxError
from scatterbox.oauth import TokenManager
from scatterbox.providers._http import AuthedClient
from scatterbox.providers.base import (
    ProviderProfile,
    Quota,
    RemoteRef,
    Transform,
)
from scatterbox.vault import SecretStore

_API = "https://www.googleapis.com/drive/v3"
_UPLOAD_API = "https://www.googleapis.com/upload/drive/v3"
_FOLDER_NAME = "scatterbox"
_FOLDER_MIME = "application/vnd.google-apps.folder"

# OAuth endpoints/scope — used by the CLI onboarding flow, kept here so all
# Drive knowledge lives in one file.
AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
SCOPES = "https://www.googleapis.com/auth/drive.file"
# access_type=offline + prompt=consent: required to be issued a refresh
# token (and re-issued one on re-auth instead of silently getting none).
EXTRA_AUTH_PARAMS = {"access_type": "offline", "prompt": "consent"}

_PROFILE = ProviderProfile(
    latency_class="hot",
    throughput_class="high",
    max_object_bytes=None,
    reliability_prior=0.9,  # PLAN.md §6 table
    exposure_risk="low",
    rate_limited=True,
)


class GDriveProvider:
    transform: Transform | None = None

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        folder_id: str | None = None,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,  # user cap: "use at most N of my Drive"
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        tokens = TokenManager(secrets, secret_name, transport=transport)
        self._http = AuthedClient(tokens, transport=transport, backoff_base_s=backoff_base_s)
        self._folder_id = folder_id
        self._max_object_bytes = max_object_bytes
        self._capacity_bytes = capacity_bytes

    def profile(self) -> ProviderProfile:
        if self._max_object_bytes is None:
            return _PROFILE
        # user-configured per-instance cap (PLAN.md §6: always respected)
        return ProviderProfile(
            latency_class=_PROFILE.latency_class,
            throughput_class=_PROFILE.throughput_class,
            max_object_bytes=self._max_object_bytes,
            reliability_prior=_PROFILE.reliability_prior,
            exposure_risk=_PROFILE.exposure_risk,
            rate_limited=_PROFILE.rate_limited,
        )

    def learned_config(self) -> dict:
        """Config keys discovered at runtime, for the CLI to persist."""
        return {"folder_id": self._folder_id} if self._folder_id else {}

    async def prepare(self) -> None:
        """Onboarding hook: find-or-create the scatterbox folder now, so it
        appears in the user's Drive immediately and the id lands in
        learned_config() for the CLI to persist."""
        await self._ensure_folder()

    # -- helpers ---------------------------------------------------------------

    def _check(self, resp: httpx.Response, action: str) -> httpx.Response:
        """Map Drive error responses onto scatterbox's exception hierarchy."""
        if resp.status_code < 400:
            return resp
        if resp.status_code == 403 and b"storageQuotaExceeded" in resp.content:
            raise ProviderFullError("Google Drive storage quota exceeded")
        raise ScatterboxError(
            f"gdrive {action} failed ({resp.status_code}): {resp.text[:200]}"
        )

    async def _ensure_folder(self) -> str:
        if self._folder_id:
            return self._folder_id
        q = (
            f"name = '{_FOLDER_NAME}' and mimeType = '{_FOLDER_MIME}' "
            "and trashed = false and 'root' in parents"
        )
        resp = self._check(
            await self._http.request(
                "GET", f"{_API}/files?q={urllib.parse.quote(q)}&fields=files(id)"
            ),
            "folder lookup",
        )
        found = resp.json().get("files", [])
        if found:
            self._folder_id = found[0]["id"]
        else:
            resp = self._check(
                await self._http.request(
                    "POST",
                    f"{_API}/files?fields=id",
                    json={"name": _FOLDER_NAME, "mimeType": _FOLDER_MIME},
                ),
                "folder create",
            )
            self._folder_id = resp.json()["id"]
        return self._folder_id

    # -- Provider interface ------------------------------------------------------

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        if self._max_object_bytes is not None and len(data) > self._max_object_bytes:
            raise ObjectTooLargeError(
                f"object of {len(data)} bytes exceeds configured max "
                f"{self._max_object_bytes}"
            )
        folder = await self._ensure_folder()
        # resumable session: POST metadata, receive the upload URL...
        resp = self._check(
            await self._http.request(
                "POST",
                f"{_UPLOAD_API}/files?uploadType=resumable&fields=id",
                json={"name": chunk_id, "parents": [folder]},
                headers={
                    "X-Upload-Content-Type": "application/octet-stream",
                    "X-Upload-Content-Length": str(len(data)),
                },
            ),
            "upload session",
        )
        session_url = resp.headers.get("Location")
        if not session_url:
            raise ScatterboxError("gdrive upload session returned no Location URL")
        # ...then PUT the bytes in one shot (chunks fit in a single request).
        resp = self._check(
            await self._http.request(
                "PUT",
                session_url,
                content=data,
                headers={"Content-Type": "application/octet-stream"},
            ),
            "upload",
        )
        return RemoteRef(resp.json()["id"])

    async def get(self, ref: RemoteRef) -> bytes:
        resp = self._check(
            await self._http.request("GET", f"{_API}/files/{ref.value}?alt=media"),
            "download",
        )
        return resp.content

    async def delete(self, ref: RemoteRef) -> None:
        resp = await self._http.request("DELETE", f"{_API}/files/{ref.value}")
        if resp.status_code == 404:
            return  # already gone — deletion is idempotent
        self._check(resp, "delete")

    async def exists(self, ref: RemoteRef) -> bool:
        resp = await self._http.request(
            "GET", f"{_API}/files/{ref.value}?fields=id,trashed"
        )
        if resp.status_code == 404:
            return False
        self._check(resp, "exists probe")
        # Trashed is as good as gone: the user threw it away, and Drive will
        # purge it — treat it as missing so repair makes a real copy.
        return not resp.json().get("trashed", False)

    async def quota(self) -> Quota:
        resp = self._check(
            await self._http.request("GET", f"{_API}/about?fields=storageQuota"),
            "quota",
        )
        sq = resp.json().get("storageQuota", {})
        used = int(sq.get("usage", 0))
        limit = int(sq["limit"]) if "limit" in sq else None  # absent = unlimited plan
        if self._capacity_bytes is not None:
            # The user said "use at most this much" — honor the tighter cap.
            limit = min(limit, self._capacity_bytes) if limit else self._capacity_bytes
        if limit is None:
            return Quota(total_bytes=None, used_bytes=used, confidence="unknown")
        return Quota(total_bytes=limit, used_bytes=used, confidence="exact")
