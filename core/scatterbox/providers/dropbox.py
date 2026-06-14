"""Dropbox adapter.

Talks to the Dropbox v2 HTTP API directly over httpx (same no-SDK rationale
as the gdrive/onedrive adapters). The app is created with *App folder*
access, so objects live in `Apps/<app name>/` — visible and manually
deletable (the revoke-and-heal verify gate works), while the rest of the
account stays off-limits.

API shape notes:
- Content endpoints (`files/upload`, `files/download`) take their arguments
  in a `Dropbox-API-Arg` JSON header, not the body — the body is the raw
  object bytes (or empty for download).
- RPC endpoints (`files/get_metadata`, `files/delete_v2`,
  `users/get_space_usage`) are plain JSON POSTs.
- Domain errors come back as 409 with an `error_summary` string; rate
  limiting is a regular 429 (handled by AuthedClient).
- A single `files/upload` request is capped at 150 MB — far above the 8 MiB
  default chunk size, so no upload-session protocol is needed; the cap is
  declared in the profile so the splitter can never exceed it.

OAuth: Dropbox apps are public clients here (PKCE, no secret), but unlike
Google/Microsoft the redirect URI must be pre-registered EXACTLY — random
loopback ports won't match. REDIRECT_PORT pins the loopback flow to one
port; the user registers `http://127.0.0.1:8421/` once in the App Console.
Refresh tokens require `token_access_type=offline` and do not rotate.
"""

from __future__ import annotations

import json

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

_API = "https://api.dropboxapi.com/2"
_CONTENT = "https://content.dropboxapi.com/2"
_UPLOAD_MAX = 150 * 1024 * 1024  # documented files/upload single-request cap

# OAuth endpoints/scope for the CLI/daemon onboarding flow.
AUTH_URL = "https://www.dropbox.com/oauth2/authorize"
TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"
SCOPES = "files.content.read files.content.write files.metadata.read account_info.read"
# Without token_access_type=offline Dropbox issues no refresh token.
EXTRA_AUTH_PARAMS = {"token_access_type": "offline"}
# Dropbox verifies redirect URIs against the exact registered values, so the
# loopback flow cannot use a random port (oauth.run_loopback_flow fixed_port).
REDIRECT_PORT = 8421

_PROFILE = ProviderProfile(
    latency_class="hot",
    throughput_class="high",
    max_object_bytes=_UPLOAD_MAX,
    reliability_prior=0.9,  # big-cloud class, same as Drive/OneDrive
    exposure_risk="low",
    rate_limited=True,
)


class DropboxProvider:
    """Provider adapter for Dropbox app-folder storage (module docstring
    covers the API shape and the fixed-redirect-port OAuth wrinkle)."""

    transform: Transform | None = None

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,  # user cap: "use at most N of my Dropbox"
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        tokens = TokenManager(secrets, secret_name, transport=transport)
        self._http = AuthedClient(tokens, transport=transport, backoff_base_s=backoff_base_s)
        self._max_object_bytes = max_object_bytes
        self._capacity_bytes = capacity_bytes

    def profile(self) -> ProviderProfile:
        """Static class profile, tightened by the user's per-instance object
        cap when configured (the API's own 150 MB cap is the ceiling)."""
        if self._max_object_bytes is None:
            return _PROFILE
        return ProviderProfile(
            latency_class=_PROFILE.latency_class,
            throughput_class=_PROFILE.throughput_class,
            max_object_bytes=min(self._max_object_bytes, _UPLOAD_MAX),
            reliability_prior=_PROFILE.reliability_prior,
            exposure_risk=_PROFILE.exposure_risk,
            rate_limited=_PROFILE.rate_limited,
        )

    def _check(self, resp: httpx.Response, action: str) -> httpx.Response:
        """Map Dropbox error responses onto scatterbox's exception hierarchy."""
        if resp.status_code < 400:
            return resp
        if resp.status_code == 409 and b"insufficient_space" in resp.content:
            raise ProviderFullError("Dropbox storage quota exceeded")
        raise ScatterboxError(
            f"dropbox {action} failed ({resp.status_code}): {resp.text[:200]}"
        )

    @staticmethod
    def _is_not_found(resp: httpx.Response) -> bool:
        """Dropbox path errors are 409s with a machine-readable summary."""
        return resp.status_code == 409 and b"not_found" in resp.content

    # -- Provider interface ------------------------------------------------------

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        """Upload one stored object in a single content request; returns the
        Dropbox file id as the ref."""
        cap = self.profile().max_object_bytes
        if cap is not None and len(data) > cap:
            raise ObjectTooLargeError(
                f"object of {len(data)} bytes exceeds max {cap}"
            )
        arg = {"path": f"/{chunk_id}", "mode": "overwrite", "mute": True}
        resp = self._check(
            await self._http.request(
                "POST",
                f"{_CONTENT}/files/upload",
                content=data,
                headers={
                    "Dropbox-API-Arg": json.dumps(arg),
                    "Content-Type": "application/octet-stream",
                },
            ),
            "upload",
        )
        return RemoteRef(resp.json()["id"])

    async def get(self, ref: RemoteRef) -> bytes:
        """Download an object's bytes (the file id works as a path arg)."""
        resp = self._check(
            await self._http.request(
                "POST",
                f"{_CONTENT}/files/download",
                headers={"Dropbox-API-Arg": json.dumps({"path": ref.value})},
            ),
            "download",
        )
        return resp.content

    async def delete(self, ref: RemoteRef) -> None:
        """Delete by file id; already-gone is success (idempotent)."""
        resp = await self._http.request(
            "POST", f"{_API}/files/delete_v2", json={"path": ref.value}
        )
        if self._is_not_found(resp):
            return  # already gone — deletion is idempotent
        self._check(resp, "delete")

    async def exists(self, ref: RemoteRef) -> bool:
        """Cheap scrub probe: metadata fetch, no content download. A file the
        user deleted in the Dropbox UI is not_found here (no trash facet)."""
        resp = await self._http.request(
            "POST", f"{_API}/files/get_metadata", json={"path": ref.value}
        )
        if self._is_not_found(resp):
            return False
        self._check(resp, "exists probe")
        return True

    async def find(self, name: str) -> RemoteRef | None:
        """Locate an object by its put-time name: the app folder is
        path-addressable, so this is one direct lookup."""
        resp = await self._http.request(
            "POST", f"{_API}/files/get_metadata", json={"path": f"/{name}"}
        )
        if self._is_not_found(resp):
            return None
        self._check(resp, "find")
        return RemoteRef(resp.json()["id"])

    async def quota(self) -> Quota:
        """Account storage numbers from get_space_usage — 'exact'
        confidence, optionally tightened by the user's capacity cap."""
        resp = self._check(
            await self._http.request("POST", f"{_API}/users/get_space_usage"),
            "quota",
        )
        body = resp.json()
        used = int(body.get("used", 0))
        total = body.get("allocation", {}).get("allocated")
        total = int(total) if total else None
        if self._capacity_bytes is not None:
            total = min(total, self._capacity_bytes) if total else self._capacity_bytes
        if total is None:
            return Quota(total_bytes=None, used_bytes=used, confidence="unknown")
        return Quota(total_bytes=total, used_bytes=used, confidence="exact")
