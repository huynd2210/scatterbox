"""OneDrive adapter (Phase 2, PLAN.md §6/§12).

Talks to Microsoft Graph directly over httpx (same no-SDK rationale as the
gdrive adapter). Objects live in the *app folder* (`special/approot`) —
Graph materializes it as `Apps/<app name>/` in the user's OneDrive, visible
and manually deletable (so the revoke-and-heal verify gate works), while the
`Files.ReadWrite.AppFolder` scope keeps the rest of their drive off-limits.

Uploads: Graph's simple PUT tops out at 4 MiB, so anything bigger goes
through an upload session with fragments that must be multiples of 320 KiB
(a documented Graph requirement — misaligned fragments are rejected).
Default chunks are 8 MiB, so the session path is the common one.

Microsoft consumer apps are *public clients*: client_id only, no secret,
PKCE mandatory — and refresh tokens rotate on every refresh, which is why
TokenManager persists them back to the vault immediately.
"""

from __future__ import annotations

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

_GRAPH = "https://graph.microsoft.com/v1.0"
_SIMPLE_PUT_MAX = 4 * 1024 * 1024  # Graph's limit for single-request uploads
_FRAGMENT = 24 * 320 * 1024  # 7.5 MiB, a multiple of the required 320 KiB

# OAuth endpoints/scope for the CLI onboarding flow. The "consumers" tenant
# targets personal Microsoft accounts (OneDrive personal free tier).
AUTH_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
SCOPES = "Files.ReadWrite.AppFolder offline_access"

_PROFILE = ProviderProfile(
    latency_class="hot",
    throughput_class="high",
    max_object_bytes=None,
    reliability_prior=0.9,  # big-cloud class, same as Drive (PLAN.md §6)
    exposure_risk="low",
    rate_limited=True,
)


class OneDriveProvider:
    """Provider adapter for OneDrive personal via Microsoft Graph (module
    docstring covers the app folder and fragment-upload rules)."""

    transform: Transform | None = None

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,  # user cap: "use at most N of my OneDrive"
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        tokens = TokenManager(secrets, secret_name, transport=transport)
        self._http = AuthedClient(tokens, transport=transport, backoff_base_s=backoff_base_s)
        self._max_object_bytes = max_object_bytes
        self._capacity_bytes = capacity_bytes

    def profile(self) -> ProviderProfile:
        """Static class profile (PLAN.md §6 priors), with the per-instance
        object-size cap applied when the user configured one."""
        if self._max_object_bytes is None:
            return _PROFILE
        return ProviderProfile(
            latency_class=_PROFILE.latency_class,
            throughput_class=_PROFILE.throughput_class,
            max_object_bytes=self._max_object_bytes,
            reliability_prior=_PROFILE.reliability_prior,
            exposure_risk=_PROFILE.exposure_risk,
            rate_limited=_PROFILE.rate_limited,
        )

    def _check(self, resp: httpx.Response, action: str) -> httpx.Response:
        """Map Graph error responses onto scatterbox's exception hierarchy."""
        if resp.status_code < 400:
            return resp
        if resp.status_code == 507 or b"insufficientStorage" in resp.content:
            raise ProviderFullError("OneDrive storage quota exceeded")
        raise ScatterboxError(
            f"onedrive {action} failed ({resp.status_code}): {resp.text[:200]}"
        )

    # -- Provider interface ------------------------------------------------------

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        """Upload one stored object: simple PUT up to 4 MiB, an upload
        session with 320 KiB-aligned fragments above; returns the driveItem
        id as the ref."""
        if self._max_object_bytes is not None and len(data) > self._max_object_bytes:
            raise ObjectTooLargeError(
                f"object of {len(data)} bytes exceeds configured max "
                f"{self._max_object_bytes}"
            )
        if len(data) <= _SIMPLE_PUT_MAX:
            resp = self._check(
                await self._http.request(
                    "PUT",
                    f"{_GRAPH}/me/drive/special/approot:/{chunk_id}:/content"
                    "?@microsoft.graph.conflictBehavior=replace",
                    content=data,
                    headers={"Content-Type": "application/octet-stream"},
                ),
                "upload",
            )
            return RemoteRef(resp.json()["id"])

        # Upload session: create, then PUT 320 KiB-aligned fragments. The
        # session URL is pre-authorized — Graph documents that the bearer
        # header must NOT be sent on the fragment PUTs (authed=False).
        resp = self._check(
            await self._http.request(
                "POST",
                f"{_GRAPH}/me/drive/special/approot:/{chunk_id}:/createUploadSession",
                json={"item": {"@microsoft.graph.conflictBehavior": "replace"}},
            ),
            "upload session",
        )
        upload_url = resp.json()["uploadUrl"]
        total = len(data)
        for start in range(0, total, _FRAGMENT):
            end = min(start + _FRAGMENT, total)
            resp = self._check(
                await self._http.request(
                    "PUT",
                    upload_url,
                    authed=False,
                    content=data[start:end],
                    headers={
                        "Content-Length": str(end - start),
                        "Content-Range": f"bytes {start}-{end - 1}/{total}",
                    },
                ),
                "upload fragment",
            )
        # The final fragment's response carries the created driveItem.
        return RemoteRef(resp.json()["id"])

    async def get(self, ref: RemoteRef) -> bytes:
        """Download an object's bytes (follows Graph's pre-signed 302)."""
        # /content answers with a 302 to a pre-signed download URL; the
        # AuthedClient follows redirects.
        resp = self._check(
            await self._http.request("GET", f"{_GRAPH}/me/drive/items/{ref.value}/content"),
            "download",
        )
        return resp.content

    async def delete(self, ref: RemoteRef) -> None:
        """Delete by item id; already-gone is success (idempotent)."""
        resp = await self._http.request("DELETE", f"{_GRAPH}/me/drive/items/{ref.value}")
        if resp.status_code == 404:
            return  # already gone — deletion is idempotent
        self._check(resp, "delete")

    async def exists(self, ref: RemoteRef) -> bool:
        """Cheap scrub probe: metadata fetch; the deleted facet counts as
        missing so repair makes a real copy."""
        resp = await self._http.request(
            "GET", f"{_GRAPH}/me/drive/items/{ref.value}?$select=id,deleted"
        )
        if resp.status_code == 404:
            return False
        self._check(resp, "exists probe")
        return "deleted" not in resp.json()

    async def find(self, name: str) -> RemoteRef | None:
        """Locate an object by its put-time name: the app folder is
        path-addressable, so this is one direct lookup."""
        resp = await self._http.request(
            "GET", f"{_GRAPH}/me/drive/special/approot:/{name}?$select=id"
        )
        if resp.status_code == 404:
            return None
        self._check(resp, "find")
        return RemoteRef(resp.json()["id"])

    async def quota(self) -> Quota:
        """Drive quota from Graph — 'exact' confidence, optionally tightened
        by the user's capacity cap."""
        resp = self._check(
            await self._http.request("GET", f"{_GRAPH}/me/drive?$select=quota"),
            "quota",
        )
        q = resp.json().get("quota", {})
        used = int(q.get("used", 0))
        total = int(q["total"]) if q.get("total") else None
        if self._capacity_bytes is not None:
            total = min(total, self._capacity_bytes) if total else self._capacity_bytes
        if total is None:
            return Quota(total_bytes=None, used_bytes=used, confidence="unknown")
        return Quota(total_bytes=total, used_bytes=used, confidence="exact")
