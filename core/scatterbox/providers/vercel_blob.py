"""Vercel Blob adapter.

Talks to the Vercel Blob REST API directly over httpx (same no-SDK rationale as
the other adapters). Unlike the S3-compatible backends, Vercel Blob is a simple
**Bearer-token** REST API, so it reuses TokenManager / AuthedClient like the
OAuth backends — but the credential is a single static **Read-Write Token**
(`BLOB_READ_WRITE_TOKEN` from the Vercel dashboard), stored as
`{"access_token": <token>}`. There is nothing to refresh, so a 401 surfaces as
a re-authenticate error (the TokenManager turns a rejected static token into
"no refresh token", the same path Koofr relies on).

Four Vercel Blob traits shape this adapter:

- One API host, public object host. Metadata operations (upload, delete, head,
  list) go to `https://blob.vercel-storage.com` with the bearer; the object
  itself is served from a public, unguessable `*.public.blob.vercel-storage.com`
  URL, so get() fetches that URL WITHOUT the bearer (authed=False). Objects are
  therefore exposure_risk "high": public URLs, readable by anyone who has them
  (every chunk is encrypted before upload regardless).
- Upload returns the ref. PUT `/<pathname>` returns JSON whose `url` is the
  object's public URL; that URL IS the RemoteRef, so get/delete/exists need no
  lookup. A `scatterbox/` pathname prefix keeps the footprint contained, and
  the random suffix is disabled so the pathname (and URL) is stable.
- Delete by URL. `POST /delete` with `{"urls": [...]}`; already-gone is success.
- Versioned API. Every request carries an `x-api-version` header.

quota() lists the `scatterbox/` prefix and sums object sizes (also the
onboarding connection test). Vercel reports no free-space cap, so total is the
user's configured capacity if set ('estimated') else None ('unknown').
"""

from __future__ import annotations

import httpx

from scatterbox.errors import ObjectTooLargeError, ProviderFullError, ScatterboxError
from scatterbox.oauth import TokenManager
from scatterbox.providers._http import AuthedClient
from scatterbox.providers.base import ProviderProfile, Quota, RemoteRef, Transform
from scatterbox.vault import SecretStore

_BASE = "https://blob.vercel-storage.com"
_PREFIX = "scatterbox"
# Vercel Blob requires an API version header on every request; this tracks the
# Vercel Blob API and may need bumping if Vercel raises the required version.
_API_VERSION = "7"
# Single-request, in-memory upload ceiling (the splitter never builds an object
# larger than the one-shot PUT can hold in memory).
_UPLOAD_MAX = 500 * 1024 * 1024

_PROFILE = ProviderProfile(
    latency_class="hot",  # CDN-backed object delivery
    throughput_class="high",
    max_object_bytes=_UPLOAD_MAX,
    reliability_prior=0.85,  # solid managed store, a newer/free-tier service
    exposure_risk="high",  # objects served at public (unguessable) URLs
    rate_limited=True,
)


def credential_blob(token: str) -> dict:
    """Build the vault credential blob for a Vercel Blob read-write token.

    Stored as the static bearer credential under `access_token`, so the
    TokenManager serves it straight through (no expiry, no refresh) and the
    AuthedClient sends it as `Authorization: Bearer <it>`. The one place the
    token becomes a stored blob; add/reauth/recover all route through here."""
    return {"access_token": token}


class VercelBlobProvider:
    """Provider adapter for Vercel Blob storage (module docstring covers the
    bearer-token, public-URL, and versioned-API wrinkles)."""

    transform: Transform | None = None

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        base_url: str | None = None,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,  # user cap: "use at most N of the store"
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        self._base = (base_url or _BASE).rstrip("/")
        tokens = TokenManager(secrets, secret_name, transport=transport)
        # Static bearer token (default scheme) — no refresh, like a pCloud token.
        self._http = AuthedClient(tokens, transport=transport, backoff_base_s=backoff_base_s)
        self._max_object_bytes = max_object_bytes
        self._capacity_bytes = capacity_bytes

    def profile(self) -> ProviderProfile:
        """Static class profile, tightened by the user's per-instance object cap
        (never above the single-request upload ceiling)."""
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

    # -- helpers ----------------------------------------------------------------

    @staticmethod
    def _api_headers() -> dict:
        return {"x-api-version": _API_VERSION}

    def _check(self, resp: httpx.Response, action: str) -> httpx.Response:
        """Map a Vercel Blob error response onto scatterbox's exceptions;
        returns the response unchanged on success. (401 never reaches here —
        AuthedClient turns a rejected static token into a re-auth error.)"""
        if resp.status_code < 300:
            return resp
        body = resp.text[:300]
        if resp.status_code == 507 or b"exceeded" in resp.content.lower() or (
            resp.status_code == 403 and b"limit" in resp.content.lower()
        ):
            raise ProviderFullError("Vercel Blob store limit reached")
        if resp.status_code == 403:
            raise ScatterboxError(
                f"Vercel Blob {action} was rejected (HTTP 403): the read-write "
                "token was refused — re-run 'scatterbox provider reauth'. " + body
            )
        raise ScatterboxError(f"vercel blob {action} failed (HTTP {resp.status_code}): {body}")

    # -- Provider interface ------------------------------------------------------

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        """Upload opaque bytes under the scatterbox/ pathname prefix; the ref is
        the returned public URL. The random suffix is disabled so the pathname
        is stable (a re-snapshot overwrites in place rather than orphaning)."""
        cap = self.profile().max_object_bytes
        if cap is not None and len(data) > cap:
            raise ObjectTooLargeError(f"object of {len(data)} bytes exceeds max {cap}")
        pathname = f"{_PREFIX}/{chunk_id}"
        resp = await self._http.request(
            "PUT",
            f"{self._base}/{pathname}",
            headers={
                **self._api_headers(),
                "x-add-random-suffix": "0",  # stable pathname/URL across re-puts
                "x-content-type": "application/octet-stream",
            },
            content=data,
        )
        self._check(resp, "upload")
        return RemoteRef(resp.json()["url"])

    async def get(self, ref: RemoteRef) -> bytes:
        """Download by the object's public URL — served openly, so the bearer
        is NOT sent (authed=False)."""
        resp = await self._http.request("GET", ref.value, authed=False)
        if resp.status_code == 404:
            raise ScatterboxError(f"vercel blob: object {ref.value!r} not found")
        self._check(resp, "download")
        return resp.content

    async def delete(self, ref: RemoteRef) -> None:
        """Delete by URL; already-gone is success (idempotent)."""
        resp = await self._http.request(
            "POST",
            f"{self._base}/delete",
            headers=self._api_headers(),
            json={"urls": [ref.value]},
        )
        if resp.status_code == 404:
            return  # already gone
        self._check(resp, "delete")

    async def exists(self, ref: RemoteRef) -> bool:
        """Cheap scrub probe: the head operation (metadata only, no body)."""
        resp = await self._http.request(
            "GET", self._base, headers=self._api_headers(), params={"url": ref.value}
        )
        if resp.status_code == 404:
            return False
        self._check(resp, "exists probe")
        return True

    async def find(self, name: str) -> RemoteRef | None:
        """Locate an object by its put-time name: list the known pathname prefix
        and match the exact pathname (what makes Vercel Blob a cold-recovery
        source — the public URL isn't known without the listing)."""
        pathname = f"{_PREFIX}/{name}"
        cursor: str | None = None
        while True:
            params = {"prefix": pathname, "limit": "1000"}
            if cursor:
                params["cursor"] = cursor
            resp = self._check(
                await self._http.request(
                    "GET", self._base, headers=self._api_headers(), params=params
                ),
                "find",
            )
            body = resp.json()
            for blob in body.get("blobs", []):
                if blob.get("pathname") == pathname:
                    return RemoteRef(blob["url"])
            cursor = body.get("cursor")
            if not body.get("hasMore"):
                return None

    async def quota(self) -> Quota:
        """Sum stored bytes under the prefix via the list operation (also the
        onboarding connection test). Vercel reports no free-space cap, so total
        is the user's configured capacity if set ('estimated') else None
        ('unknown')."""
        used = 0
        cursor: str | None = None
        while True:
            params = {"prefix": f"{_PREFIX}/", "limit": "1000"}
            if cursor:
                params["cursor"] = cursor
            resp = self._check(
                await self._http.request(
                    "GET", self._base, headers=self._api_headers(), params=params
                ),
                "quota",
            )
            body = resp.json()
            used += sum(int(b.get("size", 0)) for b in body.get("blobs", []))
            cursor = body.get("cursor")
            if not body.get("hasMore"):
                break
        if self._capacity_bytes is None:
            return Quota(total_bytes=None, used_bytes=used, confidence="unknown")
        return Quota(total_bytes=self._capacity_bytes, used_bytes=used, confidence="estimated")
