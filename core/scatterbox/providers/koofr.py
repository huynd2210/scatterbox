"""Koofr adapter.

Talks to the Koofr Files API directly over httpx (same no-SDK rationale as
the gdrive/onedrive/dropbox/pcloud adapters). Objects live in a visible
`scatterbox/` folder at the account's primary mount root — find-or-created
lazily and remembered via learned_config(), like the Drive/pCloud adapters —
so the revoke-and-heal verify gate works and scatterbox's footprint stays
contained.

Four Koofr traits shape this adapter:

- App-password / Basic auth (not OAuth). Koofr's recommended OAuth client
  registration is not self-serve, whereas an *application-specific password*
  is one click in the account's web settings, limited-scope, and individually
  revocable — exactly the "providers are hostile, revoke a chunk and watch it
  heal" posture scatterbox wants. So credentials are an app password sent as
  HTTP Basic (`Authorization: Basic base64(email:app_password)`), the way
  rclone's Koofr backend authenticates. It is a *static* credential: there is
  no token to refresh, so a rejected one is a re-auth, not a refresh (the
  AuthedClient's 401 path surfaces that via the TokenManager).
- Mounts. Every Koofr path is scoped to a "mount"; a user's own storage is
  their *primary* mount. The mount id is discovered once via /api/v2/mounts
  and persisted through learned_config() (`mount_id`), like pCloud's api_base
  — every file request then targets that mount.
- Split API hosts by path. Metadata/RPC calls live under `/api/v2/...`;
  content (upload/download) lives under `/content/api/v2/...` on the same
  host. Both are app-password authenticated.
- Path-addressable. Every object is addressed by its path, so the RemoteRef
  IS the object's path — get/delete/exists are direct, and find() (what makes
  Koofr usable as a cold-recovery source) is a single files/info call.

Upload is one multipart/form-data POST to `files/put` (the real filename is a
query param; `overwrite=true` makes a same-name rewrite replace in place, so a
re-snapshot keeps the same path/ref); download is a plain GET of `files/get`.
"""

from __future__ import annotations

import base64

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

_FOLDER_NAME = "scatterbox"
_DEFAULT_BASE = "https://app.koofr.net"  # Koofr; Digi Storage / self-hosted override


def credential_blob(email: str, app_password: str) -> dict:
    """Build the vault credential blob for a Koofr app password.

    Stored as the pre-computed HTTP Basic credential under `access_token`, so
    the TokenManager serves it straight through (no expiry, no refresh) and
    the AuthedClient sends it as `Authorization: Basic <it>`. This is the one
    place that knows the email + app password become a Basic credential; the
    CLI/daemon onboarding, reauth, and cold recovery all go through here."""
    raw = f"{email}:{app_password}".encode("utf-8")
    return {"access_token": base64.b64encode(raw).decode("ascii")}


_PROFILE = ProviderProfile(
    latency_class="hot",
    throughput_class="high",
    max_object_bytes=None,  # full cloud drive: no small per-request cap (like Drive)
    reliability_prior=0.85,  # solid EU consumer cloud, a notch below Drive/OneDrive
    exposure_risk="low",
    rate_limited=True,
)


class KoofrProvider:
    """Provider adapter for Koofr account storage (module docstring covers the
    app-password, mount, split-host, and path-addressing wrinkles)."""

    transform: Transform | None = None

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        mount_id: str | None = None,
        base_url: str | None = None,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,  # user cap: "use at most N of my Koofr"
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        self._base = (base_url or _DEFAULT_BASE).rstrip("/")
        tokens = TokenManager(secrets, secret_name, transport=transport)
        # Koofr authenticates with an app password sent as HTTP Basic, not a
        # bearer token — the only adapter that overrides the auth scheme.
        self._http = AuthedClient(
            tokens,
            transport=transport,
            backoff_base_s=backoff_base_s,
            auth_scheme="Basic",
        )
        self._mount_id = mount_id
        self._max_object_bytes = max_object_bytes
        self._capacity_bytes = capacity_bytes

    def profile(self) -> ProviderProfile:
        """Static class profile, tightened by the user's per-instance object
        cap when one is configured."""
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

    def learned_config(self) -> dict:
        """Config keys discovered at runtime, for the CLI to persist."""
        return {"mount_id": self._mount_id} if self._mount_id is not None else {}

    async def prepare(self) -> None:
        """Onboarding hook: resolve the primary mount and create the
        scatterbox/ folder now, so it appears in the account immediately and
        the mount id lands in learned_config() for the CLI to persist."""
        await self._ensure_folder()

    # -- helpers ----------------------------------------------------------------

    def _api(self, mount_id: str, op: str) -> str:
        return f"{self._base}/api/v2/mounts/{mount_id}/files/{op}"

    def _content(self, mount_id: str, op: str) -> str:
        return f"{self._base}/content/api/v2/mounts/{mount_id}/files/{op}"

    def _check(self, resp: httpx.Response, action: str) -> httpx.Response:
        """Map a Koofr error response onto scatterbox's exception hierarchy;
        returns the response unchanged on success."""
        if resp.status_code < 400:
            return resp
        # 507 Insufficient Storage is the standard over-quota signal; some
        # responses only say so in the body.
        if resp.status_code == 507 or b"quota" in resp.content.lower():
            raise ProviderFullError("Koofr storage quota exceeded")
        raise ScatterboxError(
            f"koofr {action} failed ({resp.status_code}): {resp.text[:200]}"
        )

    @staticmethod
    def _is_not_found(resp: httpx.Response) -> bool:
        """A missing path is a plain HTTP 404 across files/info, files/get,
        and files/remove."""
        return resp.status_code == 404

    async def _ensure_mount(self) -> str:
        """Resolve and cache the account's primary mount id (persisted via
        learned_config). The primary mount is the user's own storage."""
        if self._mount_id is not None:
            return self._mount_id
        resp = self._check(
            await self._http.request("GET", f"{self._base}/api/v2/mounts"),
            "list mounts",
        )
        mounts = resp.json().get("mounts", [])
        primary = next(
            (m for m in mounts if m.get("isPrimary")),
            mounts[0] if mounts else None,
        )
        if primary is None:
            raise ScatterboxError("koofr account has no mounts")
        self._mount_id = str(primary["id"])
        return self._mount_id

    async def _ensure_folder(self) -> str:
        """Find-or-create the visible scatterbox/ folder at the mount root;
        creating one that already exists is a 409 we treat as success."""
        mount = await self._ensure_mount()
        resp = await self._http.request(
            "POST",
            self._api(mount, "folder"),
            params={"path": "/"},
            json={"name": _FOLDER_NAME},
        )
        if resp.status_code != 409:  # 409 == already exists, which is fine
            self._check(resp, "folder create")
        return mount

    # -- Provider interface ------------------------------------------------------

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        """Upload one stored object as a single multipart request into the
        scatterbox folder; the ref is the object's (stable) path. overwrite
        replaces a same-name object in place rather than autorenaming."""
        cap = self.profile().max_object_bytes
        if cap is not None and len(data) > cap:
            raise ObjectTooLargeError(f"object of {len(data)} bytes exceeds max {cap}")
        mount = await self._ensure_folder()
        resp = await self._http.request(
            "POST",
            self._content(mount, "put"),
            params={
                "path": f"/{_FOLDER_NAME}",
                "filename": chunk_id,
                "info": "true",
                "overwrite": "true",
            },
            files={"file": (chunk_id, data, "application/octet-stream")},
        )
        self._check(resp, "upload")
        return RemoteRef(f"/{_FOLDER_NAME}/{chunk_id}")

    async def get(self, ref: RemoteRef) -> bytes:
        """Download an object's bytes by path from the content host."""
        mount = await self._ensure_mount()
        resp = self._check(
            await self._http.request(
                "GET", self._content(mount, "get"), params={"path": ref.value}
            ),
            "download",
        )
        return resp.content

    async def delete(self, ref: RemoteRef) -> None:
        """Delete by path; already-gone (404) is success (idempotent)."""
        mount = await self._ensure_mount()
        resp = await self._http.request(
            "DELETE", self._api(mount, "remove"), params={"path": ref.value}
        )
        if self._is_not_found(resp):
            return  # already gone — deletion is idempotent
        self._check(resp, "delete")

    async def exists(self, ref: RemoteRef) -> bool:
        """Cheap scrub probe: files/info (metadata only), no content download.
        A file the user deleted in the Koofr UI is 404 here."""
        mount = await self._ensure_mount()
        resp = await self._http.request(
            "GET", self._api(mount, "info"), params={"path": ref.value}
        )
        if self._is_not_found(resp):
            return False
        self._check(resp, "exists probe")
        return True

    async def find(self, name: str) -> RemoteRef | None:
        """Locate an object by its put-time name: the scatterbox folder sits
        at a known mount-root path, so this is one files/info by path (what
        makes Koofr usable as a cold-recovery source)."""
        mount = await self._ensure_mount()
        path = f"/{_FOLDER_NAME}/{name}"
        resp = await self._http.request(
            "GET", self._api(mount, "info"), params={"path": path}
        )
        if self._is_not_found(resp):
            return None
        self._check(resp, "find")
        return RemoteRef(path)

    async def quota(self) -> Quota:
        """Account storage numbers from the primary mount — 'exact'
        confidence, optionally tightened by the user's capacity cap."""
        mount = await self._ensure_mount()
        resp = self._check(
            await self._http.request("GET", f"{self._base}/api/v2/mounts/{mount}"),
            "quota",
        )
        body = resp.json()
        used = int(body.get("spaceUsed", 0))
        total = body.get("spaceTotal")
        total = int(total) if total is not None else None
        if self._capacity_bytes is not None:
            total = min(total, self._capacity_bytes) if total else self._capacity_bytes
        if total is None:
            return Quota(total_bytes=None, used_bytes=used, confidence="unknown")
        return Quota(total_bytes=total, used_bytes=used, confidence="exact")
