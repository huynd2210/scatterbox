"""pCloud adapter.

Talks to the pCloud HTTP API directly over httpx (same no-SDK rationale as
the gdrive/onedrive/dropbox adapters). Objects live in a visible
`scatterbox/` folder at the account root — find-or-created lazily and
remembered via learned_config(), exactly like the Drive adapter — so the
revoke-and-heal verify gate works and scatterbox's footprint is contained
(pCloud's OAuth grant covers the whole account; there is no app-folder
sandbox like Dropbox's or Drive's drive.file scope).

Three pCloud traits shape this adapter:

- Region. pCloud runs two independent data centers, US (api.pcloud.com) and
  EU (eapi.pcloud.com); an account lives in exactly one. The OAuth redirect
  reveals which (`hostname`/`locationid`), and that host is persisted in the
  token blob as `api_base` so every request targets the right region.
- Result-code errors. Almost everything returns HTTP 200 with a JSON
  `result` field — 0 is success, 2008 is over-quota, 2005/2009/2010 are
  not-found/bad-path. So error mapping reads the body, not the status code.
  The genuine HTTP errors pCloud still emits (429/5xx) are handled by the
  shared AuthedClient as usual.
- Non-expiring tokens. The OAuth access token never expires and there is no
  refresh token (see oauth.run_loopback_flow / TokenManager); it is sent as
  a Bearer header like the other adapters. A rejected token is therefore a
  re-auth, not a refresh.

Upload is a single multipart/form-data POST to `uploadfile`; download is two
steps — `getfilelink` returns a host+path, then a plain (unauthenticated) GET
fetches the bytes (the link carries its own token).
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

_FOLDER_NAME = "scatterbox"
_DEFAULT_API = "https://api.pcloud.com"  # US; EU accounts override via api_base
# A single uploadfile request streams the object in one shot; cap it well
# below any practical limit so the splitter never builds an object pCloud
# would reject mid-upload.
_UPLOAD_MAX = 150 * 1024 * 1024

# pCloud result codes we act on; any other nonzero result is a hard error.
_RESULT_OVER_QUOTA = 2008
_RESULT_NOT_FOUND = {2005, 2009, 2010}  # dir not found, file not found, invalid path

# OAuth endpoints for the CLI/daemon onboarding flow, kept here so all pCloud
# knowledge lives in one file. The token host is region-dependent: TOKEN_URL
# is the US default and resolve_token_url() picks the real one (and records
# api_base) from the redirect parameters.
AUTH_URL = "https://my.pcloud.com/oauth2/authorize"
TOKEN_URL = f"{_DEFAULT_API}/oauth2_token"
SCOPES = ""  # pCloud has no scope parameter — access is whole-account
# pCloud is a confidential client (a client_secret is required at the token
# endpoint) and issues a non-expiring access token with no refresh token.
REQUIRE_REFRESH_TOKEN = False
# pCloud verifies the redirect URI against the value registered in the App
# Console, so the loopback flow uses a fixed port (like Dropbox); the user
# registers http://127.0.0.1:8422/ once.
REDIRECT_PORT = 8422

_HOST_BY_LOCATION = {"1": "api.pcloud.com", "2": "eapi.pcloud.com"}


def resolve_token_url(redirect_params: dict) -> tuple[str, dict]:
    """Pick the token endpoint and api_base for the account's data center.

    pCloud's redirect carries `hostname` (and `locationid`: 1=US, 2=EU); we
    exchange the code against that host and persist it as `api_base` so the
    adapter later talks to the same region. Returned as (token_url,
    blob_extra) for run_loopback_flow.
    """
    host = redirect_params.get("hostname") or _HOST_BY_LOCATION.get(
        redirect_params.get("locationid", "1"), "api.pcloud.com"
    )
    api_base = f"https://{host}"
    return f"{api_base}/oauth2_token", {"api_base": api_base}


_PROFILE = ProviderProfile(
    latency_class="hot",
    throughput_class="high",
    max_object_bytes=_UPLOAD_MAX,
    reliability_prior=0.85,  # solid consumer cloud, a notch below Drive/OneDrive
    exposure_risk="low",
    rate_limited=True,
)


class PCloudProvider:
    """Provider adapter for pCloud account storage (module docstring covers
    the region, result-code, and non-expiring-token wrinkles)."""

    transform: Transform | None = None

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        folder_id: int | None = None,
        api_base: str | None = None,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,  # user cap: "use at most N of my pCloud"
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        # The per-account API host (region) is discovered at onboarding and
        # stored in the token blob; prefer an explicit/config value, then the
        # blob, then the US default.
        blob = secrets.get_secret(secret_name)
        self._api = (api_base or blob.get("api_base") or _DEFAULT_API).rstrip("/")
        tokens = TokenManager(secrets, secret_name, transport=transport)
        self._http = AuthedClient(
            tokens, transport=transport, backoff_base_s=backoff_base_s
        )
        self._folder_id = folder_id
        self._max_object_bytes = max_object_bytes
        self._capacity_bytes = capacity_bytes

    def profile(self) -> ProviderProfile:
        """Static class profile, tightened by the user's per-instance object
        cap when configured (the single-request upload size is the ceiling)."""
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

    def learned_config(self) -> dict:
        """Config keys discovered at runtime, for the CLI to persist."""
        return {"folder_id": self._folder_id} if self._folder_id is not None else {}

    async def prepare(self) -> None:
        """Onboarding hook: find-or-create the scatterbox folder now, so it
        appears in the account immediately and its id lands in
        learned_config() for the CLI to persist."""
        await self._ensure_folder()

    # -- helpers ----------------------------------------------------------------

    def _raise_for(self, body: dict, action: str) -> dict:
        """Map a pCloud response body's `result` code onto scatterbox's
        exception hierarchy; returns the body unchanged on success."""
        result = body.get("result", 0)
        if result == 0:
            return body
        if result == _RESULT_OVER_QUOTA:
            raise ProviderFullError("pCloud storage quota exceeded")
        raise ScatterboxError(
            f"pcloud {action} failed (result {result}): {body.get('error', '')}"
        )

    async def _ensure_folder(self) -> int:
        """Find-or-create the visible scatterbox/ folder at the account root;
        caches the id for this adapter's lifetime (persisted via
        learned_config). createfolderifnotexists is idempotent."""
        if self._folder_id is not None:
            return self._folder_id
        resp = await self._http.request(
            "POST",
            f"{self._api}/createfolderifnotexists",
            params={"path": f"/{_FOLDER_NAME}"},
        )
        body = self._raise_for(resp.json(), "folder create")
        self._folder_id = int(body["metadata"]["folderid"])
        return self._folder_id

    # -- Provider interface ------------------------------------------------------

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        """Upload one stored object as a single multipart request into the
        scatterbox folder; returns the pCloud file id as the ref."""
        cap = self.profile().max_object_bytes
        if cap is not None and len(data) > cap:
            raise ObjectTooLargeError(f"object of {len(data)} bytes exceeds max {cap}")
        folder = await self._ensure_folder()
        resp = await self._http.request(
            "POST",
            f"{self._api}/uploadfile",
            params={"folderid": folder, "nopartial": 1},
            files={"file": (chunk_id, data, "application/octet-stream")},
        )
        body = self._raise_for(resp.json(), "upload")
        return RemoteRef(str(body["metadata"][0]["fileid"]))

    async def get(self, ref: RemoteRef) -> bytes:
        """Download an object's bytes: getfilelink yields a host+path, then a
        plain GET fetches the content (the link carries its own token)."""
        resp = await self._http.request(
            "GET", f"{self._api}/getfilelink", params={"fileid": ref.value}
        )
        body = self._raise_for(resp.json(), "download link")
        url = f"https://{body['hosts'][0]}{body['path']}"
        data = await self._http.request("GET", url, authed=False)
        if data.status_code >= 400:
            raise ScatterboxError(f"pcloud download failed (HTTP {data.status_code})")
        return data.content

    async def delete(self, ref: RemoteRef) -> None:
        """Delete by file id; already-gone (result 2009) is success."""
        resp = await self._http.request(
            "POST", f"{self._api}/deletefile", params={"fileid": ref.value}
        )
        body = resp.json()
        if body.get("result") in _RESULT_NOT_FOUND:
            return  # already gone — deletion is idempotent
        self._raise_for(body, "delete")

    async def exists(self, ref: RemoteRef) -> bool:
        """Cheap scrub probe: stat (metadata only), no content download. A
        file the user deleted in the pCloud UI is not_found here."""
        resp = await self._http.request(
            "POST", f"{self._api}/stat", params={"fileid": ref.value}
        )
        body = resp.json()
        if body.get("result") in _RESULT_NOT_FOUND:
            return False
        self._raise_for(body, "exists probe")
        return True

    async def find(self, name: str) -> RemoteRef | None:
        """Locate an object by its put-time name: the scatterbox folder sits
        at a known root path, so this is one stat by path (what makes pCloud
        usable as a cold-recovery source)."""
        resp = await self._http.request(
            "POST", f"{self._api}/stat", params={"path": f"/{_FOLDER_NAME}/{name}"}
        )
        body = resp.json()
        if body.get("result") in _RESULT_NOT_FOUND:
            return None
        self._raise_for(body, "find")
        return RemoteRef(str(body["metadata"]["fileid"]))

    async def quota(self) -> Quota:
        """Account storage numbers from userinfo — 'exact' confidence,
        optionally tightened by the user's capacity cap."""
        resp = await self._http.request("GET", f"{self._api}/userinfo")
        body = self._raise_for(resp.json(), "quota")
        used = int(body.get("usedquota", 0))
        total = body.get("quota")
        total = int(total) if total is not None else None
        if self._capacity_bytes is not None:
            total = min(total, self._capacity_bytes) if total else self._capacity_bytes
        if total is None:
            return Quota(total_bytes=None, used_bytes=used, confidence="unknown")
        return Quota(total_bytes=total, used_bytes=used, confidence="exact")
