"""OAuth 2.0 plumbing for real provider adapters (Phase 2).

Two pieces, used at different times:

- run_loopback_flow() — the one-time, interactive authorization. Used by
  `scatterbox provider add`: opens the system browser on the provider's
  consent page, catches the redirect on a local 127.0.0.1 port, exchanges
  the authorization code for tokens. Implements PKCE (S256), which is
  mandatory for Microsoft public clients and recommended for Google
  installed apps. Synchronous on purpose — it runs inside a CLI prompt
  session, not the async pipeline.

- TokenManager — the steady-state token source adapters use on every
  request. Hands out a valid access token, refreshing it via the
  refresh-token grant when (nearly) expired, and persists rotated refresh
  tokens back to the vault (Microsoft rotates them on every refresh;
  losing the new one would force the user to re-consent).

Token blobs stored in the vault look like:
    {"access_token": ..., "refresh_token": ..., "expires_at": <epoch float>,
     "client_id": ..., "client_secret": <or absent>, "token_url": ...}
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import os
import threading
import time
import urllib.parse
import webbrowser
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import httpx

from scatterbox.errors import ScatterboxError
from scatterbox.vault import SecretStore

# Refresh this many seconds before the access token actually expires, so a
# token can't die mid-upload between the check and the request.
_EXPIRY_SKEW_S = 60
_FLOW_TIMEOUT_S = 300  # give up if the user abandons the browser consent


def _pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) per RFC 7636, S256 method."""
    verifier = base64.urlsafe_b64encode(os.urandom(64)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


class _RedirectCatcher(BaseHTTPRequestHandler):
    """Minimal handler for the single loopback redirect request."""

    result: dict[str, str] = {}

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        """Capture the OAuth redirect's query params and show the user a
        you-can-close-this-tab page."""
        query = urllib.parse.urlparse(self.path).query
        params = dict(urllib.parse.parse_qsl(query))
        type(self).result = params
        ok = "code" in params
        self.send_response(200 if ok else 400)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        body = (
            "<h1>scatterbox: authorization complete</h1>You can close this tab."
            if ok
            else f"<h1>scatterbox: authorization failed</h1><pre>{params.get('error', 'no code returned')}</pre>"
        )
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *args: Any) -> None:
        pass  # keep the CLI output clean


def run_loopback_flow(
    *,
    auth_url: str,
    token_url: str,
    client_id: str,
    scopes: str,
    client_secret: str | None = None,
    extra_auth_params: dict[str, str] | None = None,
    fixed_port: int | None = None,
    open_browser: bool = True,
    timeout_s: float = _FLOW_TIMEOUT_S,
    require_refresh_token: bool = True,
    token_url_resolver: Callable[[dict[str, str]], tuple[str, dict[str, Any]]]
    | None = None,
) -> dict[str, Any]:
    """Interactive authorization-code + PKCE flow; returns a token blob.

    Binds a throwaway HTTP server to 127.0.0.1:<random port> as the redirect
    target, sends the user's browser to the consent page, waits for the
    redirect, exchanges the code. Raises ScatterboxError on denial/timeout.

    fixed_port pins the loopback port: providers that verify the redirect
    URI against exact pre-registered values (Dropbox) can't use a random
    port — the adapter module declares REDIRECT_PORT and the user registers
    that one URI once.

    require_refresh_token=False is for backends whose access tokens never
    expire and that issue no refresh token (pCloud): the blob is then stored
    without an expires_at, and the TokenManager serves it forever.

    token_url_resolver, when given, is called with the redirect's query
    params and returns (token_url, blob_extra): it lets region-sharded
    backends (pCloud's US/EU data centers) pick the token endpoint and record
    the per-account API host discovered only at consent time.
    """
    verifier, challenge = _pkce_pair()
    state = base64.urlsafe_b64encode(os.urandom(16)).rstrip(b"=").decode()

    try:
        server = HTTPServer(("127.0.0.1", fixed_port or 0), _RedirectCatcher)
    except OSError as exc:
        raise ScatterboxError(
            f"cannot listen on the OAuth redirect port {fixed_port}: {exc} — "
            "close whatever is using it and retry"
        )
    _RedirectCatcher.result = {}
    redirect_uri = f"http://127.0.0.1:{server.server_port}/"

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        **(extra_auth_params or {}),
    }
    if scopes:  # pCloud has no scope parameter (access is whole-account)
        params["scope"] = scopes
    url = auth_url + "?" + urllib.parse.urlencode(params)

    # Serve exactly one request (the redirect) on a helper thread while this
    # thread blocks waiting for it.
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    if open_browser:
        webbrowser.open(url)
    else:
        print(f"Open this URL to authorize scatterbox:\n{url}")  # noqa: T201
    thread.join(timeout=timeout_s)
    alive = thread.is_alive()
    server.server_close()
    if alive:
        raise ScatterboxError("authorization timed out — no browser redirect received")

    result = _RedirectCatcher.result
    if result.get("state") != state:
        raise ScatterboxError("authorization failed: state mismatch (possible CSRF)")
    if "code" not in result:
        raise ScatterboxError(
            f"authorization failed: {result.get('error', 'no code returned')}"
        )

    # Region-sharded backends derive the token endpoint (and extra non-secret
    # blob keys, e.g. the per-account API host) from the redirect params.
    blob_extra: dict[str, Any] = {}
    if token_url_resolver is not None:
        token_url, blob_extra = token_url_resolver(result)

    data = {
        "grant_type": "authorization_code",
        "code": result["code"],
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "code_verifier": verifier,
    }
    if client_secret:
        data["client_secret"] = client_secret
    resp = httpx.post(token_url, data=data)
    if resp.status_code != 200:
        raise ScatterboxError(
            f"token exchange failed ({resp.status_code}): {resp.text[:200]}"
        )
    tok = resp.json()
    if tok.get("result"):  # pCloud-style API error: HTTP 200 + nonzero result
        raise ScatterboxError(
            f"token exchange failed (result {tok['result']}): {tok.get('error', '')}"
        )
    if "access_token" not in tok:
        raise ScatterboxError(
            f"token exchange returned no access token: {resp.text[:200]}"
        )
    if require_refresh_token and "refresh_token" not in tok:
        # Without one we'd lose access within the hour; for Google this means
        # consent was granted before without prompt=consent, for MS a missing
        # offline_access scope. Fail now, not at 3 a.m. during a scrub.
        raise ScatterboxError(
            "provider returned no refresh token — remove the app's prior "
            "consent and try again"
        )
    blob: dict[str, Any] = {
        "access_token": tok["access_token"],
        "client_id": client_id,
        "token_url": token_url,
        **blob_extra,
    }
    if "refresh_token" in tok:
        blob["refresh_token"] = tok["refresh_token"]
    # A non-expiring token (pCloud) is stored without expires_at; the
    # TokenManager then serves it forever and never tries to refresh.
    expires_in = tok.get("expires_in")
    if expires_in is not None:
        blob["expires_at"] = time.time() + float(expires_in)
    elif require_refresh_token:
        blob["expires_at"] = time.time() + 3600.0  # refreshable but unstated
    if client_secret:
        blob["client_secret"] = client_secret
    return blob


class TokenManager:
    """Async access-token source for one provider instance.

    Reads the token blob from the SecretStore at construction, refreshes
    on demand, writes every change back so rotated refresh tokens survive.
    A lock serializes refreshes — concurrent chunk uploads must not race
    to redeem the same (possibly single-use) refresh token.
    """

    def __init__(self, secrets: SecretStore, secret_name: str, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._secrets = secrets
        self._name = secret_name
        self._blob: dict[str, Any] = dict(secrets.get_secret(secret_name))
        self._lock = asyncio.Lock()
        self._transport = transport

    async def access_token(self) -> str:
        """A currently-valid bearer token, refreshing if (nearly) expired."""
        # A token stored without an expiry never refreshes (pCloud: tokens
        # don't expire and there is no refresh token to redeem).
        if "expires_at" not in self._blob:
            return self._blob["access_token"]
        if time.time() < self._blob["expires_at"] - _EXPIRY_SKEW_S:
            return self._blob["access_token"]
        return await self.refresh()

    async def refresh(self, *, failed_token: str | None = None) -> str:
        """Refresh the access token. Pass failed_token after a 401 — the
        server may have revoked the token regardless of its local expiry, so
        a forced refresh must not be satisfied by the not-yet-expired check."""
        async with self._lock:
            if "refresh_token" not in self._blob:
                # Non-expiring, non-refreshable token (pCloud) that the server
                # nonetheless rejected — only re-consent can fix it.
                raise ScatterboxError(
                    f"the access token for {self._name} was rejected and it "
                    "has no refresh token (pCloud issues non-expiring tokens) "
                    "— re-run 'scatterbox provider reauth' to re-authorize"
                )
            # Another task may have refreshed while we waited on the lock.
            current = self._blob["access_token"]
            if current != failed_token and time.time() < self._blob[
                "expires_at"
            ] - _EXPIRY_SKEW_S:
                return current
            data = {
                "grant_type": "refresh_token",
                "refresh_token": self._blob["refresh_token"],
                "client_id": self._blob["client_id"],
            }
            if self._blob.get("client_secret"):
                data["client_secret"] = self._blob["client_secret"]
            async with httpx.AsyncClient(transport=self._transport) as client:
                resp = await client.post(self._blob["token_url"], data=data)
            if resp.status_code != 200:
                raise ScatterboxError(
                    f"token refresh failed ({resp.status_code}) for "
                    f"{self._name}: {resp.text[:200]} — re-run "
                    "'scatterbox provider add' to re-authorize"
                )
            tok = resp.json()
            self._blob["access_token"] = tok["access_token"]
            self._blob["expires_at"] = time.time() + float(tok.get("expires_in", 3600))
            if tok.get("refresh_token"):  # rotation (Microsoft does this)
                self._blob["refresh_token"] = tok["refresh_token"]
            self._secrets.set_secret(self._name, self._blob)
            return self._blob["access_token"]
