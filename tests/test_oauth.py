"""OAuth foundation: PKCE, TokenManager refresh discipline, loopback flow
(TASKS.md Phase 2 §2). Everything offline — token endpoints are mock
transports, the "browser" is a test thread."""

import asyncio
import base64
import hashlib
import time
import urllib.parse

import httpx
import pytest

from scatterbox import oauth
from scatterbox.errors import ScatterboxError

TOKEN_URL = "https://token.example/oauth2/token"


class FakeSecrets:
    """Dict-backed SecretStore for tests."""

    def __init__(self, **secrets):
        self.data = dict(secrets)
        self.writes = 0

    def get_secret(self, name):
        return self.data[name]

    def set_secret(self, name, value):
        self.data[name] = value
        self.writes += 1


def blob(*, expires_in=3600, **extra):
    return {
        "access_token": "tok-original",
        "refresh_token": "ref-original",
        "expires_at": time.time() + expires_in,
        "client_id": "cid",
        "token_url": TOKEN_URL,
        **extra,
    }


def token_endpoint(responses: list[dict]):
    """MockTransport playing the token endpoint; records request bodies."""
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == TOKEN_URL
        calls.append(dict(urllib.parse.parse_qsl(request.content.decode())))
        return httpx.Response(200, json=responses[len(calls) - 1])

    return httpx.MockTransport(handler), calls


def test_pkce_challenge_is_s256_of_verifier():
    verifier, challenge = oauth._pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert challenge == expected
    assert len(verifier) >= 43  # RFC 7636 minimum


def test_valid_token_is_served_without_refresh():
    transport, calls = token_endpoint([])
    secrets = FakeSecrets(s=blob())
    tm = oauth.TokenManager(secrets, "s", transport=transport)
    assert asyncio.run(tm.access_token()) == "tok-original"
    assert calls == [] and secrets.writes == 0


def test_expired_token_triggers_one_refresh_and_persists():
    transport, calls = token_endpoint(
        [{"access_token": "tok-new", "expires_in": 3600}]
    )
    secrets = FakeSecrets(s=blob(expires_in=10))  # inside the 60 s skew
    tm = oauth.TokenManager(secrets, "s", transport=transport)
    assert asyncio.run(tm.access_token()) == "tok-new"
    assert len(calls) == 1
    assert calls[0]["grant_type"] == "refresh_token"
    assert calls[0]["refresh_token"] == "ref-original"
    assert secrets.data["s"]["access_token"] == "tok-new"
    # no rotation in the response -> the old refresh token is kept
    assert secrets.data["s"]["refresh_token"] == "ref-original"


def test_rotated_refresh_token_is_persisted():
    transport, calls = token_endpoint(
        [{"access_token": "tok-new", "refresh_token": "ref-rotated", "expires_in": 3600}]
    )
    secrets = FakeSecrets(s=blob(expires_in=0))
    tm = oauth.TokenManager(secrets, "s", transport=transport)
    asyncio.run(tm.access_token())
    assert secrets.data["s"]["refresh_token"] == "ref-rotated"


def test_failed_token_forces_refresh_despite_local_expiry():
    transport, calls = token_endpoint(
        [{"access_token": "tok-new", "expires_in": 3600}]
    )
    secrets = FakeSecrets(s=blob())  # locally still valid
    tm = oauth.TokenManager(secrets, "s", transport=transport)
    # a 401 happened: the server rejected tok-original
    assert asyncio.run(tm.refresh(failed_token="tok-original")) == "tok-new"
    assert len(calls) == 1
    # ...but a refresh forced with a token that is no longer current is a
    # no-op (another task already refreshed)
    assert asyncio.run(tm.refresh(failed_token="tok-original")) == "tok-new"
    assert len(calls) == 1


def test_client_secret_included_when_present():
    transport, calls = token_endpoint(
        [{"access_token": "tok-new", "expires_in": 3600}]
    )
    secrets = FakeSecrets(s=blob(expires_in=0, client_secret="shh"))
    tm = oauth.TokenManager(secrets, "s", transport=transport)
    asyncio.run(tm.access_token())
    assert calls[0]["client_secret"] == "shh"


def test_refresh_failure_raises_with_guidance():
    def handler(request):
        return httpx.Response(400, json={"error": "invalid_grant"})

    secrets = FakeSecrets(s=blob(expires_in=0))
    tm = oauth.TokenManager(secrets, "s", transport=httpx.MockTransport(handler))
    with pytest.raises(ScatterboxError, match="re-run 'scatterbox provider add'"):
        asyncio.run(tm.access_token())


# -- loopback flow -------------------------------------------------------------


def _fake_browser_and_exchange(monkeypatch, *, redirect_params=None, token_json=None):
    """Patch webbrowser.open to act as the user's browser (immediately follow
    the redirect back) and httpx.post to act as the token endpoint."""
    seen = {}

    def fake_open(url):
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        seen["auth_params"] = params
        redirect = params["redirect_uri"]
        qs = redirect_params if redirect_params is not None else {
            "code": "authcode", "state": params["state"]
        }
        httpx.get(redirect + "?" + urllib.parse.urlencode(qs))
        return True

    def fake_post(url, data=None):
        seen["token_request"] = {"url": url, "data": data}
        return httpx.Response(
            200,
            json=token_json
            if token_json is not None
            else {"access_token": "at", "refresh_token": "rt", "expires_in": 3600},
            request=httpx.Request("POST", url),
        )

    monkeypatch.setattr(oauth.webbrowser, "open", fake_open)
    monkeypatch.setattr(oauth.httpx, "post", fake_post)
    return seen


def test_loopback_flow_happy_path(monkeypatch):
    seen = _fake_browser_and_exchange(monkeypatch)
    tok = oauth.run_loopback_flow(
        auth_url="https://auth.example/authorize",
        token_url=TOKEN_URL,
        client_id="cid",
        scopes="scope.a scope.b",
        timeout_s=10,
    )
    assert tok["access_token"] == "at" and tok["refresh_token"] == "rt"
    assert tok["client_id"] == "cid" and tok["token_url"] == TOKEN_URL
    assert tok["expires_at"] > time.time()
    auth = seen["auth_params"]
    assert auth["code_challenge_method"] == "S256"
    assert auth["scope"] == "scope.a scope.b"
    exchange = seen["token_request"]["data"]
    assert exchange["code"] == "authcode"
    assert exchange["code_verifier"]  # PKCE verifier sent on exchange


def test_loopback_flow_rejects_state_mismatch(monkeypatch):
    _fake_browser_and_exchange(
        monkeypatch, redirect_params={"code": "authcode", "state": "forged"}
    )
    with pytest.raises(ScatterboxError, match="state mismatch"):
        oauth.run_loopback_flow(
            auth_url="https://auth.example/authorize",
            token_url=TOKEN_URL,
            client_id="cid",
            scopes="s",
            timeout_s=10,
        )


def test_loopback_flow_surfaces_denial(monkeypatch):
    def fake_open(url):
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))
        httpx.get(
            params["redirect_uri"]
            + "?"
            + urllib.parse.urlencode(
                {"error": "access_denied", "state": params["state"]}
            )
        )
        return True

    monkeypatch.setattr(oauth.webbrowser, "open", fake_open)
    with pytest.raises(ScatterboxError, match="access_denied"):
        oauth.run_loopback_flow(
            auth_url="https://auth.example/authorize",
            token_url=TOKEN_URL,
            client_id="cid",
            scopes="s",
            timeout_s=10,
        )


def test_loopback_flow_requires_refresh_token(monkeypatch):
    _fake_browser_and_exchange(
        monkeypatch, token_json={"access_token": "at", "expires_in": 3600}
    )
    with pytest.raises(ScatterboxError, match="no refresh token"):
        oauth.run_loopback_flow(
            auth_url="https://auth.example/authorize",
            token_url=TOKEN_URL,
            client_id="cid",
            scopes="s",
            timeout_s=10,
        )
