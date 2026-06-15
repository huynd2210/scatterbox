"""Vercel Blob adapter against a fake Vercel Blob REST API.

The fake speaks the Blob protocol over an httpx.MockTransport: the bearer-
authenticated API host (PUT upload, POST /delete, GET ?url= head, GET ?prefix=
list) and the *separate* public object host the upload URL points at — which is
fetched WITHOUT the bearer. It validates the adapter's orchestration, the
static-bearer auth, and the content round-trip.
"""

import asyncio
import json

import httpx
import pytest

from scatterbox.errors import ObjectTooLargeError, ProviderFullError, ScatterboxError
from scatterbox.providers import vercel_blob
from scatterbox.providers.vercel_blob import VercelBlobProvider

from test_oauth import FakeSecrets

TOKEN = "vercel_rw_token_xyz"
STORE_HOST = "store123.public.blob.vercel-storage.com"


class FakeVercelBlob:
    """A minimal in-memory Vercel Blob store behind an httpx.MockTransport."""

    def __init__(self):
        self.by_url: dict[str, bytes] = {}  # public url -> bytes
        self.url_to_pathname: dict[str, str] = {}  # public url -> pathname
        self.requests: list[httpx.Request] = []
        self.over_quota = False

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def _url_for(self, pathname: str) -> str:
        return f"https://{STORE_HOST}/{pathname}"

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if request.url.host == STORE_HOST:
            # Public object read — served openly, the bearer must NOT be sent.
            assert "Authorization" not in request.headers
            data = self.by_url.get(str(request.url))
            return httpx.Response(200, content=data) if data is not None else httpx.Response(404)

        # API host: every request carries the static bearer + the version header.
        assert request.headers.get("Authorization") == f"Bearer {TOKEN}"
        assert request.headers.get("x-api-version")
        method = request.method
        path = request.url.path
        params = dict(request.url.params)

        if method == "PUT":
            if self.over_quota:
                return httpx.Response(507, json={"error": {"message": "store size exceeded"}})
            pathname = path.lstrip("/")
            url = self._url_for(pathname)
            self.by_url[url] = request.content
            self.url_to_pathname[url] = pathname
            return httpx.Response(
                200,
                json={
                    "url": url,
                    "downloadUrl": url + "?download=1",
                    "pathname": pathname,
                    "contentType": "application/octet-stream",
                },
            )
        if method == "POST" and path == "/delete":
            for u in json.loads(request.content)["urls"]:
                self.url_to_pathname.pop(u, None)
                self.by_url.pop(u, None)
            return httpx.Response(200, json={})
        if method == "GET" and "url" in params:  # head
            u = params["url"]
            if u in self.by_url:
                return httpx.Response(
                    200,
                    json={"url": u, "pathname": self.url_to_pathname[u], "size": len(self.by_url[u])},
                )
            return httpx.Response(404, json={"error": {"code": "not_found"}})
        if method == "GET":  # list
            prefix = params.get("prefix", "")
            blobs = [
                {"url": u, "pathname": pn, "size": len(self.by_url[u])}
                for u, pn in self.url_to_pathname.items()
                if pn.startswith(prefix)
            ]
            return httpx.Response(200, json={"blobs": blobs, "hasMore": False})
        raise AssertionError(f"unexpected request: {method} {request.url}")


@pytest.fixture
def fake():
    return FakeVercelBlob()


def make_provider(fake: FakeVercelBlob, **kwargs) -> VercelBlobProvider:
    secrets = FakeSecrets(s=vercel_blob.credential_blob(TOKEN))
    return VercelBlobProvider(
        secrets=secrets,
        secret_name="s",
        transport=fake.transport(),
        backoff_base_s=0,
        **kwargs,
    )


def test_credential_blob_is_a_static_bearer():
    blob = vercel_blob.credential_blob(TOKEN)
    assert blob == {"access_token": TOKEN}
    # static credential: nothing for the TokenManager to expire or refresh
    assert "expires_at" not in blob and "refresh_token" not in blob


def test_roundtrip_and_idempotent_delete(fake):
    p = make_provider(fake)
    data = b"opaque ciphertext"
    ref = asyncio.run(p.put("chunk1", data))
    # the ref is the object's public URL under the scatterbox/ pathname prefix
    assert ref.value == f"https://{STORE_HOST}/scatterbox/chunk1"
    assert asyncio.run(p.get(ref)) == data
    assert asyncio.run(p.exists(ref))
    asyncio.run(p.delete(ref))
    assert not asyncio.run(p.exists(ref))
    asyncio.run(p.delete(ref))  # idempotent: already-gone is success


def test_objects_land_under_scatterbox_prefix(fake):
    p = make_provider(fake)
    asyncio.run(p.put("chunk1", b"x"))
    assert "scatterbox/chunk1" in fake.url_to_pathname.values()


def test_public_url_is_fetched_without_the_bearer(fake):
    p = make_provider(fake)
    ref = asyncio.run(p.put("chunk1", b"data"))
    assert asyncio.run(p.get(ref)) == b"data"
    # the download hit the public host and carried no Authorization (the fake
    # asserts this too, but make it explicit)
    gets = [r for r in fake.requests if r.url.host == STORE_HOST]
    assert gets and all("Authorization" not in r.headers for r in gets)


def test_over_quota_maps_to_provider_full(fake):
    fake.over_quota = True
    with pytest.raises(ProviderFullError):
        asyncio.run(make_provider(fake).put("c", b"x"))


def test_quota_sums_prefix_and_honors_cap(fake):
    p = make_provider(fake)
    asyncio.run(p.put("a", b"12345"))  # 5 bytes
    asyncio.run(p.put("b", b"678"))  # 3 bytes
    q = asyncio.run(p.quota())
    assert (q.total_bytes, q.used_bytes, q.confidence) == (None, 8, "unknown")
    capped = make_provider(fake, capacity_bytes=1000)
    cq = asyncio.run(capped.quota())
    assert (cq.total_bytes, cq.used_bytes, cq.confidence) == (1000, 8, "estimated")


def test_find_enables_cold_recovery(fake):
    p = make_provider(fake)
    assert asyncio.run(p.find("register-snap")) is None
    ref = asyncio.run(p.put("register-snap", b"snapshot bytes"))
    found = asyncio.run(p.find("register-snap"))
    assert found is not None and found.value == ref.value
    assert asyncio.run(p.get(found)) == b"snapshot bytes"


def test_max_object_bytes_enforced_locally(fake):
    p = make_provider(fake, max_object_bytes=4)
    with pytest.raises(ObjectTooLargeError):
        asyncio.run(p.put("c", b"x" * 5))
    assert fake.requests == []  # rejected before any network call
    assert p.profile().max_object_bytes == 4


def test_rejected_token_surfaces_reauth_error():
    # A static bearer the server rejects (401) cannot be refreshed — the
    # TokenManager turns that into a clear re-authenticate error.
    transport = httpx.MockTransport(lambda req: httpx.Response(401, json={"error": "auth"}))
    secrets = FakeSecrets(s=vercel_blob.credential_blob(TOKEN))
    p = VercelBlobProvider(
        secrets=secrets, secret_name="s", transport=transport, backoff_base_s=0
    )
    with pytest.raises(ScatterboxError, match="no refresh token"):
        asyncio.run(p.quota())
