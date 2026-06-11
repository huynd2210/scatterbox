"""OneDrive adapter against a fake Microsoft Graph (TASKS.md Phase 2 §4).

Covers both upload paths (simple PUT ≤4 MiB, upload session above), the
documented constraints — 320 KiB-aligned fragments, no Authorization header
on session PUTs — and the shared retry/refresh discipline.
"""

import asyncio
import json
import time

import httpx
import pytest

from scatterbox.errors import ObjectTooLargeError, ProviderFullError
from scatterbox.providers.onedrive import _FRAGMENT, OneDriveProvider

from test_oauth import FakeSecrets

TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"


class FakeGraph:
    def __init__(self):
        self.objects: dict[str, dict] = {}  # id -> {"name", "data", "deleted"}
        self.counter = 0
        self.refreshes = 0
        self.valid_token = "tok-1"
        self.fail_with: list[httpx.Response] = []
        self.requests: list[httpx.Request] = []
        self.fragments: list[httpx.Request] = []
        self.session_buf: bytes = b""
        self.session_name: str | None = None
        self.quota = {"total": 5368709120, "used": 1000000}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def _new_id(self) -> str:
        self.counter += 1
        return f"item{self.counter}"

    def _store(self, name: str, data: bytes) -> str:
        oid = self._new_id()
        self.objects[oid] = {"name": name, "data": data, "deleted": False}
        return oid

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        path = request.url.path

        if url.startswith(TOKEN_URL):
            self.refreshes += 1
            self.valid_token = f"tok-{self.refreshes + 1}"
            return httpx.Response(
                200, json={"access_token": self.valid_token, "expires_in": 3600}
            )

        # session-PUT URL: pre-signed, must arrive WITHOUT a bearer header
        if request.url.host == "upload.graph.example":
            assert "Authorization" not in request.headers
            self.fragments.append(request)
            start, rest = request.headers["Content-Range"].removeprefix("bytes ").split("-")
            end, total = rest.split("/")
            assert int(start) == len(self.session_buf)  # in-order, gapless
            self.session_buf += request.content
            assert int(end) == len(self.session_buf) - 1
            if len(self.session_buf) == int(total):  # final fragment
                oid = self._store(self.session_name, self.session_buf)
                return httpx.Response(201, json={"id": oid})
            return httpx.Response(202, json={"nextExpectedRanges": [f"{len(self.session_buf)}-"]})

        # pre-signed download URL (the target of the 302): no bearer header —
        # httpx strips Authorization on cross-host redirects
        if request.url.host == "dl.graph.example":
            oid = path.removeprefix("/")
            return httpx.Response(200, content=self.objects[oid]["data"])

        self.requests.append(request)
        if self.fail_with:
            return self.fail_with.pop(0)
        if request.headers.get("Authorization") != f"Bearer {self.valid_token}":
            return httpx.Response(401, json={"error": "InvalidAuthenticationToken"})

        # approot simple upload / session creation
        if path.startswith("/v1.0/me/drive/special/approot:/"):
            name = path.removeprefix("/v1.0/me/drive/special/approot:/").split(":/")[0]
            if path.endswith(":/content") and request.method == "PUT":
                return httpx.Response(201, json={"id": self._store(name, request.content)})
            if path.endswith(":/createUploadSession"):
                self.session_buf = b""
                self.session_name = name
                return httpx.Response(
                    200, json={"uploadUrl": "https://upload.graph.example/session1"}
                )

        if path == "/v1.0/me/drive":
            return httpx.Response(200, json={"quota": self.quota})

        if path.startswith("/v1.0/me/drive/items/"):
            oid = path.removeprefix("/v1.0/me/drive/items/").split("/")[0]
            obj = self.objects.get(oid)
            if obj is None:
                return httpx.Response(404, json={"error": "itemNotFound"})
            if request.method == "DELETE":
                del self.objects[oid]
                return httpx.Response(204)
            if path.endswith("/content"):
                # Graph answers with a redirect to a pre-signed URL
                return httpx.Response(
                    302,
                    headers={"Location": f"https://dl.graph.example/{oid}"},
                )
            body = {"id": oid}
            if obj["deleted"]:
                body["deleted"] = {"state": "deleted"}
            return httpx.Response(200, json=body)

        raise AssertionError(f"unexpected request: {request.method} {url}")


@pytest.fixture
def graph():
    return FakeGraph()


def make_provider(graph: FakeGraph, **kwargs) -> tuple[OneDriveProvider, FakeSecrets]:
    secrets = FakeSecrets(
        s={
            "access_token": "tok-1",
            "refresh_token": "ref",
            "expires_at": time.time() + 3600,
            "client_id": "cid",  # public client: no secret
            "token_url": TOKEN_URL,
        }
    )
    provider = OneDriveProvider(
        secrets=secrets,
        secret_name="s",
        transport=graph.transport(),
        backoff_base_s=0,
        **kwargs,
    )
    return provider, secrets


def test_small_object_uses_simple_put(graph):
    provider, _ = make_provider(graph)
    data = b"small ciphertext"
    ref = asyncio.run(provider.put("chunk1", data))
    assert graph.fragments == []  # no session involved
    assert asyncio.run(provider.get(ref)) == data
    assert asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))
    assert not asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))  # idempotent


def test_large_object_uses_aligned_upload_session(graph):
    provider, _ = make_provider(graph)
    data = bytes(range(256)) * (9 * 4096)  # 9 MiB > the 4 MiB simple-PUT cap
    ref = asyncio.run(provider.put("bigchunk", data))
    assert len(graph.fragments) == 2  # 7.5 MiB + remainder
    # every fragment except the last is exactly the 320 KiB-aligned size
    sizes = [len(f.content) for f in graph.fragments]
    assert sizes[:-1] == [_FRAGMENT] * (len(sizes) - 1)
    assert _FRAGMENT % (320 * 1024) == 0
    assert asyncio.run(provider.get(ref)) == data


def test_deleted_facet_counts_as_missing(graph):
    provider, _ = make_provider(graph)
    ref = asyncio.run(provider.put("c", b"x"))
    graph.objects[ref.value]["deleted"] = True
    assert not asyncio.run(provider.exists(ref))


def test_429_retried_and_401_refreshes(graph):
    provider, secrets = make_provider(graph)
    graph.fail_with = [httpx.Response(429, headers={"Retry-After": "0"})]
    graph.valid_token = "tok-2"  # also force one refresh
    ref = asyncio.run(provider.put("c", b"x"))
    assert graph.objects[ref.value]["data"] == b"x"
    assert graph.refreshes == 1
    assert secrets.data["s"]["access_token"] == "tok-2"


def test_insufficient_storage_maps_to_provider_full(graph):
    provider, _ = make_provider(graph)
    graph.fail_with = [
        httpx.Response(
            507, json={"error": {"code": "insufficientStorage"}}
        )
    ]
    with pytest.raises(ProviderFullError):
        asyncio.run(provider.put("c", b"x"))


def test_quota_exact_and_user_cap(graph):
    provider, _ = make_provider(graph)
    q = asyncio.run(provider.quota())
    assert (q.total_bytes, q.used_bytes, q.confidence) == (5368709120, 1000000, "exact")
    capped, _ = make_provider(graph, capacity_bytes=42)
    assert asyncio.run(capped.quota()).total_bytes == 42


def test_max_object_bytes_enforced_locally(graph):
    provider, _ = make_provider(graph, max_object_bytes=4)
    with pytest.raises(ObjectTooLargeError):
        asyncio.run(provider.put("c", b"x" * 5))
    assert graph.requests == []
