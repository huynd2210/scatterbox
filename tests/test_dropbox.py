"""Dropbox adapter against a fake Dropbox v2 API.

Covers the API's two endpoint styles (content endpoints driven by the
Dropbox-API-Arg header, JSON RPC endpoints), the 409/error_summary error
shape (not_found vs insufficient_space), and the shared retry/refresh
discipline.
"""

import asyncio
import json
import time

import httpx
import pytest

from scatterbox.errors import ObjectTooLargeError, ProviderFullError
from scatterbox.providers.dropbox import DropboxProvider

from test_oauth import FakeSecrets

TOKEN_URL = "https://api.dropboxapi.com/oauth2/token"


class FakeDropbox:
    def __init__(self):
        self.objects: dict[str, dict] = {}  # id -> {"name", "data"}
        self.counter = 0
        self.refreshes = 0
        self.valid_token = "tok-1"
        self.fail_with: list[httpx.Response] = []
        self.requests: list[httpx.Request] = []
        self.quota = {"used": 1000000, "allocation": {".tag": "individual", "allocated": 2147483648}}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def _store(self, name: str, data: bytes) -> str:
        self.counter += 1
        oid = f"id:obj{self.counter}"
        self.objects[oid] = {"name": name, "data": data}
        return oid

    def _resolve(self, path: str) -> str | None:
        """Dropbox path args accept both 'id:…' refs and '/name' paths."""
        if path.startswith("id:"):
            return path if path in self.objects else None
        name = path.removeprefix("/")
        return next(
            (oid for oid, o in self.objects.items() if o["name"] == name), None
        )

    @staticmethod
    def _not_found() -> httpx.Response:
        return httpx.Response(
            409,
            json={"error_summary": "path/not_found/..", "error": {".tag": "path"}},
        )

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        path = request.url.path

        if url.startswith(TOKEN_URL):
            self.refreshes += 1
            self.valid_token = f"tok-{self.refreshes + 1}"
            return httpx.Response(
                200, json={"access_token": self.valid_token, "expires_in": 3600}
            )

        self.requests.append(request)
        if self.fail_with:
            return self.fail_with.pop(0)
        if request.headers.get("Authorization") != f"Bearer {self.valid_token}":
            return httpx.Response(
                401, json={"error_summary": "expired_access_token/.."}
            )

        if request.url.host == "content.dropboxapi.com":
            arg = json.loads(request.headers["Dropbox-API-Arg"])
            if path == "/2/files/upload":
                assert arg["mode"] == "overwrite"
                name = arg["path"].removeprefix("/")
                oid = self._store(name, request.content)
                return httpx.Response(200, json={"id": oid, "name": name})
            if path == "/2/files/download":
                oid = self._resolve(arg["path"])
                if oid is None:
                    return self._not_found()
                return httpx.Response(200, content=self.objects[oid]["data"])

        if path == "/2/files/get_metadata":
            oid = self._resolve(json.loads(request.content)["path"])
            if oid is None:
                return self._not_found()
            return httpx.Response(
                200, json={"id": oid, "name": self.objects[oid]["name"]}
            )

        if path == "/2/files/delete_v2":
            oid = self._resolve(json.loads(request.content)["path"])
            if oid is None:
                return self._not_found()
            del self.objects[oid]
            return httpx.Response(200, json={"metadata": {"id": oid}})

        if path == "/2/users/get_space_usage":
            return httpx.Response(200, json=self.quota)

        raise AssertionError(f"unexpected request: {request.method} {url}")


@pytest.fixture
def dbx():
    return FakeDropbox()


def make_provider(dbx: FakeDropbox, **kwargs) -> tuple[DropboxProvider, FakeSecrets]:
    secrets = FakeSecrets(
        s={
            "access_token": "tok-1",
            "refresh_token": "ref",
            "expires_at": time.time() + 3600,
            "client_id": "appkey",  # public client: no secret
            "token_url": TOKEN_URL,
        }
    )
    provider = DropboxProvider(
        secrets=secrets,
        secret_name="s",
        transport=dbx.transport(),
        backoff_base_s=0,
        **kwargs,
    )
    return provider, secrets


def test_roundtrip_and_idempotent_delete(dbx):
    provider, _ = make_provider(dbx)
    data = b"opaque ciphertext"
    ref = asyncio.run(provider.put("chunk1", data))
    assert ref.value.startswith("id:")
    assert asyncio.run(provider.get(ref)) == data
    assert asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))
    assert not asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))  # idempotent


def test_overwrite_same_name(dbx):
    provider, _ = make_provider(dbx)
    asyncio.run(provider.put("c", b"v1"))
    ref = asyncio.run(provider.put("c", b"v2"))
    assert asyncio.run(provider.get(ref)) == b"v2"


def test_429_retried_and_401_refreshes(dbx):
    provider, secrets = make_provider(dbx)
    dbx.fail_with = [httpx.Response(429, headers={"Retry-After": "0"})]
    dbx.valid_token = "tok-2"  # also force one refresh
    ref = asyncio.run(provider.put("c", b"x"))
    assert dbx.objects[ref.value]["data"] == b"x"
    assert dbx.refreshes == 1
    assert secrets.data["s"]["access_token"] == "tok-2"


def test_insufficient_space_maps_to_provider_full(dbx):
    provider, _ = make_provider(dbx)
    dbx.fail_with = [
        httpx.Response(
            409,
            json={"error_summary": "path/insufficient_space/.."},
        )
    ]
    with pytest.raises(ProviderFullError):
        asyncio.run(provider.put("c", b"x"))


def test_quota_exact_and_user_cap(dbx):
    provider, _ = make_provider(dbx)
    q = asyncio.run(provider.quota())
    assert (q.total_bytes, q.used_bytes, q.confidence) == (2147483648, 1000000, "exact")
    capped, _ = make_provider(dbx, capacity_bytes=42)
    assert asyncio.run(capped.quota()).total_bytes == 42


def test_find_by_path(dbx):
    provider, _ = make_provider(dbx)
    assert asyncio.run(provider.find("register-snap")) is None
    ref = asyncio.run(provider.put("register-snap", b"snapshot bytes"))
    assert asyncio.run(provider.find("register-snap")).value == ref.value


def test_max_object_bytes_enforced_locally(dbx):
    provider, _ = make_provider(dbx, max_object_bytes=4)
    with pytest.raises(ObjectTooLargeError):
        asyncio.run(provider.put("c", b"x" * 5))
    assert dbx.requests == []
    # the user cap can only tighten the API's own 150 MB ceiling
    assert provider.profile().max_object_bytes == 4
