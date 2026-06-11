"""Google Drive adapter against a fake Drive API (TASKS.md Phase 2 §3).

A MockTransport plays the Drive v3 surface the adapter uses: folder
search/create, resumable upload, download, metadata probe, delete, about —
plus the token endpoint, so the 401-refresh path is exercised end to end.
"""

import asyncio
import json
import time
import urllib.parse

import httpx
import pytest

from scatterbox.errors import ObjectTooLargeError, ProviderFullError, ScatterboxError
from scatterbox.providers.gdrive import GDriveProvider

from test_oauth import FakeSecrets

TOKEN_URL = "https://oauth2.googleapis.com/token"


class FakeDrive:
    def __init__(self):
        self.objects: dict[str, dict] = {}  # id -> {"name", "data", "trashed"}
        self.folder_id: str | None = None
        self.counter = 0
        self.refreshes = 0
        self.valid_token = "tok-1"
        self.fail_with: list[httpx.Response] = []  # popped before real handling
        self.requests: list[httpx.Request] = []
        self.quota = {"limit": "16106127360", "usage": "5000000000"}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def _new_id(self) -> str:
        self.counter += 1
        return f"id{self.counter}"

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
            return httpx.Response(401, json={"error": "invalid_credentials"})

        # resumable upload: session open, then PUT to the session URL
        if path == "/upload/drive/v3/files" and request.method == "POST":
            meta = json.loads(request.content)
            oid = self._new_id()
            self.objects[oid] = {"name": meta["name"], "data": b"", "trashed": False}
            assert meta["parents"] == [self.folder_id]
            return httpx.Response(
                200, headers={"Location": f"https://upload.example/session/{oid}"}
            )
        if request.url.host == "upload.example" and request.method == "PUT":
            oid = path.rsplit("/", 1)[1]
            self.objects[oid]["data"] = request.content
            return httpx.Response(200, json={"id": oid})

        # folder search / create
        if path == "/drive/v3/files" and request.method == "GET":
            q = dict(urllib.parse.parse_qsl(request.url.query.decode()))["q"]
            assert "scatterbox" in q
            files = [{"id": self.folder_id}] if self.folder_id else []
            return httpx.Response(200, json={"files": files})
        if path == "/drive/v3/files" and request.method == "POST":
            self.folder_id = self._new_id()
            return httpx.Response(200, json={"id": self.folder_id})

        if path == "/drive/v3/about":
            return httpx.Response(200, json={"storageQuota": self.quota})

        # per-object operations
        if path.startswith("/drive/v3/files/"):
            oid = path.rsplit("/", 1)[1]
            obj = self.objects.get(oid)
            if obj is None or (request.method != "GET" and obj.get("purged")):
                return httpx.Response(404, json={"error": "notFound"})
            if request.method == "DELETE":
                del self.objects[oid]
                return httpx.Response(204)
            params = dict(urllib.parse.parse_qsl(request.url.query.decode()))
            if params.get("alt") == "media":
                if obj["trashed"]:
                    return httpx.Response(404, json={"error": "notFound"})
                return httpx.Response(200, content=obj["data"])
            return httpx.Response(200, json={"id": oid, "trashed": obj["trashed"]})

        raise AssertionError(f"unexpected request: {request.method} {url}")


@pytest.fixture
def drive():
    return FakeDrive()


def make_provider(drive: FakeDrive, **kwargs) -> tuple[GDriveProvider, FakeSecrets]:
    secrets = FakeSecrets(
        s={
            "access_token": "tok-1",
            "refresh_token": "ref",
            "expires_at": time.time() + 3600,
            "client_id": "cid",
            "client_secret": "shh",
            "token_url": TOKEN_URL,
        }
    )
    provider = GDriveProvider(
        secrets=secrets,
        secret_name="s",
        transport=drive.transport(),
        backoff_base_s=0,
        **kwargs,
    )
    return provider, secrets


def test_put_get_exists_delete_roundtrip(drive):
    provider, _ = make_provider(drive)
    data = b"ciphertext bytes" * 1000
    ref = asyncio.run(provider.put("chunkhash1", data))
    assert asyncio.run(provider.get(ref)) == data
    assert asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))
    assert not asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))  # idempotent

    stored = [o for o in drive.objects.values()]
    assert stored == []  # deleted
    assert drive.folder_id is not None  # folder was created


def test_folder_created_once_and_reused(drive):
    provider, _ = make_provider(drive)
    asyncio.run(provider.put("c1", b"a"))
    asyncio.run(provider.put("c2", b"b"))
    folder_posts = [
        r for r in drive.requests
        if r.url.path == "/drive/v3/files" and r.method == "POST"
    ]
    assert len(folder_posts) == 1
    # a provider constructed with the persisted folder_id skips even the search
    provider2, _ = make_provider(drive, folder_id=drive.folder_id)
    drive.requests.clear()
    asyncio.run(provider2.put("c3", b"c"))
    assert not any(r.url.path == "/drive/v3/files" for r in drive.requests)


def test_existing_folder_is_found_not_duplicated(drive):
    provider, _ = make_provider(drive)
    drive.folder_id = "preexisting"
    asyncio.run(provider.put("c1", b"a"))
    assert drive.folder_id == "preexisting"


def test_trashed_object_counts_as_missing(drive):
    provider, _ = make_provider(drive)
    ref = asyncio.run(provider.put("c1", b"data"))
    drive.objects[ref.value]["trashed"] = True
    assert not asyncio.run(provider.exists(ref))


def test_429_is_retried(drive):
    provider, _ = make_provider(drive)
    drive.fail_with = [httpx.Response(429, headers={"Retry-After": "0"})] * 2
    ref = asyncio.run(provider.put("c1", b"data"))
    assert asyncio.run(provider.get(ref)) == b"data"


def test_rate_limit_403_is_retried(drive):
    provider, _ = make_provider(drive)
    drive.fail_with = [
        httpx.Response(
            403, json={"error": {"errors": [{"reason": "userRateLimitExceeded"}]}}
        )
    ]
    ref = asyncio.run(provider.put("c1", b"data"))
    assert drive.objects[ref.value]["data"] == b"data"


def test_permission_403_is_not_retried(drive):
    provider, _ = make_provider(drive)
    drive.fail_with = [httpx.Response(403, json={"error": "insufficientPermissions"})]
    with pytest.raises(ScatterboxError, match="403"):
        asyncio.run(provider.put("c1", b"data"))
    assert len(drive.requests) == 1  # no retry


def test_401_refreshes_token_and_retries(drive):
    provider, secrets = make_provider(drive)
    drive.valid_token = "tok-2"  # server-side revocation: tok-1 now invalid
    ref = asyncio.run(provider.put("c1", b"data"))
    assert drive.objects[ref.value]["data"] == b"data"
    assert drive.refreshes == 1
    assert secrets.data["s"]["access_token"] == "tok-2"  # persisted


def test_quota_exceeded_maps_to_provider_full(drive):
    provider, _ = make_provider(drive)
    drive.fail_with = [
        httpx.Response(
            403,
            json={"error": {"errors": [{"reason": "storageQuotaExceeded"}]}},
        )
    ]
    with pytest.raises(ProviderFullError):
        asyncio.run(provider.put("c1", b"data"))


def test_quota_exact_and_user_cap(drive):
    provider, _ = make_provider(drive)
    q = asyncio.run(provider.quota())
    assert (q.total_bytes, q.used_bytes, q.confidence) == (
        16106127360,
        5000000000,
        "exact",
    )
    capped, _ = make_provider(drive, capacity_bytes=1_000_000_000)
    q = asyncio.run(capped.quota())
    assert q.total_bytes == 1_000_000_000  # user cap is tighter than the plan

    drive.quota = {"usage": "123"}  # unlimited plan: no limit field
    q = asyncio.run(make_provider(drive)[0].quota())
    assert q.total_bytes is None and q.confidence == "unknown"


def test_max_object_bytes_enforced_locally(drive):
    provider, _ = make_provider(drive, max_object_bytes=10)
    with pytest.raises(ObjectTooLargeError):
        asyncio.run(provider.put("c1", b"x" * 11))
    assert drive.requests == []  # rejected before any network traffic
    assert provider.profile().max_object_bytes == 10
