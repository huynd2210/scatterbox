"""Koofr adapter against a fake Koofr Files API.

Covers what makes Koofr different from the other cloud adapters: HTTP Basic
auth from an app password (not a bearer token, and static — a rejected one is
a re-auth, not a refresh), the mount-scoped paths with the primary mount
discovered and learned, the split metadata (/api/v2) vs content
(/content/api/v2) hosts-by-path, and the path-addressed put/get/find.
"""

import asyncio
import base64
import json

import httpx
import pytest

from scatterbox.errors import ObjectTooLargeError, ProviderFullError, ScatterboxError
from scatterbox.providers.koofr import KoofrProvider, credential_blob

from test_oauth import FakeSecrets

BASE = "https://koofr.test"
EMAIL = "alice@koofr.test"
APP_PW = "app-pw-123"
EXPECTED_AUTH = "Basic " + base64.b64encode(f"{EMAIL}:{APP_PW}".encode()).decode()
MOUNT = "mount-primary"


def _upload_data(request: httpx.Request) -> bytes:
    """Pull the file bytes out of a multipart/form-data upload body."""
    ctype = request.headers["content-type"]
    boundary = ctype.split("boundary=", 1)[1].encode()
    for chunk in request.content.split(b"--" + boundary):
        head, _, data = chunk.partition(b"\r\n\r\n")
        if b"filename=" not in head:
            continue
        if data.endswith(b"\r\n"):  # CRLF the encoder appends before the boundary
            data = data[:-2]
        return data
    raise AssertionError("no file part in upload body")


class FakeKoofr:
    def __init__(self):
        self.objects: dict[str, bytes] = {}  # path -> bytes
        self.folders: set[str] = set()
        self.over_quota = False
        self.requests: list[httpx.Request] = []
        self.space = {"spaceTotal": 10 * 1024**3, "spaceUsed": 1024**3}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        # Every Koofr request authenticates with the app password as Basic.
        assert request.headers.get("Authorization") == EXPECTED_AUTH
        path = request.url.path
        params = dict(request.url.params)
        method = request.method

        if path == "/api/v2/mounts" and method == "GET":
            return httpx.Response(
                200, json={"mounts": [{"id": MOUNT, "isPrimary": True, **self.space}]}
            )

        if path == f"/api/v2/mounts/{MOUNT}" and method == "GET":
            return httpx.Response(200, json={"id": MOUNT, "isPrimary": True, **self.space})

        if path == f"/api/v2/mounts/{MOUNT}/files/folder" and method == "POST":
            name = json.loads(request.content)["name"]
            folder = params["path"].rstrip("/") + "/" + name
            if folder in self.folders:
                return httpx.Response(409, json={"error": "already exists"})
            self.folders.add(folder)
            return httpx.Response(200, json={"name": name, "type": "dir"})

        if path == f"/content/api/v2/mounts/{MOUNT}/files/put" and method == "POST":
            if self.over_quota:
                return httpx.Response(507, json={"error": "not enough space"})
            dest = params["path"].rstrip("/") + "/" + params["filename"]
            self.objects[dest] = _upload_data(request)
            return httpx.Response(
                200, json={"name": params["filename"], "size": len(self.objects[dest])}
            )

        if path == f"/content/api/v2/mounts/{MOUNT}/files/get" and method == "GET":
            data = self.objects.get(params["path"])
            return httpx.Response(200, content=data) if data is not None else httpx.Response(404)

        if path == f"/api/v2/mounts/{MOUNT}/files/info" and method == "GET":
            if params["path"] in self.objects:
                return httpx.Response(
                    200, json={"name": params["path"].rsplit("/", 1)[-1]}
                )
            return httpx.Response(404, json={"error": "not found"})

        if path == f"/api/v2/mounts/{MOUNT}/files/remove" and method == "DELETE":
            if params["path"] in self.objects:
                del self.objects[params["path"]]
                return httpx.Response(200)
            return httpx.Response(404, json={"error": "not found"})

        raise AssertionError(f"unexpected request: {method} {request.url}")


@pytest.fixture
def fk():
    return FakeKoofr()


def make_provider(fk: FakeKoofr, **kwargs) -> tuple[KoofrProvider, FakeSecrets]:
    # The app password is stored as the pre-computed Basic credential under
    # access_token (no expiry, no refresh) — exactly what credential_blob builds.
    secrets = FakeSecrets(s=credential_blob(EMAIL, APP_PW))
    provider = KoofrProvider(
        secrets=secrets,
        secret_name="s",
        base_url=BASE,
        transport=fk.transport(),
        backoff_base_s=0,
        **kwargs,
    )
    return provider, secrets


def test_credential_blob_is_basic_and_static():
    blob = credential_blob(EMAIL, APP_PW)
    assert base64.b64decode(blob["access_token"]).decode() == f"{EMAIL}:{APP_PW}"
    # static credential: nothing for the TokenManager to expire or refresh
    assert "expires_at" not in blob and "refresh_token" not in blob


def test_roundtrip_and_idempotent_delete(fk):
    provider, _ = make_provider(fk)
    data = b"opaque ciphertext"
    ref = asyncio.run(provider.put("chunk1", data))
    assert ref.value == "/scatterbox/chunk1"  # ref is the object's stable path
    assert asyncio.run(provider.get(ref)) == data
    assert asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))
    assert not asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))  # idempotent: already-gone is success


def test_objects_land_in_the_scatterbox_folder(fk):
    provider, _ = make_provider(fk)
    asyncio.run(provider.put("chunk1", b"x"))
    assert "/scatterbox" in fk.folders  # created find-or-create on first put
    assert "/scatterbox/chunk1" in fk.objects


def test_over_quota_maps_to_provider_full(fk):
    provider, _ = make_provider(fk)
    fk.over_quota = True
    with pytest.raises(ProviderFullError):
        asyncio.run(provider.put("c", b"x"))


def test_quota_exact_and_user_cap(fk):
    provider, _ = make_provider(fk)
    q = asyncio.run(provider.quota())
    assert (q.total_bytes, q.used_bytes, q.confidence) == (
        10 * 1024**3,
        1024**3,
        "exact",
    )
    capped, _ = make_provider(fk, capacity_bytes=42)
    assert asyncio.run(capped.quota()).total_bytes == 42


def test_find_by_path(fk):
    provider, _ = make_provider(fk)
    assert asyncio.run(provider.find("register-snap")) is None
    ref = asyncio.run(provider.put("register-snap", b"snapshot bytes"))
    assert asyncio.run(provider.find("register-snap")).value == ref.value


def test_max_object_bytes_enforced_locally(fk):
    provider, _ = make_provider(fk, max_object_bytes=4)
    with pytest.raises(ObjectTooLargeError):
        asyncio.run(provider.put("c", b"x" * 5))
    assert fk.requests == []  # rejected before any network call
    assert provider.profile().max_object_bytes == 4


def test_mount_id_is_learned_for_persistence(fk):
    provider, _ = make_provider(fk)
    assert provider.learned_config() == {}  # nothing discovered yet
    asyncio.run(provider.prepare())
    assert provider.learned_config() == {"mount_id": MOUNT}


def test_configured_mount_id_skips_discovery(fk):
    provider, _ = make_provider(fk, mount_id=MOUNT)
    asyncio.run(provider.put("c", b"x"))
    # a known mount id means no /api/v2/mounts discovery call is ever made
    assert all(r.url.path != "/api/v2/mounts" for r in fk.requests)


def test_rejected_app_password_surfaces_reauth_error():
    # A static credential the server rejects (401) cannot be refreshed — the
    # TokenManager turns that into a clear re-authenticate error.
    transport = httpx.MockTransport(lambda req: httpx.Response(401, json={"error": "auth"}))
    secrets = FakeSecrets(s=credential_blob(EMAIL, APP_PW))
    provider = KoofrProvider(
        secrets=secrets,
        secret_name="s",
        base_url=BASE,
        mount_id=MOUNT,
        transport=transport,
        backoff_base_s=0,
    )
    with pytest.raises(ScatterboxError, match="no refresh token"):
        asyncio.run(provider.quota())
