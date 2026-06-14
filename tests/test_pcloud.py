"""pCloud adapter against a fake pCloud API.

Covers what makes pCloud different from the other cloud adapters: the
HTTP-200 + `result`-code error model (not_found vs over_quota), the
multipart upload / getfilelink-then-download split, the region api_base read
from the token blob, and the non-expiring (refresh-token-less) token served
straight through the TokenManager.
"""

import asyncio

import httpx
import pytest

from scatterbox.errors import ObjectTooLargeError, ProviderFullError
from scatterbox.providers.pcloud import PCloudProvider

from test_oauth import FakeSecrets

API = "https://api.pcloud.test"  # stands in for the region host (api_base)
CONTENT_HOST = "content.pcloud.test"  # getfilelink download host


def _upload_part(request: httpx.Request) -> tuple[str, bytes]:
    """Pull (filename, data) out of a multipart/form-data upload body."""
    ctype = request.headers["content-type"]
    boundary = ctype.split("boundary=", 1)[1].encode()
    for chunk in request.content.split(b"--" + boundary):
        head, _, data = chunk.partition(b"\r\n\r\n")
        if b"filename=" not in head:
            continue
        fn = head.split(b'filename="', 1)[1].split(b'"', 1)[0].decode()
        if data.endswith(b"\r\n"):  # CRLF the encoder appends before the boundary
            data = data[:-2]
        return fn, data
    raise AssertionError("no file part in upload body")


class FakePCloud:
    def __init__(self):
        self.objects: dict[str, dict] = {}  # fileid -> {"name", "data"}
        self.folders: dict[str, int] = {}
        self.counter = 0
        self.folder_counter = 0
        self.over_quota = False
        self.requests: list[httpx.Request] = []
        self.quota = {"quota": 10 * 1024**3, "usedquota": 1024**3}

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def _by_name(self, name: str) -> str | None:
        return next((fid for fid, o in self.objects.items() if o["name"] == name), None)

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        path = request.url.path
        params = dict(request.url.params)

        # The pre-signed download host returns raw bytes, no result envelope.
        if host == CONTENT_HOST:
            fid = path.rsplit("/", 1)[-1]
            obj = self.objects.get(fid)
            return (
                httpx.Response(200, content=obj["data"]) if obj else httpx.Response(404)
            )

        self.requests.append(request)
        # Every API call is Bearer-authenticated (pCloud's non-expiring token).
        assert request.headers.get("Authorization") == "Bearer tok-static"

        if path == "/createfolderifnotexists":
            fid = self.folders.setdefault(params["path"], len(self.folders) + 1)
            return httpx.Response(
                200, json={"result": 0, "metadata": {"folderid": fid}}
            )

        if path == "/uploadfile":
            if self.over_quota:
                return httpx.Response(200, json={"result": 2008, "error": "over quota"})
            name, data = _upload_part(request)
            self.counter += 1
            fid = str(self.counter)
            self.objects[fid] = {"name": name, "data": data}
            return httpx.Response(
                200,
                json={"result": 0, "metadata": [{"fileid": int(fid), "name": name}]},
            )

        if path == "/getfilelink":
            if params["fileid"] not in self.objects:
                return httpx.Response(200, json={"result": 2009, "error": "not found"})
            return httpx.Response(
                200,
                json={
                    "result": 0,
                    "hosts": [CONTENT_HOST],
                    "path": f"/d/{params['fileid']}",
                },
            )

        if path == "/deletefile":
            fid = params["fileid"]
            if fid not in self.objects:
                return httpx.Response(200, json={"result": 2009, "error": "not found"})
            del self.objects[fid]
            return httpx.Response(
                200, json={"result": 0, "metadata": {"isdeleted": True}}
            )

        if path == "/stat":
            fid = params.get("fileid") or self._by_name(
                params["path"].rsplit("/", 1)[-1]
            )
            if fid is None or fid not in self.objects:
                return httpx.Response(200, json={"result": 2009, "error": "not found"})
            return httpx.Response(
                200, json={"result": 0, "metadata": {"fileid": int(fid)}}
            )

        if path == "/userinfo":
            return httpx.Response(200, json={"result": 0, **self.quota})

        raise AssertionError(f"unexpected request: {request.method} {request.url}")


@pytest.fixture
def pc():
    return FakePCloud()


def make_provider(pc: FakePCloud, **kwargs) -> tuple[PCloudProvider, FakeSecrets]:
    secrets = FakeSecrets(
        s={
            # No expires_at and no refresh_token: a static pCloud token, served
            # straight through. api_base is the region host learned at consent.
            "access_token": "tok-static",
            "client_id": "appid",
            "client_secret": "shh",
            "token_url": f"{API}/oauth2_token",
            "api_base": API,
        }
    )
    provider = PCloudProvider(
        secrets=secrets,
        secret_name="s",
        transport=pc.transport(),
        backoff_base_s=0,
        **kwargs,
    )
    return provider, secrets


def test_roundtrip_and_idempotent_delete(pc):
    provider, _ = make_provider(pc)
    data = b"opaque ciphertext"
    ref = asyncio.run(provider.put("chunk1", data))
    assert asyncio.run(provider.get(ref)) == data
    assert asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))
    assert not asyncio.run(provider.exists(ref))
    asyncio.run(provider.delete(ref))  # idempotent: already-gone is success


def test_requests_target_the_region_api_base(pc):
    provider, _ = make_provider(pc)
    asyncio.run(provider.put("c", b"x"))
    assert pc.requests  # and every recorded API request hit the api_base host
    assert all(r.url.host == "api.pcloud.test" for r in pc.requests)


def test_over_quota_maps_to_provider_full(pc):
    provider, _ = make_provider(pc)
    pc.over_quota = True
    with pytest.raises(ProviderFullError):
        asyncio.run(provider.put("c", b"x"))


def test_quota_exact_and_user_cap(pc):
    provider, _ = make_provider(pc)
    q = asyncio.run(provider.quota())
    assert (q.total_bytes, q.used_bytes, q.confidence) == (
        10 * 1024**3,
        1024**3,
        "exact",
    )
    capped, _ = make_provider(pc, capacity_bytes=42)
    assert asyncio.run(capped.quota()).total_bytes == 42


def test_find_by_path(pc):
    provider, _ = make_provider(pc)
    assert asyncio.run(provider.find("register-snap")) is None
    ref = asyncio.run(provider.put("register-snap", b"snapshot bytes"))
    assert asyncio.run(provider.find("register-snap")).value == ref.value


def test_max_object_bytes_enforced_locally(pc):
    provider, _ = make_provider(pc, max_object_bytes=4)
    with pytest.raises(ObjectTooLargeError):
        asyncio.run(provider.put("c", b"x" * 5))
    assert pc.requests == []  # rejected before any network call
    # the user cap only tightens the single-request upload ceiling
    assert provider.profile().max_object_bytes == 4


def test_folder_id_is_learned_for_persistence(pc):
    provider, _ = make_provider(pc)
    assert provider.learned_config() == {}  # nothing discovered yet
    asyncio.run(provider.prepare())
    assert provider.learned_config() == {"folder_id": 1}
