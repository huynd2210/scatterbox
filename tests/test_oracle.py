"""Oracle Cloud Object Storage adapter against a fake S3 endpoint.

Oracle's S3 Compatibility API speaks the S3 REST dialect with AWS SigV4 auth,
so the fake is a path-style S3 bucket over httpx.MockTransport: object
PUT/GET/HEAD/DELETE plus a ListObjectsV2 for quota. It validates the adapter's
orchestration and content round-trip; the SigV4 signing itself is pinned
independently against AWS's published test vector
(test_sigv4_matches_aws_known_answer).
"""

import asyncio
import hashlib

import httpx
import pytest

from scatterbox.errors import ObjectTooLargeError, ProviderFullError, ScatterboxError
from scatterbox.providers import oracle
from scatterbox.providers._s3 import sign_v4
from scatterbox.providers.oracle import OracleProvider

from test_oauth import FakeSecrets

NAMESPACE = "myns"
REGION = "us-ashburn-1"
BUCKET = "mybucket"
AKID = "AKID"
SECRET = "SECRETKEY"


class FakeS3:
    """A minimal in-memory path-style S3 bucket behind an httpx.MockTransport."""

    def __init__(self, bucket: str = BUCKET):
        self.bucket = bucket
        self.objects: dict[str, bytes] = {}  # key -> bytes
        self.requests: list[httpx.Request] = []
        self.over_quota = False

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.headers["Authorization"].startswith(
            f"AWS4-HMAC-SHA256 Credential={AKID}/"
        )
        assert request.headers["x-amz-content-sha256"]
        method = request.method
        path = request.url.path
        params = dict(request.url.params)

        if method == "GET" and params.get("list-type") == "2":
            want = params.get("prefix", "")
            keys = sorted(k for k in self.objects if k.startswith(want))
            items = "".join(
                f"<Contents><Key>{k}</Key><Size>{len(self.objects[k])}</Size></Contents>"
                for k in keys
            )
            xml = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
                f"<IsTruncated>false</IsTruncated>{items}</ListBucketResult>"
            )
            return httpx.Response(200, content=xml.encode())

        prefix = f"/{self.bucket}/"
        if not path.startswith(prefix):
            return httpx.Response(404)
        key = path[len(prefix):]
        if method == "PUT":
            if self.over_quota:
                return httpx.Response(507, text="<Error><Code>QuotaExceeded</Code></Error>")
            self.objects[key] = request.content
            return httpx.Response(200, headers={"ETag": '"etag"'})
        if method == "GET":
            data = self.objects.get(key)
            return httpx.Response(200, content=data) if data is not None else httpx.Response(404)
        if method == "HEAD":
            return httpx.Response(200) if key in self.objects else httpx.Response(404)
        if method == "DELETE":
            if key in self.objects:
                del self.objects[key]
                return httpx.Response(204)
            return httpx.Response(404)
        raise AssertionError(f"unexpected request: {method} {request.url}")


@pytest.fixture
def fake():
    return FakeS3()


def make_provider(fake: FakeS3, **kwargs) -> OracleProvider:
    secrets = FakeSecrets(s=oracle.credential_blob(AKID, SECRET))
    return OracleProvider(
        secrets=secrets,
        secret_name="s",
        namespace=NAMESPACE,
        region=REGION,
        bucket=fake.bucket,
        transport=fake.transport(),
        backoff_base_s=0,
        **kwargs,
    )


def test_sigv4_matches_aws_known_answer():
    # AWS SigV4 test-suite "get-vanilla": fixed credentials/date/region/service
    # must yield this exact signature. Pins our signing to the spec.
    auth = sign_v4(
        method="GET",
        canonical_uri="/",
        canonical_query="",
        headers={"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"},
        payload_hash=hashlib.sha256(b"").hexdigest(),
        access_key_id="AKIDEXAMPLE",
        secret_access_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        region="us-east-1",
        service="service",
        amz_date="20150830T123600Z",
    )
    assert auth == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    )


def test_endpoint_is_namespace_and_region_scoped():
    assert (
        oracle.endpoint_for(NAMESPACE, REGION)
        == "https://myns.compat.objectstorage.us-ashburn-1.oraclecloud.com"
    )


def test_roundtrip_and_idempotent_delete(fake):
    p = make_provider(fake)
    data = b"opaque ciphertext"
    ref = asyncio.run(p.put("chunk1", data))
    assert ref.value == "scatterbox/chunk1"  # ref is the stable object key
    assert asyncio.run(p.get(ref)) == data
    assert asyncio.run(p.exists(ref))
    asyncio.run(p.delete(ref))
    assert not asyncio.run(p.exists(ref))
    asyncio.run(p.delete(ref))  # idempotent: already-gone is success


def test_objects_land_under_scatterbox_prefix(fake):
    p = make_provider(fake)
    asyncio.run(p.put("chunk1", b"x"))
    assert "scatterbox/chunk1" in fake.objects


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


def test_rejected_keys_surface_reauth_error():
    transport = httpx.MockTransport(
        lambda req: httpx.Response(403, text="<Error><Code>SignatureDoesNotMatch</Code></Error>")
    )
    secrets = FakeSecrets(s=oracle.credential_blob(AKID, SECRET))
    p = OracleProvider(
        secrets=secrets,
        secret_name="s",
        namespace=NAMESPACE,
        region=REGION,
        bucket=BUCKET,
        transport=transport,
        backoff_base_s=0,
    )
    with pytest.raises(ScatterboxError, match="reauth"):
        asyncio.run(p.quota())


def test_missing_credential_blob_is_a_clear_error():
    secrets = FakeSecrets(s={"access_key_id": "only-half"})  # no secret_access_key
    with pytest.raises(ScatterboxError, match="access key/secret"):
        OracleProvider(
            secrets=secrets, secret_name="s", namespace=NAMESPACE, region=REGION, bucket=BUCKET
        )
