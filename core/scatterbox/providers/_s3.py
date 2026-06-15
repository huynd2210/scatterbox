"""Shared S3 (AWS Signature Version 4) machinery for S3-compatible backends.

Cloudflare R2, Oracle Cloud Object Storage (its S3 Compatibility API), and
Tigris all speak the same S3 REST dialect: object PUT/GET/HEAD/DELETE and a
ListObjectsV2 over a bucket, every request signed with AWS SigV4. No SDK
(boto3) — the same no-SDK rationale as the other adapters — so the signing is
implemented here directly and `S3Bucket` carries the request/retry/error
machinery the three thin adapters share.

Auth is a *static* access-key-id / secret-access-key pair (not a refreshable
token), so there is nothing to refresh: a 403 SignatureDoesNotMatch /
InvalidAccessKeyId surfaces as a re-authenticate error, the way Koofr's
rejected app password does. The retry discipline mirrors providers/_http
(429/5xx backoff honoring Retry-After, transport retry); each retry re-signs
because the signature is timestamped.

Path-style addressing (`<endpoint>/<bucket>/<key>`) is used throughout — R2,
Tigris, and Oracle's S3 compat all accept it, and it keeps one signing path.
Objects live under a `scatterbox/` key prefix; the RemoteRef is the object key,
so get/delete/exists/find are direct and find() makes every S3 backend a
cold-recovery source.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import random
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from urllib.parse import quote

import httpx

from scatterbox.errors import ProviderFullError, ScatterboxError
from scatterbox.providers.base import Quota

_PREFIX = "scatterbox"  # all objects live under this key prefix
_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_TRIES = 5
_TIMEOUT_S = 120.0  # generous: a multi-MiB chunk on a slow uplink takes a while
# S3's single-PUT ceiling (multipart is required beyond it; we upload one-shot).
SINGLE_PUT_MAX = 5 * 1024 * 1024 * 1024


def _q(s: object) -> str:
    """RFC 3986 encode one query token (encode everything but the unreserved
    set — note `/` IS encoded, unlike a path segment)."""
    return quote(str(s), safe="-_.~")


def _qs(params: dict) -> str:
    """Canonical (sorted, encoded) query string — identical bytes are used to
    build the URL and to sign it, so the two can never disagree."""
    return "&".join(f"{_q(k)}={_q(v)}" for k, v in sorted(params.items()))


def _hmac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date_stamp: str, region: str, service: str) -> bytes:
    """The SigV4 derived signing key: HMAC chain over date/region/service."""
    k = _hmac(("AWS4" + secret).encode("utf-8"), date_stamp)
    k = _hmac(k, region)
    k = _hmac(k, service)
    return _hmac(k, "aws4_request")


def sign_v4(
    *,
    method: str,
    canonical_uri: str,
    canonical_query: str,
    headers: dict,
    payload_hash: str,
    access_key_id: str,
    secret_access_key: str,
    region: str,
    service: str,
    amz_date: str,
) -> str:
    """Compute the `Authorization` header value for one SigV4-signed request.

    `headers` is exactly the set of headers to sign (host + the x-amz-* ones);
    `canonical_uri`/`canonical_query` are already encoded. Pure and
    deterministic — checked against AWS's published test vector in the tests.
    """
    items = sorted((k.lower(), " ".join(str(v).split())) for k, v in headers.items())
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in items)
    signed_headers = ";".join(k for k, _ in items)
    canonical_request = "\n".join(
        [method, canonical_uri, canonical_query, canonical_headers, signed_headers, payload_hash]
    )
    date_stamp = amz_date[:8]
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signing_key = _signing_key(secret_access_key, date_stamp, region, service)
    signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    return (
        f"AWS4-HMAC-SHA256 Credential={access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )


def _parse_list(xml_bytes: bytes) -> tuple[int, str | None]:
    """Sum object sizes in one ListObjectsV2 page; return (bytes, next-token).

    Namespace-agnostic (`{*}`) so it tolerates the schema differences between
    R2, Tigris, and Oracle's S3 compat."""
    root = ET.fromstring(xml_bytes)
    used = sum(int(s.text or 0) for s in root.findall("{*}Contents/{*}Size"))
    truncated = (root.findtext("{*}IsTruncated") or "false").strip().lower() == "true"
    token = root.findtext("{*}NextContinuationToken") if truncated else None
    return used, (token or None)


class S3Bucket:
    """One bucket on one S3-compatible endpoint: signs, retries, and maps
    errors. The three S3 adapters delegate their Provider methods to this."""

    def __init__(
        self,
        *,
        access_key_id: str,
        secret_access_key: str,
        endpoint: str,
        region: str,
        bucket: str,
        label: str,
        prefix: str = _PREFIX,
        service: str = "s3",
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        self._akid = access_key_id
        self._secret = secret_access_key
        self._endpoint = endpoint.rstrip("/")
        self._host = httpx.URL(self._endpoint).host
        self._region = region
        self._bucket = bucket
        self._label = label
        self._prefix = prefix
        self._service = service
        self._transport = transport
        self._backoff_base_s = backoff_base_s

    def key_for(self, name: str) -> str:
        return f"{self._prefix}/{name}"

    # -- signed transport -------------------------------------------------------

    async def _send(
        self,
        method: str,
        key: str = "",
        *,
        query: dict | None = None,
        data: bytes | None = None,
    ) -> httpx.Response:
        """One signed request with the retry discipline (429/5xx backoff,
        transport retry). Re-signs on every attempt (the signature is dated)."""
        enc_key = quote(key, safe="/")  # key slashes are path separators, not encoded
        canonical_uri = f"/{self._bucket}" + (f"/{enc_key}" if enc_key else "")
        canonical_query = _qs(query) if query else ""
        url = f"{self._endpoint}{canonical_uri}" + (f"?{canonical_query}" if canonical_query else "")
        payload = data if data is not None else b""
        payload_hash = hashlib.sha256(payload).hexdigest()
        last_exc: Exception | None = None
        for attempt in range(_MAX_TRIES):
            amz_date = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            headers = {
                "host": self._host,
                "x-amz-content-sha256": payload_hash,
                "x-amz-date": amz_date,
            }
            headers["Authorization"] = sign_v4(
                method=method,
                canonical_uri=canonical_uri,
                canonical_query=canonical_query,
                headers=headers,
                payload_hash=payload_hash,
                access_key_id=self._akid,
                secret_access_key=self._secret,
                region=self._region,
                service=self._service,
                amz_date=amz_date,
            )
            try:
                async with httpx.AsyncClient(
                    transport=self._transport, timeout=_TIMEOUT_S, follow_redirects=True
                ) as client:
                    resp = await client.request(
                        method,
                        url,
                        headers=headers,
                        content=payload if data is not None else None,
                    )
            except httpx.TransportError as exc:
                last_exc = exc
                await self._sleep(attempt, None)
                continue
            if resp.status_code in _RETRY_STATUSES and attempt < _MAX_TRIES - 1:
                await self._sleep(attempt, resp.headers.get("Retry-After"))
                continue
            return resp
        if last_exc is not None:
            raise last_exc
        return resp

    async def _sleep(self, attempt: int, retry_after: str | None) -> None:
        if retry_after is not None:
            try:
                await asyncio.sleep(float(retry_after))
                return
            except ValueError:
                pass
        delay = self._backoff_base_s * (2**attempt)
        await asyncio.sleep(delay * (0.5 + random.random() / 2))

    def _raise_for(self, resp: httpx.Response, action: str) -> httpx.Response:
        """Map an S3 error response onto scatterbox's exceptions; returns the
        response unchanged on success (any 2xx). Callers that tolerate 404
        (delete/exists/find) check it before calling this."""
        if resp.status_code < 300:
            return resp
        body = resp.text[:300]
        if resp.status_code in (401, 403):
            raise ScatterboxError(
                f"{self._label} {action} was rejected (HTTP {resp.status_code}): the "
                "S3 access key/secret was refused — re-run 'scatterbox provider "
                f"reauth'. {body}"
            )
        if resp.status_code == 507 or b"QuotaExceeded" in resp.content:
            raise ProviderFullError(f"{self._label} storage quota exceeded")
        raise ScatterboxError(f"{self._label} {action} failed (HTTP {resp.status_code}): {body}")

    # -- object operations ------------------------------------------------------

    async def put(self, name: str, data: bytes) -> str:
        """Upload opaque bytes under the scatterbox/ prefix; the ref is the
        (stable) object key, so a re-snapshot overwrites in place."""
        key = self.key_for(name)
        self._raise_for(await self._send("PUT", key, data=data), "upload")
        return key

    async def get(self, key: str) -> bytes:
        resp = await self._send("GET", key)
        if resp.status_code == 404:
            raise ScatterboxError(f"{self._label}: object {key!r} not found")
        return self._raise_for(resp, "download").content

    async def delete(self, key: str) -> None:
        """Delete by key; already-gone (404) is success (idempotent). Many S3
        backends return 204 even when absent — both count as success."""
        resp = await self._send("DELETE", key)
        if resp.status_code == 404:
            return
        self._raise_for(resp, "delete")

    async def exists(self, key: str) -> bool:
        """Cheap scrub probe: a HEAD (metadata only, no body transfer)."""
        resp = await self._send("HEAD", key)
        if resp.status_code == 404:
            return False
        self._raise_for(resp, "exists probe")
        return True

    async def find(self, name: str) -> str | None:
        """Locate an object by its put-time name: one HEAD on the known key (no
        listing needed since the prefix is fixed)."""
        key = self.key_for(name)
        resp = await self._send("HEAD", key)
        if resp.status_code == 404:
            return None
        self._raise_for(resp, "find")
        return key

    async def quota(self, capacity_bytes: int | None) -> Quota:
        """Sum stored bytes under the prefix via ListObjectsV2 (also the
        onboarding connection test). S3 reports no free-space cap, so total is
        the user's configured capacity if set ('estimated') else None
        ('unknown')."""
        used = 0
        token: str | None = None
        while True:
            params = {"list-type": "2", "prefix": f"{self._prefix}/"}
            if token:
                params["continuation-token"] = token
            resp = self._raise_for(await self._send("GET", "", query=params), "list")
            page_used, token = _parse_list(resp.content)
            used += page_used
            if token is None:
                break
        if capacity_bytes is None:
            return Quota(total_bytes=None, used_bytes=used, confidence="unknown")
        return Quota(total_bytes=capacity_bytes, used_bytes=used, confidence="estimated")
