"""Oracle Cloud Object Storage adapter (S3 Compatibility API).

Oracle exposes an S3-compatible API at a per-tenancy endpoint
(`https://<namespace>.compat.objectstorage.<region>.oraclecloud.com`),
authenticated with a **Customer Secret Key** — an S3-style Access Key ID +
Secret Access Key generated under the user's settings — signed with AWS SigV4
(region = the OCI region). All of that machinery lives in
providers/_s3.S3Bucket; this adapter only wires Oracle's endpoint and profile
to it.

Credentials (the key/secret pair) are kept in the vault; the non-secret
`namespace`, `region`, and `bucket` are register config (so cold recovery can
reconstruct the endpoint). Objects live under a `scatterbox/` prefix and the
RemoteRef is the object key — so get/delete/exists are direct and find() makes
Oracle usable as a cold-recovery source.

The bucket is private (signed requests only). Oracle reports no free-space cap
over the S3 API, so quota() reports summed used bytes with 'estimated'
confidence only when the user sets a capacity cap, else 'unknown'.
"""

from __future__ import annotations

import httpx

from scatterbox.errors import ObjectTooLargeError, ScatterboxError
from scatterbox.providers._s3 import SINGLE_PUT_MAX, S3Bucket
from scatterbox.providers.base import ProviderProfile, Quota, RemoteRef, Transform
from scatterbox.vault import SecretStore

_PROFILE = ProviderProfile(
    latency_class="warm",  # regional enterprise store, a notch off the hot CDNs
    throughput_class="high",
    max_object_bytes=SINGLE_PUT_MAX,  # one-shot PUT ceiling (multipart not used)
    reliability_prior=0.88,  # enterprise object store, S3-durable
    exposure_risk="low",  # private bucket, signed requests only
    rate_limited=True,
)


def credential_blob(access_key_id: str, secret_access_key: str) -> dict:
    """Build the vault credential blob for Oracle's Customer Secret Key (an S3
    access key pair). The only place the key/secret become a stored blob;
    add/reauth/recover all route through here."""
    return {"access_key_id": access_key_id, "secret_access_key": secret_access_key}


def endpoint_for(namespace: str, region: str) -> str:
    """Oracle's S3 compatibility endpoint is per-namespace and per-region."""
    return f"https://{namespace}.compat.objectstorage.{region}.oraclecloud.com"


class OracleProvider:
    """Provider adapter for an Oracle Cloud Object Storage bucket via its S3
    Compatibility API (module docstring covers the wiring); the heavy lifting is
    in providers/_s3.S3Bucket."""

    transform: Transform | None = None

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        namespace: str,
        region: str,
        bucket: str,
        endpoint: str | None = None,  # explicit override (tests/custom domains)
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,  # user cap: "use at most N of this bucket"
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        blob = secrets.get_secret(secret_name)
        if (
            not isinstance(blob, dict)
            or "access_key_id" not in blob
            or "secret_access_key" not in blob
        ):
            raise ScatterboxError(
                f"the Oracle credential {secret_name!r} is missing the S3 access "
                "key/secret — re-run 'scatterbox provider reauth'"
            )
        self._namespace = namespace
        self._region = region
        self._bucket = bucket
        self._max_object_bytes = max_object_bytes
        self._capacity_bytes = capacity_bytes
        self._s3 = S3Bucket(
            access_key_id=blob["access_key_id"],
            secret_access_key=blob["secret_access_key"],
            endpoint=endpoint or endpoint_for(namespace, region),
            region=region,
            bucket=bucket,
            label="Oracle Object Storage",
            transport=transport,
            backoff_base_s=backoff_base_s,
        )

    def profile(self) -> ProviderProfile:
        """Static class profile, tightened by the user's per-instance object cap
        (never above the single-PUT ceiling)."""
        if self._max_object_bytes is None:
            return _PROFILE
        return ProviderProfile(
            latency_class=_PROFILE.latency_class,
            throughput_class=_PROFILE.throughput_class,
            max_object_bytes=min(self._max_object_bytes, SINGLE_PUT_MAX),
            reliability_prior=_PROFILE.reliability_prior,
            exposure_risk=_PROFILE.exposure_risk,
            rate_limited=_PROFILE.rate_limited,
        )

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        cap = self.profile().max_object_bytes
        if cap is not None and len(data) > cap:
            raise ObjectTooLargeError(f"object of {len(data)} bytes exceeds max {cap}")
        return RemoteRef(await self._s3.put(chunk_id, data))

    async def get(self, ref: RemoteRef) -> bytes:
        return await self._s3.get(ref.value)

    async def delete(self, ref: RemoteRef) -> None:
        await self._s3.delete(ref.value)

    async def exists(self, ref: RemoteRef) -> bool:
        return await self._s3.exists(ref.value)

    async def find(self, name: str) -> RemoteRef | None:
        key = await self._s3.find(name)
        return RemoteRef(key) if key is not None else None

    async def quota(self) -> Quota:
        return await self._s3.quota(self._capacity_bytes)
