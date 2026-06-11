"""Template for a new provider adapter — copy, rename, fill in.

Everything scatterbox hands an adapter is already AES-256-GCM ciphertext
with a random-looking name; the backend is trusted with NOTHING. An adapter
is therefore small: move opaque bytes in and out, be honest in profile()
and quota(), and raise loudly on failure (the scrubber turns failures into
replica-state changes and reliability penalties — never swallow them).

Checklist for a real adapter (see gdrive.py / onedrive.py for worked
examples of the HTTP/retry/auth patterns):

1. Implement the five async methods + profile() below.
2. Pick honest profile() priors. PLAN.md §6's table for the planned types:
       Discord-class:  latency warm,  throughput low,  max_object ~10 MB,
                       reliability_prior 0.5, exposure_risk high, rate-limited
       YouTube-class:  latency glacial, throughput very_low (encode-bound),
                       reliability_prior 0.3, exposure_risk high, transform
       Mega-class:     like a small cloud drive: hot/high, prior ~0.8
       Pastebin-class: tiny max_object_bytes, exposure_risk high, prior low
3. Credentials: NEVER in the register config. Take `secrets` (the unlocked
   vault) + a `secret_name` and read/write the credential blob there, like
   the OAuth adapters do. Config keys in the register must be non-secret
   (ids, folder names, user limits).
4. quota(): report a confidence level you can defend — "exact" only if the
   API truly says so, "estimated" for configured caps, "unknown" otherwise
   (Discord-class). The placement engine keeps safety margins on non-exact.
5. Networked backends: route requests through providers/_http.AuthedClient
   (or mirror its discipline): 429/5xx backoff honoring Retry-After, one
   token refresh on 401, injectable transport so tests run offline.
6. Transform-stage backends (YouTube-class): set `transform` to an
   encoder/decoder pair (bytes -> uploadable form and back). The pipeline
   treats it as a black box with declared size overhead.
7. Register it in providers/__init__.py:
       register_adapter("mybackend", AdapterSpec(
           factory=_mybackend_factory,
           requires_secrets=True,          # if credentials live in the vault
           oauth_module=mybackend_module,  # only for OAuth loopback onboarding
       ))
   Token/webhook-configured backends skip oauth_module; extend the CLI/
   daemon onboarding with whatever prompt their credential flow needs.
8. Test offline with httpx.MockTransport (see tests/test_gdrive.py) and,
   if it can lose data in interesting ways, against the chaos harness.
"""

from __future__ import annotations

from scatterbox.providers.base import ProviderProfile, Quota, RemoteRef, Transform
from scatterbox.vault import SecretStore

_PROFILE = ProviderProfile(
    latency_class="warm",  # hot | warm | glacial
    throughput_class="low",  # high | low | very_low
    max_object_bytes=10 * 1024 * 1024,  # the backend's hard per-object cap
    reliability_prior=0.5,  # 0..1 starting guess; the scrubber learns from there
    exposure_risk="high",  # low | high — how publicly visible objects are
    rate_limited=True,
)


class TemplateProvider:
    """Rename me. Any class with these methods IS a Provider (structural
    typing) — no inheritance needed."""

    transform: Transform | None = None  # set for YouTube-class backends

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,
    ) -> None:
        raise NotImplementedError("this is a template, not an adapter")

    def profile(self) -> ProviderProfile:
        return _PROFILE

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        """Store opaque bytes under a random-looking name; return whatever
        handle is needed to fetch/delete it later (file id, URL, message
        id…). Raise ObjectTooLargeError / ProviderFullError where they
        apply so placement learns the real limits."""
        raise NotImplementedError

    async def get(self, ref: RemoteRef) -> bytes:
        raise NotImplementedError

    async def delete(self, ref: RemoteRef) -> None:
        """Idempotent: deleting something already gone is success."""
        raise NotImplementedError

    async def exists(self, ref: RemoteRef) -> bool:
        """The scrubber's cheap probe — must be much cheaper than get()."""
        raise NotImplementedError

    async def quota(self) -> Quota:
        return Quota(total_bytes=None, used_bytes=0, confidence="unknown")
