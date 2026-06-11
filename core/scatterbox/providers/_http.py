"""Shared HTTP machinery for real provider adapters.

One class, AuthedClient: an httpx wrapper that injects the bearer token from
a TokenManager and applies the retry discipline every real backend needs —

- 429 / 5xx → exponential backoff with jitter, honoring Retry-After,
- 401 → one forced token refresh, then retry (the token may have been
  revoked server-side even if not locally expired),
- transport errors (connection reset, DNS, timeout) → same backoff.

Anything else is returned to the adapter as-is; mapping provider-specific
errors (quota exceeded, not found, ...) is the adapter's job.

A fresh httpx.AsyncClient is opened per request: adapters have no close()
in the Provider protocol, so holding a pooled client would leak. The
handshake cost is acceptable at Phase 2 scale; pooling can come with the
daemon if profiling ever says so.
"""

from __future__ import annotations

import asyncio
import random

import httpx

from scatterbox.oauth import TokenManager

_RETRY_STATUSES = {429, 500, 502, 503, 504}
_MAX_TRIES = 5
_TIMEOUT_S = 120.0  # generous: an 8 MiB chunk on a slow uplink takes a while


def _is_rate_limit_403(resp: httpx.Response) -> bool:
    """Google signals per-user rate limiting as 403 with a rateLimit reason
    (not as 429). Only that flavor of 403 is retryable — a permissions 403
    is permanent and must surface immediately."""
    return resp.status_code == 403 and b"ateLimitExceeded" in resp.content


class AuthedClient:
    """Bearer-authenticated httpx wrapper with the retry discipline from
    the module docstring (429/5xx backoff, 401 refresh, transport retry)."""

    def __init__(
        self,
        tokens: TokenManager,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,  # tests set 0 to skip real sleeps
    ) -> None:
        self._tokens = tokens
        self._transport = transport
        self._backoff_base_s = backoff_base_s

    async def request(
        self,
        method: str,
        url: str,
        *,
        authed: bool = True,  # pre-signed URLs (upload sessions) skip the bearer
        **kwargs,
    ) -> httpx.Response:
        """One logical request with the full retry discipline applied.

        Returns the final response (which may still be an error status the
        adapter must map); raises only on persistent transport failure."""
        refreshed = False
        last_exc: Exception | None = None
        headers = dict(kwargs.pop("headers", None) or {})
        for attempt in range(_MAX_TRIES):
            token = None
            if authed:
                token = await self._tokens.access_token()
                headers["Authorization"] = f"Bearer {token}"
            try:
                async with httpx.AsyncClient(
                    transport=self._transport,
                    timeout=_TIMEOUT_S,
                    follow_redirects=True,
                ) as client:
                    resp = await client.request(method, url, headers=headers, **kwargs)
            except httpx.TransportError as exc:
                last_exc = exc
                await self._sleep(attempt, None)
                continue
            if authed and resp.status_code == 401 and not refreshed:
                # Token rejected: refresh once and retry immediately. A second
                # 401 after a fresh token is a real authorization problem.
                await self._tokens.refresh(failed_token=token)
                refreshed = True
                continue
            if resp.status_code in _RETRY_STATUSES or _is_rate_limit_403(resp):
                if attempt < _MAX_TRIES - 1:
                    await self._sleep(attempt, resp.headers.get("Retry-After"))
                    continue
            return resp
        if last_exc is not None:
            raise last_exc
        return resp  # exhausted retries on a retryable status — caller decides

    async def _sleep(self, attempt: int, retry_after: str | None) -> None:
        """Back off before a retry: honor Retry-After when given, else
        exponential with jitter."""
        if retry_after is not None:
            try:
                await asyncio.sleep(float(retry_after))
                return
            except ValueError:
                pass  # HTTP-date form; fall through to backoff
        # 0.5, 1, 2, 4... seconds, with jitter so parallel uploads don't
        # retry in lockstep against the same rate limiter.
        delay = self._backoff_base_s * (2**attempt)
        await asyncio.sleep(delay * (0.5 + random.random() / 2))
