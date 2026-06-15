"""MEGA (mega.nz) adapter.

Talks to MEGA's `cs` JSON-RPC API directly over httpx (same no-SDK rationale
as the other adapters). MEGA is materially different from every other backend
here, so this adapter carries its own session + crypto instead of reusing
TokenManager / AuthedClient:

- No OAuth, no bearer token. The credential is the account email + password.
  A login handshake (see _megacrypto) derives the account master key and a
  session id `sid`; every request is POSTed to
  `https://g.api.mega.co.nz/cs?id=<seq>&sid=<sid>` as a JSON array of command
  objects. The session is logged in lazily and cached for the adapter's
  lifetime (the pipeline builds one instance per file operation); a -15 ESID
  triggers one transparent re-login.
- Errors are negative integers in a JSON body under HTTP 200 (not HTTP
  statuses), so error mapping reads the body — -3 EAGAIN is retried with
  backoff, -9 ENOENT is not-found, -17 EOVERQUOTA is provider-full, -15 ESID
  is a stale session.
- Everything is client-side encrypted. Each object gets a random AES-128 key;
  put() AES-CTR-encrypts it, computes MEGA's chunked MAC, uploads the
  ciphertext, and stores the node key WRAPPED under the account master key.
  The RemoteRef is `<node handle>:<wrapped key>` so get()/delete()/exists()
  need no node-tree walk; only find() (cold recovery) lists+decrypts the
  scatterbox/ folder.

Objects live in a visible `scatterbox/` folder at the Cloud Drive root,
find-or-created lazily and remembered via learned_config() like the
Drive/pCloud/Koofr adapters, so the revoke-and-heal verify gate works.

SECURITY NOTE: unlike the OAuth backends (scoped, revocable) and Koofr (a
revocable app password), MEGA has no scoped credential — the vault stores the
full account password, which grants total account access. The visible
scatterbox/ folder is the only containment; every object is encrypted before
upload regardless.

Crypto adapted from odwyersoftware/mega.py (Apache-2.0); see _megacrypto.py.
"""

from __future__ import annotations

import asyncio
import os
import random

import httpx

from scatterbox.errors import ObjectTooLargeError, ProviderFullError, ScatterboxError
from scatterbox.providers import _megacrypto as mc
from scatterbox.providers.base import (
    ProviderProfile,
    Quota,
    RemoteRef,
    Transform,
)
from scatterbox.vault import SecretStore

_API = "https://g.api.mega.co.nz/cs"
_FOLDER_NAME = "scatterbox"
# Single-request, in-memory upload: cap so the splitter never builds an object
# the one-shot POST (and its in-memory encrypt+MAC) can't take. Matches the
# dropbox/pcloud ceiling.
_UPLOAD_MAX = 150 * 1024 * 1024
_MAX_TRIES = 5
_TIMEOUT_S = 160.0  # MEGA's long-poll-friendly default

# MEGA API error codes we act on (negative ints in a 200 body).
_EAGAIN = -3  # retry with backoff
_ENOENT = -9  # not found
_ESID = -15  # session expired -> re-login
_EBLOCKED = -16
_EOVERQUOTA = -17
_EMFAREQUIRED = -26

_PROFILE = ProviderProfile(
    latency_class="hot",
    throughput_class="high",
    max_object_bytes=_UPLOAD_MAX,
    reliability_prior=0.8,  # Mega-class (PLAN.md §6) — capable consumer cloud
    exposure_risk="low",
    rate_limited=True,
)


def credential_blob(email: str, password: str) -> dict:
    """Build the vault credential blob for a MEGA account. The adapter derives
    the master key + session from these at login; cold recovery rebuilds the
    same blob. (This is the full account password — see the module security
    note.)"""
    return {"email": email, "password": password}


class _Retry(Exception):
    """Internal: a retryable API outcome (-3 EAGAIN or a transport error)."""


class _SessionExpired(Exception):
    """Internal: -15 ESID — the session id must be refreshed."""


class _NotFound(Exception):
    """Internal: -9 ENOENT — the node does not exist."""


class MegaProvider:
    """Provider adapter for MEGA account storage (module docstring covers the
    session, error-code, and client-side-crypto wrinkles)."""

    transform: Transform | None = None

    def __init__(
        self,
        *,
        secrets: SecretStore,
        secret_name: str,
        folder_handle: str | None = None,
        max_object_bytes: int | None = None,
        capacity_bytes: int | None = None,  # user cap: "use at most N of my MEGA"
        transport: httpx.AsyncBaseTransport | None = None,
        backoff_base_s: float = 0.5,
    ) -> None:
        blob = secrets.get_secret(secret_name)
        if not isinstance(blob, dict) or "email" not in blob or "password" not in blob:
            raise ScatterboxError(
                f"the MEGA credential {secret_name!r} is missing email/password "
                "— re-run 'scatterbox provider reauth'"
            )
        self._email = blob["email"]
        self._password = blob["password"]
        self._folder_handle = folder_handle
        self._max_object_bytes = max_object_bytes
        self._capacity_bytes = capacity_bytes
        self._transport = transport
        self._backoff_base_s = backoff_base_s
        # Session state, derived lazily at first use and reused thereafter.
        self._sid: str | None = None
        self._master_key: tuple[int, ...] | None = None
        self._seq = random.randint(0, 0xFFFFFFFF)
        self._session_lock = asyncio.Lock()
        self._folder_lock = asyncio.Lock()

    def profile(self) -> ProviderProfile:
        """Static class profile, tightened by the user's per-instance object
        cap (the single-request upload size is the ceiling)."""
        if self._max_object_bytes is None:
            return _PROFILE
        return ProviderProfile(
            latency_class=_PROFILE.latency_class,
            throughput_class=_PROFILE.throughput_class,
            max_object_bytes=min(self._max_object_bytes, _UPLOAD_MAX),
            reliability_prior=_PROFILE.reliability_prior,
            exposure_risk=_PROFILE.exposure_risk,
            rate_limited=_PROFILE.rate_limited,
        )

    def learned_config(self) -> dict:
        """Config keys discovered at runtime, for the CLI to persist."""
        return (
            {"folder_handle": self._folder_handle}
            if self._folder_handle is not None
            else {}
        )

    async def prepare(self) -> None:
        """Onboarding hook: log in and find-or-create the scatterbox folder now,
        so it appears in the account immediately and its handle lands in
        learned_config()."""
        await self._ensure_folder()

    # -- session / transport ----------------------------------------------------

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    @staticmethod
    def _error_code(data: object) -> int | None:
        """The MEGA error code of a cs response, or None if it carries a real
        payload. Errors are a bare negative int, or a one-element array whose
        element is a negative int."""
        if isinstance(data, int):
            return data
        if isinstance(data, list) and data and isinstance(data[0], int):
            return data[0]
        return None

    async def _api(self, command: dict, *, authed: bool = True) -> object:
        """Issue one cs command with the full retry discipline; returns its
        result payload. authed=False is for the login commands (us0/us), which
        run before a session exists."""
        if authed:
            await self._ensure_session()
        relogged = False
        last_exc: Exception | None = None
        for attempt in range(_MAX_TRIES):
            try:
                return await self._raw_api(command, authed)
            except _Retry as exc:
                last_exc = exc
                if attempt < _MAX_TRIES - 1:
                    await self._sleep(attempt)
                continue
            except _SessionExpired:
                if relogged or not authed:
                    raise ScatterboxError(
                        f"MEGA rejected the session for {self._email} — re-run "
                        "'scatterbox provider reauth'"
                    )
                relogged = True
                self._sid = None
                await self._ensure_session()  # re-login (idempotent under the lock)
                continue
        raise last_exc or ScatterboxError("mega: exhausted retries")

    async def _raw_api(self, command: dict, authed: bool) -> object:
        """One HTTP POST + error mapping. Raises the internal control-flow
        exceptions (_Retry/_SessionExpired/_NotFound) or a ScatterboxError."""
        params: dict[str, object] = {"id": self._next_seq()}
        if authed and self._sid:
            params["sid"] = self._sid
        try:
            async with httpx.AsyncClient(
                transport=self._transport, timeout=_TIMEOUT_S, follow_redirects=True
            ) as client:
                resp = await client.post(_API, params=params, json=[command])
        except httpx.TransportError as exc:
            raise _Retry() from exc
        if resp.status_code in (500, 502, 503, 504):
            raise _Retry()
        code = self._error_code(resp.json())
        if code is not None and code != 0:
            self._raise_for(code, command["a"])
        data = resp.json()
        return data[0] if isinstance(data, list) else data

    def _raise_for(self, code: int, action: str) -> None:
        """Map a MEGA error code to control flow / a ScatterboxError."""
        if code == _EAGAIN:
            raise _Retry()
        if code == _ESID:
            raise _SessionExpired()
        if code == _ENOENT:
            raise _NotFound()
        if code == _EOVERQUOTA:
            raise ProviderFullError("MEGA storage quota exceeded")
        if code == _EMFAREQUIRED:
            raise ScatterboxError(
                "MEGA account has two-factor auth enabled, which scatterbox "
                "does not support"
            )
        if code == _EBLOCKED:
            raise ScatterboxError("MEGA account is blocked")
        raise ScatterboxError(f"mega {action} failed (error {code})")

    async def _ensure_session(self) -> None:
        if self._sid is not None and self._master_key is not None:
            return
        async with self._session_lock:
            if self._sid is None or self._master_key is None:
                await self._login()

    async def _login(self) -> None:
        """Email/password login: probe the account version, derive the key,
        exchange for the master key and session id."""
        email = self._email.lower()
        pre = await self._api({"a": "us0", "user": email}, authed=False)
        if isinstance(pre, dict) and "s" in pre:  # v2 account (PBKDF2)
            password_key, user_hash = mc.derive_v2(self._password, pre["s"])
        else:  # legacy v1 account (iterated AES)
            password_key = mc.derive_v1(self._password)
            user_hash = mc.stringhash(email, password_key)
        try:
            res = await self._api(
                {"a": "us", "user": email, "uh": user_hash}, authed=False
            )
        except _NotFound as exc:  # -9 on us == unknown account / wrong password
            raise ScatterboxError(
                "MEGA login failed — check the account email and password"
            ) from exc
        if not isinstance(res, dict):
            raise ScatterboxError("MEGA login returned an unexpected response")
        master_key = mc.recover_master_key(res["k"], password_key)
        if "tsid" in res:
            if not mc.verify_tsid(res["tsid"], master_key):
                raise ScatterboxError("MEGA login failed — bad transient session")
            sid = res["tsid"]
        else:
            sid = mc.recover_sid_csid(res["privk"], res["csid"], master_key)
        self._master_key = master_key
        self._sid = sid

    async def _sleep(self, attempt: int) -> None:
        """Exponential backoff with jitter (mirrors AuthedClient's discipline)."""
        delay = self._backoff_base_s * (2**attempt)
        await asyncio.sleep(delay * (0.5 + random.random() / 2))

    # -- node tree / folder -----------------------------------------------------

    def _decode_node(self, f: dict) -> tuple[str | None, str | None]:
        """Decrypt a node's name and return (name, wrapped_key_b64). Foreign or
        keyless nodes decode to (None, None)."""
        owner = f.get("u")
        raw_k = f.get("k")
        if not raw_k:
            return None, None
        wrapped = None
        for pair in raw_k.split("/"):
            handle, _, kb = pair.partition(":")
            if handle == owner:
                wrapped = kb
                break
            if wrapped is None:
                wrapped = kb
        if not wrapped:
            return None, None
        key_words = mc.decrypt_key(mc.base64_to_a32(wrapped), self._master_key)
        if f["t"] == 0:  # file: fold the 8-word key to the 128-bit attr key
            attr_key, _, _ = mc.unfold_file_key(key_words)
        else:  # folder: 4-word key used directly
            attr_key = key_words
        attr = (
            mc.decrypt_attr(mc.base64_url_decode(f["a"]), attr_key)
            if f.get("a")
            else None
        )
        return (attr.get("n") if attr else None), wrapped

    async def _fetch_nodes(self) -> tuple[str | None, list[dict]]:
        """Fetch + decrypt the whole node tree. Returns (cloud-drive root handle,
        [{h, p, t, name, wrapped}])."""
        res = await self._api(
            {"a": "f", "c": 1, "r": 1}
        )  # c=full keys/attrs, r=recursive
        root = None
        nodes: list[dict] = []
        for f in res["f"]:
            if f["t"] == 2:  # the Cloud Drive root
                root = f["h"]
            name, wrapped = (None, None)
            if f["t"] in (0, 1):
                name, wrapped = self._decode_node(f)
            nodes.append(
                {
                    "h": f["h"],
                    "p": f.get("p", ""),
                    "t": f["t"],
                    "name": name,
                    "wrapped": wrapped,
                }
            )
        return root, nodes

    async def _ensure_folder(self) -> str:
        """Find-or-create the visible scatterbox/ folder at the Cloud Drive
        root; caches the handle (persisted via learned_config)."""
        if self._folder_handle is not None:
            return self._folder_handle
        await self._ensure_session()
        async with self._folder_lock:
            if self._folder_handle is None:
                root, nodes = await self._fetch_nodes()
                existing = next(
                    (
                        n["h"]
                        for n in nodes
                        if n["t"] == 1 and n["p"] == root and n["name"] == _FOLDER_NAME
                    ),
                    None,
                )
                self._folder_handle = existing or await self._mkdir(_FOLDER_NAME, root)
        return self._folder_handle

    async def _mkdir(self, name: str, parent: str) -> str:
        """Create a folder under parent; returns the new handle."""
        key = mc.bytes_to_a32(os.urandom(16))  # 4-word folder key
        attr = mc.base64_url_encode(mc.encrypt_attr({"n": name}, key))
        wrapped = mc.a32_to_base64(mc.encrypt_key(key, self._master_key))
        res = await self._api(
            {
                "a": "p",
                "t": parent,
                "n": [{"h": "xxxxxxxx", "t": 1, "a": attr, "k": wrapped}],
            }
        )
        return res["f"][0]["h"]

    # -- Provider interface ------------------------------------------------------

    async def put(self, chunk_id: str, data: bytes) -> RemoteRef:
        """Encrypt one object (AES-CTR + MEGA's chunked MAC), upload the
        ciphertext, and create a node whose key is wrapped under the master
        key. The ref is `<node handle>:<wrapped key>`."""
        cap = self.profile().max_object_bytes
        if cap is not None and len(data) > cap:
            raise ObjectTooLargeError(f"object of {len(data)} bytes exceeds max {cap}")
        folder = await self._ensure_folder()
        aes_key = mc.bytes_to_a32(os.urandom(16))  # 4 words
        nonce = mc.bytes_to_a32(os.urandom(8))  # 2 words
        k_bytes = mc.a32_to_bytes(aes_key)
        meta_mac = mc.compute_meta_mac(data, k_bytes, nonce)
        ciphertext = mc.aes_ctr(data, k_bytes, nonce)
        up = await self._api({"a": "u", "s": len(data)})
        completion = await self._upload(up["p"], ciphertext)
        key8 = mc.obfuscate_file_key(aes_key, nonce, meta_mac)
        wrapped = mc.a32_to_base64(mc.encrypt_key(key8, self._master_key))
        attr = mc.base64_url_encode(mc.encrypt_attr({"n": chunk_id}, aes_key))
        res = await self._api(
            {
                "a": "p",
                "t": folder,
                "n": [{"h": completion, "t": 0, "a": attr, "k": wrapped}],
            }
        )
        return RemoteRef(f"{res['f'][0]['h']}:{wrapped}")

    async def _upload(self, url: str, ciphertext: bytes) -> str:
        """Single-request upload of the whole ciphertext to <url>/0; the
        response body is the completion handle. The storage node has the same
        retry discipline as the cs API: transport/5xx and a -3 EAGAIN body are
        retried with backoff, -17 over-quota maps to ProviderFullError."""
        for attempt in range(_MAX_TRIES):
            try:
                async with httpx.AsyncClient(
                    transport=self._transport, timeout=_TIMEOUT_S, follow_redirects=True
                ) as client:
                    resp = await client.post(f"{url}/0", content=ciphertext)
            except httpx.TransportError:
                if attempt < _MAX_TRIES - 1:
                    await self._sleep(attempt)
                    continue
                raise
            if resp.status_code in (500, 502, 503, 504) and attempt < _MAX_TRIES - 1:
                await self._sleep(attempt)
                continue
            resp.raise_for_status()
            token = resp.text.strip().strip('"')
            # The storage node signals errors as a bare negative integer body.
            if token.startswith("-") and token[1:].isdigit():
                code = int(token)
                if code == _EAGAIN and attempt < _MAX_TRIES - 1:
                    await self._sleep(attempt)
                    continue
                if code == _EOVERQUOTA:
                    raise ProviderFullError("MEGA storage quota exceeded")
                raise ScatterboxError(f"mega upload failed (error {code})")
            return token
        raise ScatterboxError("mega upload failed — retries exhausted")

    async def get(self, ref: RemoteRef) -> bytes:
        """Download an object's bytes and verify its MAC; the wrapped key rides
        in the ref so no node-tree walk is needed."""
        handle, _, wrapped = ref.value.partition(":")
        await self._ensure_session()
        aes_key, nonce, meta_mac = mc.unfold_file_key(
            mc.decrypt_key(mc.base64_to_a32(wrapped), self._master_key)
        )
        res = await self._api({"a": "g", "g": 1, "n": handle})
        url = res.get("g")
        if not isinstance(url, str):
            raise ScatterboxError(f"mega: object {handle} is not accessible")
        async with httpx.AsyncClient(
            transport=self._transport, timeout=_TIMEOUT_S, follow_redirects=True
        ) as client:
            dl = await client.get(url)
        dl.raise_for_status()
        k_bytes = mc.a32_to_bytes(aes_key)
        plaintext = mc.aes_ctr(dl.content, k_bytes, nonce)
        if mc.compute_meta_mac(plaintext, k_bytes, nonce) != meta_mac:
            raise ScatterboxError(f"mega: MAC mismatch on {handle} (corrupt download)")
        return plaintext

    async def delete(self, ref: RemoteRef) -> None:
        """Delete by handle; already-gone (-9 ENOENT) is success (idempotent)."""
        handle = ref.value.partition(":")[0]
        try:
            await self._api({"a": "d", "n": handle})
        except _NotFound:
            return  # already gone

    async def exists(self, ref: RemoteRef) -> bool:
        """Cheap scrub probe: ask for the download URL (no bytes transferred);
        a deleted node is -9 ENOENT."""
        handle = ref.value.partition(":")[0]
        try:
            await self._api({"a": "g", "g": 1, "n": handle})
        except _NotFound:
            return False
        return True

    async def find(self, name: str) -> RemoteRef | None:
        """Locate an object by its put-time name: list the scatterbox folder
        and decrypt child names (what makes MEGA a cold-recovery source). Names
        are encrypted, so this lists+decrypts rather than doing a path lookup."""
        await self._ensure_session()
        root, nodes = await self._fetch_nodes()
        folder = next(
            (
                n["h"]
                for n in nodes
                if n["t"] == 1 and n["p"] == root and n["name"] == _FOLDER_NAME
            ),
            None,
        )
        if folder is None:
            return None
        match = next(
            (
                n
                for n in nodes
                if n["t"] == 0 and n["p"] == folder and n["name"] == name
            ),
            None,
        )
        return RemoteRef(f"{match['h']}:{match['wrapped']}") if match else None

    async def quota(self) -> Quota:
        """Account storage numbers from the uq command — 'exact' confidence,
        optionally tightened by the user's capacity cap."""
        res = await self._api({"a": "uq", "strg": 1, "xfer": 1})
        used = int(res.get("cstrg", 0))
        total = res.get("mstrg")
        total = int(total) if total is not None else None
        if self._capacity_bytes is not None:
            total = min(total, self._capacity_bytes) if total else self._capacity_bytes
        if total is None:
            return Quota(total_bytes=None, used_bytes=used, confidence="unknown")
        return Quota(total_bytes=total, used_bytes=used, confidence="exact")
