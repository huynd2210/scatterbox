"""MEGA adapter against a fake MEGA `cs` API.

The fake speaks MEGA's JSON-command protocol over an httpx.MockTransport: the
login handshake (us0 version probe + us with a wrapped master key, RSA-wrapped
private key, and an RSA-encrypted session challenge), the f/u/p/g/d/uq
commands, and the separate upload/download hosts. It validates the adapter's
orchestration and content round-trip; the login crypto primitives themselves
are independently checked here (the uh against a raw PBKDF2) and in the
_megacrypto sanity tests. v1 (legacy iterated-AES) and v2 (PBKDF2) accounts are
both exercised.
"""

import asyncio
import hashlib
import json
import os
import struct

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from scatterbox.errors import ObjectTooLargeError, ProviderFullError
from scatterbox.providers import _megacrypto as mc
from scatterbox.providers import mega
from scatterbox.providers.mega import MegaProvider

from test_oauth import FakeSecrets

EMAIL = "user@example.com"
PASSWORD = "correct horse battery staple"


def _mpi(x: int) -> bytes:
    return struct.pack(">H", x.bit_length()) + x.to_bytes(
        (x.bit_length() + 7) // 8, "big"
    )


class FakeMega:
    """A minimal in-memory MEGA account behind the cs API."""

    USER = "SELFUSER0"

    def __init__(self, *, version: int = 2, quota=(10 * 1024**3, 1024**3)):
        self.version = version
        self.master_key = mc.bytes_to_a32(os.urandom(16))
        self.salt = os.urandom(16)
        # RSA keypair for the csid challenge path.
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        nums = priv.private_numbers()
        pub = priv.public_key().public_numbers()
        self._n, self._e = pub.n, pub.e
        privk = (
            _mpi(nums.p) + _mpi(nums.q) + _mpi(nums.d) + _mpi(pow(nums.q, -1, nums.p))
        )
        privk += b"\x00" * ((-len(privk)) % 16)  # MEGA pads the wrapped blob to 16
        self._privk_b64 = mc.a32_to_base64(
            mc.encrypt_key(mc.bytes_to_a32(privk), self.master_key)
        )
        # The session id is the first 43 bytes of the RSA-decrypted challenge.
        sid_raw = os.urandom(43)
        sid_raw = bytes([sid_raw[0] or 1]) + sid_raw[1:]  # avoid a leading zero byte
        self.sid = mc.base64_url_encode(sid_raw)
        m = int.from_bytes(sid_raw + os.urandom(20), "big")
        self._csid = mc.base64_url_encode(_mpi(pow(m, self._e, self._n)))
        # Filesystem: just the Cloud Drive root to start.
        self.root = "CLOUDDRIVE"
        self.nodes: dict[str, dict] = {self.root: {"h": self.root, "p": "", "t": 2}}
        self.uploads: dict[str, bytes] = {}
        self._counter = 0
        self.quota = quota
        self.over_quota = False
        self.reject_sid_once = False
        self.fail_next: list[int] = []
        self.upload_fail: list[str] = []  # injected storage-node POST responses
        self.requests: list[httpx.Request] = []

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handler)

    # -- crypto the fake performs to mint login material -----------------------

    def _derive(self):
        if self.version == 2:
            return mc.derive_v2(PASSWORD, mc.base64_url_encode(self.salt))
        pk = mc.derive_v1(PASSWORD)
        return pk, mc.stringhash(EMAIL.lower(), pk)

    @staticmethod
    def _resp(obj) -> httpx.Response:
        return httpx.Response(200, json=obj)

    def _f_node(self, n: dict) -> dict:
        out = {"h": n["h"], "p": n["p"], "t": n["t"]}
        if n["t"] in (0, 1):
            out["u"] = self.USER
            out["k"] = f"{self.USER}:{n['wrapped']}"  # MEGA returns owner-prefixed keys
            out["a"] = n["a"]
            if n["t"] == 0:
                out["s"] = n["s"]
        return out

    # -- request handling ------------------------------------------------------

    def handler(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        if host == "gfs.mega.test":  # the storage host (upload/download)
            parts = request.url.path.strip("/").split("/")
            if parts[0] == "upload":
                if self.upload_fail:  # inject a storage-node error body
                    return httpx.Response(200, text=self.upload_fail.pop(0))
                self.uploads[parts[1]] = request.content
                return httpx.Response(200, text=parts[1])  # completion handle
            if parts[0] == "download":
                node = self.nodes.get(parts[1])
                return httpx.Response(200, content=node["ciphertext"] if node else b"")
            return httpx.Response(404)

        self.requests.append(request)
        cmd = json.loads(request.content)[0]
        a = cmd["a"]
        if a in ("us0", "us"):
            return self._login_cmd(a, cmd)
        # Authed commands: validate the session id (carried as ?sid=).
        if self.reject_sid_once:
            self.reject_sid_once = False
            return self._resp([-15])
        if dict(request.url.params).get("sid") != self.sid:
            return self._resp([-15])
        if self.fail_next:
            return self._resp([self.fail_next.pop(0)])
        return getattr(self, f"_cmd_{a}")(cmd)

    def _login_cmd(self, a: str, cmd: dict) -> httpx.Response:
        if a == "us0":
            if self.version == 2:
                return self._resp([{"v": 2, "s": mc.base64_url_encode(self.salt)}])
            return self._resp([{"v": 1}])  # no salt -> v1
        pk, expected_uh = self._derive()
        if cmd.get("uh") != expected_uh:
            return self._resp([-9])
        k_b64 = mc.a32_to_base64(mc.encrypt_key(self.master_key, pk))
        return self._resp([{"k": k_b64, "privk": self._privk_b64, "csid": self._csid}])

    def _cmd_f(self, cmd):
        return self._resp([{"f": [self._f_node(n) for n in self.nodes.values()]}])

    def _cmd_u(self, cmd):
        if self.over_quota:
            return self._resp([-17])
        self._counter += 1
        return self._resp([{"p": f"https://gfs.mega.test/upload/up{self._counter}"}])

    def _cmd_p(self, cmd):
        node = cmd["n"][0]
        self._counter += 1
        h = f"node{self._counter}"
        rec = {
            "h": h,
            "p": cmd["t"],
            "t": node["t"],
            "wrapped": node["k"],
            "a": node["a"],
        }
        if node["t"] == 0:
            rec["ciphertext"] = self.uploads.get(node["h"], b"")
            rec["s"] = len(rec["ciphertext"])  # CTR preserves length -> plaintext size
        self.nodes[h] = rec
        return self._resp([{"f": [{"h": h}]}])

    def _cmd_g(self, cmd):
        node = self.nodes.get(cmd.get("n"))
        if node is None or node["t"] != 0:
            return self._resp([-9])
        return self._resp(
            [
                {
                    "g": f"https://gfs.mega.test/download/{node['h']}",
                    "s": node["s"],
                    "at": node["a"],
                }
            ]
        )

    def _cmd_d(self, cmd):
        if cmd.get("n") not in self.nodes:
            return self._resp([-9])
        del self.nodes[cmd["n"]]
        return self._resp([0])

    def _cmd_uq(self, cmd):
        total, used = self.quota
        return self._resp([{"mstrg": total, "cstrg": used}])


@pytest.fixture
def fake():
    return FakeMega()


def make_provider(fake: FakeMega, **kwargs) -> MegaProvider:
    secrets = FakeSecrets(s=mega.credential_blob(EMAIL, PASSWORD))
    return MegaProvider(
        secrets=secrets,
        secret_name="s",
        transport=fake.transport(),
        backoff_base_s=0,
        **kwargs,
    )


def test_v2_login_roundtrip_and_idempotent_delete(fake):
    p = make_provider(fake)
    data = os.urandom(200_000)  # spans several MEGA MAC chunks
    ref = asyncio.run(p.put("chunk-1", data))
    assert ":" in ref.value  # handle:wrapped-key
    assert asyncio.run(p.get(ref)) == data
    assert asyncio.run(p.exists(ref))
    asyncio.run(p.delete(ref))
    assert not asyncio.run(p.exists(ref))
    asyncio.run(p.delete(ref))  # idempotent: already-gone is success


def test_v1_legacy_account_roundtrip():
    fake = FakeMega(version=1)
    p = make_provider(fake)
    data = b"opaque ciphertext payload for a legacy account"
    ref = asyncio.run(p.put("c", data))
    assert asyncio.run(p.get(ref)) == data
    # the adapter took the v1 path (no salt probed)
    assert any(json.loads(r.content)[0]["a"] == "us0" for r in fake.requests)


def test_get_detects_corruption(fake):
    p = make_provider(fake)
    ref = asyncio.run(p.put("c", os.urandom(50_000)))
    handle = ref.value.partition(":")[0]
    fake.nodes[handle]["ciphertext"] = os.urandom(50_000)  # tamper after upload
    with pytest.raises(Exception, match="MAC mismatch"):
        asyncio.run(p.get(ref))


def test_quota_exact_and_user_cap(fake):
    q = asyncio.run(make_provider(fake).quota())
    assert (q.total_bytes, q.used_bytes, q.confidence) == (
        10 * 1024**3,
        1024**3,
        "exact",
    )
    assert (
        asyncio.run(make_provider(FakeMega(), capacity_bytes=42).quota()).total_bytes
        == 42
    )


def test_over_quota_maps_to_provider_full(fake):
    fake.over_quota = True
    with pytest.raises(ProviderFullError):
        asyncio.run(make_provider(fake).put("c", b"x"))


def test_max_object_bytes_enforced_locally(fake):
    p = make_provider(fake, max_object_bytes=4)
    with pytest.raises(ObjectTooLargeError):
        asyncio.run(p.put("c", b"x" * 5))
    assert fake.requests == []  # rejected before any network call
    assert p.profile().max_object_bytes == 4


def test_find_enables_cold_recovery(fake):
    p = make_provider(fake)
    assert asyncio.run(p.find("register-snap")) is None
    ref = asyncio.run(p.put("register-snap", b"snapshot bytes"))
    found = asyncio.run(p.find("register-snap"))
    assert found is not None and found.value == ref.value
    assert (
        asyncio.run(p.get(found)) == b"snapshot bytes"
    )  # round-trips via the recovered ref


def test_eagain_is_retried(fake):
    p = make_provider(fake)
    asyncio.run(p.quota())  # establish the session first
    fake.fail_next = [-3]  # next authed call gets EAGAIN, then succeeds
    assert asyncio.run(p.quota()).total_bytes == 10 * 1024**3


def test_expired_session_triggers_one_relogin(fake):
    p = make_provider(fake)
    asyncio.run(p.quota())
    logins_before = sum(json.loads(r.content)[0]["a"] == "us" for r in fake.requests)
    fake.reject_sid_once = True  # next authed call gets -15 ESID once
    assert asyncio.run(p.quota()).total_bytes == 10 * 1024**3
    logins_after = sum(json.loads(r.content)[0]["a"] == "us" for r in fake.requests)
    assert logins_after == logins_before + 1  # re-logged in exactly once


def test_upload_node_over_quota_maps_to_provider_full(fake):
    # -17 EOVERQUOTA returned by the storage node (not the cs API) on the chunk
    # POST must still surface as ProviderFullError, not a generic error.
    fake.upload_fail = ["-17"]
    with pytest.raises(ProviderFullError):
        asyncio.run(make_provider(fake).put("c", b"data"))


def test_upload_node_eagain_is_retried(fake):
    # -3 EAGAIN on the chunk POST is retried with backoff, then succeeds.
    p = make_provider(fake)
    fake.upload_fail = ["-3"]
    ref = asyncio.run(p.put("c", b"payload"))
    assert asyncio.run(p.get(ref)) == b"payload"


def test_meta_mac_self_consistent_at_chunk_boundaries(fake):
    # Sizes whose final MEGA chunk is 1..16 bytes are exactly where mega.py's
    # MAC loop misbehaves; our clean MAC must round-trip them self-consistently.
    p = make_provider(fake)
    for size in (131073, 131088, 131072, 0):  # final chunk 1, 16, exact, empty
        data = os.urandom(size)
        ref = asyncio.run(p.put(f"c{size}", data))
        assert asyncio.run(p.get(ref)) == data


def test_login_userhash_matches_independent_pbkdf2(fake):
    asyncio.run(make_provider(fake).quota())  # triggers login
    us = next(
        c for c in (json.loads(r.content)[0] for r in fake.requests) if c["a"] == "us"
    )
    dk = hashlib.pbkdf2_hmac(
        "sha512", PASSWORD.encode("utf-8"), fake.salt, 100000, dklen=32
    )
    assert us["uh"] == mc.base64_url_encode(dk[16:])  # v2 uh = last 16 PBKDF2 bytes
