"""MEGA client-side crypto primitives.

MEGA has no OAuth and no bearer tokens: the client derives keys from the
account password, authenticates with a homegrown handshake, and encrypts every
object itself. These are the exact algorithms that handshake and that
encryption need, kept in one small, separately-testable module so the adapter
(mega.py) reads like the other adapters.

Algorithms are adapted from the canonical Python client odwyersoftware/mega.py
(Apache-2.0; no per-file copyright header, repo LICENSE governs) — see the
function-level notes. Everything operates on MEGA's "a32" representation:
arrays of BIG-ENDIAN unsigned 32-bit words. Base64 is MEGA's URL-safe variant
(`-_` for `+/`, padding stripped). Two facts drive the split of rigor here:

- Login crypto (prepare_key/stringhash/PBKDF2, master-key unwrap, RSA sid)
  must be BIT-EXACT with MEGA or the server rejects the login — it is the part
  validated against real accounts.
- Content crypto (AES-CTR, the chunked MAC, key wrapping, attributes) only has
  to be self-consistent: MEGA stores object bytes and key blobs opaquely and
  never re-derives the MAC, and scatterbox only ever downloads objects it
  itself uploaded. So put() and get() agreeing is what matters.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# The fixed 128-bit seed prepare_key stretches (mega.py crypto.prepare_key).
_PREPARE_KEY_SEED = (0x93C467E3, 0x7DB0C7A4, 0xD1BE3F81, 0x0152CB56)
_ZERO_IV = b"\x00" * 16


# -- a32 / base64 conversions (BIG-ENDIAN throughout) --------------------------


def a32_to_bytes(a) -> bytes:
    """Pack a sequence of uint32 words into big-endian bytes."""
    return struct.pack(f">{len(a)}I", *a)


def bytes_to_a32(b: bytes) -> tuple[int, ...]:
    """Unpack big-endian bytes into a tuple of uint32 words (zero-right-padded
    to a 4-byte multiple, exactly as MEGA's str_to_a32 does)."""
    if len(b) % 4:
        b = b + b"\x00" * (4 - len(b) % 4)
    return struct.unpack(f">{len(b) // 4}I", b)


def str_to_a32(s: str) -> tuple[int, ...]:
    """MEGA treats string key material (password, email) as latin-1 bytes."""
    return bytes_to_a32(s.encode("latin-1"))


def base64_url_decode(data: str) -> bytes:
    """Decode MEGA's URL-safe base64 (re-pad, swap -_ -> +/, drop commas)."""
    data += "=="[(2 - len(data) * 3) % 4 :]
    data = data.replace("-", "+").replace("_", "/").replace(",", "")
    return base64.b64decode(data)


def base64_url_encode(data: bytes) -> str:
    """Encode bytes as MEGA's URL-safe base64 (swap +/ -> -_, strip padding)."""
    return (
        base64.b64encode(data)
        .decode("ascii")
        .replace("+", "-")
        .replace("/", "_")
        .replace("=", "")
    )


def base64_to_a32(s: str) -> tuple[int, ...]:
    return bytes_to_a32(base64_url_decode(s))


def a32_to_base64(a) -> str:
    return base64_url_encode(a32_to_bytes(a))


# -- AES helpers ---------------------------------------------------------------
#
# MEGA's "ECB" key wrapping is, in mega.py, CBC with a zero IV applied one
# 16-byte block at a time — which is identical to ECB over the whole buffer
# (each block is independent). We use ECB directly.


def _aes_ecb_encrypt(data: bytes, key: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()  # noqa: S305 (MEGA wire format)
    return enc.update(data) + enc.finalize()


def _aes_ecb_decrypt(data: bytes, key: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.ECB()).decryptor()  # noqa: S305 (MEGA wire format)
    return dec.update(data) + dec.finalize()


def _aes_cbc_encrypt(data: bytes, key: bytes, iv: bytes = _ZERO_IV) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(data) + enc.finalize()


def _aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes = _ZERO_IV) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return dec.update(data) + dec.finalize()


def encrypt_key(a, key) -> tuple[int, ...]:
    """AES-ECB-encrypt an a32 key array under an a32 key (used to wrap the
    master key, node keys, and the RSA private key)."""
    return bytes_to_a32(_aes_ecb_encrypt(a32_to_bytes(a), a32_to_bytes(key)))


def decrypt_key(a, key) -> tuple[int, ...]:
    """Inverse of encrypt_key."""
    return bytes_to_a32(_aes_ecb_decrypt(a32_to_bytes(a), a32_to_bytes(key)))


# -- password -> key derivation (login) ----------------------------------------


def prepare_key(password_a32) -> tuple[int, ...]:
    """v1 (legacy) account key stretch: 65536 rounds of AES-ECB folding the
    password into a 128-bit key (mega.py crypto.prepare_key)."""
    pkey = _PREPARE_KEY_SEED
    for _ in range(0x10000):
        for j in range(0, len(password_a32), 4):
            block = [0, 0, 0, 0]
            for i in range(4):
                if i + j < len(password_a32):
                    block[i] = password_a32[i + j]
            pkey = encrypt_key(pkey, tuple(block))
    return pkey


def derive_v1(password: str) -> tuple[int, ...]:
    """v1 password key (AES-128 as 4 a32 words)."""
    return prepare_key(str_to_a32(password))


def stringhash(text: str, aeskey) -> str:
    """v1 login user-hash: fold the (lowercased) email into 4 words, AES-CBC it
    under the password key 16384 times, keep words 0 and 2 (mega.py)."""
    s32 = str_to_a32(text)
    h32 = [0, 0, 0, 0]
    for i in range(len(s32)):
        h32[i % 4] ^= s32[i]
    h = tuple(h32)
    for _ in range(0x4000):
        h = encrypt_key(h, aeskey)
    return a32_to_base64((h[0], h[2]))


def derive_v2(password: str, salt_b64: str) -> tuple[tuple[int, ...], str]:
    """v2 account derivation: PBKDF2-HMAC-SHA512 over the server salt; the first
    16 bytes are the password key, the last 16 are the login user-hash.

    The salt is zero-padded to a 4-byte multiple before use, matching the
    reference's a32 round-trip (no effect on MEGA's fixed 32-byte salt, but
    keeps parity for any other length)."""
    salt = a32_to_bytes(base64_to_a32(salt_b64))
    dk = hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt, 100000, dklen=32)
    return bytes_to_a32(dk[:16]), base64_url_encode(dk[16:])


# -- session id recovery (login) -----------------------------------------------


def _parse_rsa_privk(privk_bytes: bytes) -> tuple[int, int, int]:
    """Parse the 4 concatenated MPIs of MEGA's RSA private key, returning
    (p, q, d). Each MPI is a 2-byte big-endian bit-length header + magnitude."""
    out: list[int] = []
    b = privk_bytes
    for _ in range(4):
        bitlen = (b[0] << 8) + b[1]
        bytelen = (bitlen + 7) // 8
        out.append(int.from_bytes(b[2 : 2 + bytelen], "big"))
        b = b[2 + bytelen :]
    return out[0], out[1], out[2]  # p, q, d  (out[3]=u is unused)


def recover_master_key(enc_master_key_b64: str, password_key) -> tuple[int, ...]:
    """Unwrap the account master key (the `k` field) with the password key."""
    return decrypt_key(base64_to_a32(enc_master_key_b64), password_key)


def recover_sid_csid(privk_b64: str, csid_b64: str, master_key) -> str:
    """Recover the session id from the RSA challenge: unwrap+parse the RSA
    private key, raw-RSA-decrypt the csid (m = c^d mod n, NO padding), and take
    the first 43 bytes of the plaintext as the sid."""
    privk_bytes = a32_to_bytes(decrypt_key(base64_to_a32(privk_b64), master_key))
    p, q, d = _parse_rsa_privk(privk_bytes)
    n = p * q
    encrypted_sid = int.from_bytes(
        base64_url_decode(csid_b64)[2:], "big"
    )  # strip MPI header
    m = pow(encrypted_sid, d, n)
    sid_hex = "%x" % m
    if len(sid_hex) % 2:
        sid_hex = "0" + sid_hex
    return base64_url_encode(bytes.fromhex(sid_hex)[:43])


def verify_tsid(tsid_b64: str, master_key) -> bool:
    """A tsid is self-validating: its first 16 bytes encrypted under the master
    key must equal its last 16 bytes."""
    tsid = base64_url_decode(tsid_b64)
    expected = a32_to_bytes(encrypt_key(bytes_to_a32(tsid[:16]), master_key))
    return expected == tsid[-16:]


# -- node attributes -----------------------------------------------------------


def encrypt_attr(attr: dict, key) -> bytes:
    """AES-CBC (zero IV) of the 'MEGA'-prefixed JSON attribute blob under a
    node key, zero-padded to a 16-byte multiple."""
    data = b"MEGA" + json.dumps(attr).encode("utf-8")
    if len(data) % 16:
        data += b"\x00" * (16 - len(data) % 16)
    return _aes_cbc_encrypt(data, a32_to_bytes(key))


def decrypt_attr(attr_bytes: bytes, key) -> dict | None:
    """Inverse of encrypt_attr; returns None if the plaintext is not the
    expected 'MEGA{...}' JSON (i.e. wrong key)."""
    data = _aes_cbc_decrypt(attr_bytes, a32_to_bytes(key)).rstrip(b"\x00")
    if data[:6] == b'MEGA{"':
        return json.loads(data[4:].decode("utf-8"))
    return None


# -- file content: chunking, AES-CTR, and the chunked MAC ----------------------


def get_chunks(size: int) -> list[tuple[int, int]]:
    """MEGA's chunk-size schedule as (offset, length) pairs: 128 KiB growing by
    128 KiB up to 1 MiB, then constant, with a final remainder. The MAC is
    computed per chunk, so these boundaries are load-bearing for it."""
    chunks: list[tuple[int, int]] = []
    p = 0
    s = 0x20000
    while p + s < size:
        chunks.append((p, s))
        p += s
        if s < 0x100000:
            s += 0x20000
    chunks.append((p, size - p))
    return chunks


def aes_ctr(data: bytes, key: bytes, nonce: tuple[int, int]) -> bytes:
    """AES-128-CTR over a stream. The 128-bit counter starts at nonce<<64 (the
    nonce occupies the high 64 bits, the block counter the low 64). Symmetric:
    the same call encrypts (upload) and decrypts (download)."""
    counter = a32_to_bytes((nonce[0], nonce[1], 0, 0))
    enc = Cipher(algorithms.AES(key), modes.CTR(counter)).encryptor()
    return enc.update(data) + enc.finalize()


def compute_meta_mac(
    data: bytes, key: bytes, nonce: tuple[int, int]
) -> tuple[int, int]:
    """MEGA's condensed file MAC over PLAINTEXT bytes. Each chunk is CBC-MAC'd
    with IV = nonce||nonce; each chunk's final block feeds a persistent zero-IV
    CBC chain across chunks; the resulting 128-bit MAC is XOR-folded to 64 bits.

    Implemented per chunk by processing every full block except the last into
    the per-chunk CBC state, then the last (zero-padded) block as that chunk's
    MAC — a clean equivalent of mega.py's index dance, and self-consistent
    between put() and get() which is all MEGA requires of the MAC."""
    iv = a32_to_bytes((nonce[0], nonce[1], nonce[0], nonce[1]))
    mac_chain = Cipher(algorithms.AES(key), modes.CBC(_ZERO_IV)).encryptor()
    mac_str = _ZERO_IV
    for start, length in get_chunks(len(data)):
        chunk = data[start : start + length]
        chunk_cbc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        # start of the final block (0 for an empty/short chunk)
        last = ((len(chunk) - 1) // 16) * 16 if chunk else 0
        for off in range(0, last, 16):
            chunk_cbc.update(chunk[off : off + 16])
        block = chunk[last:]  # always 0..16 bytes
        if len(block) < 16:  # short final block (or empty chunk): zero-pad to one block
            block += b"\x00" * (16 - len(block))
        mac_str = mac_chain.update(chunk_cbc.update(block))
    file_mac = bytes_to_a32(mac_str)
    return (file_mac[0] ^ file_mac[1], file_mac[2] ^ file_mac[3])


# -- node key obfuscation ------------------------------------------------------


def obfuscate_file_key(
    aes_key: tuple[int, int, int, int],
    nonce: tuple[int, int],
    meta_mac: tuple[int, int],
) -> tuple[int, ...]:
    """Pack the 128-bit AES key, nonce, and meta-MAC into MEGA's 256-bit stored
    file key (XOR the key halves with nonce+mac, then append nonce and mac)."""
    return (
        aes_key[0] ^ nonce[0],
        aes_key[1] ^ nonce[1],
        aes_key[2] ^ meta_mac[0],
        aes_key[3] ^ meta_mac[1],
        nonce[0],
        nonce[1],
        meta_mac[0],
        meta_mac[1],
    )


def unfold_file_key(
    key8: tuple[int, ...],
) -> tuple[tuple[int, ...], tuple[int, int], tuple[int, int]]:
    """Inverse of obfuscate_file_key: recover (aes_key[4], nonce[2], meta_mac[2])
    from a stored 256-bit file key (XOR the two halves for the AES key)."""
    aes_key = (
        key8[0] ^ key8[4],
        key8[1] ^ key8[5],
        key8[2] ^ key8[6],
        key8[3] ^ key8[7],
    )
    return aes_key, (key8[4], key8[5]), (key8[6], key8[7])
