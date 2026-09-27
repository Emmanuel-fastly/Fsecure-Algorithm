"""FSC2 container: FSecure-128 in CTR mode + HMAC-SHA256, encrypt-then-MAC (ALGORITHM.md §3)."""

import hashlib
import hmac
import secrets

from . import kdf
from .cipher import BLOCK_SIZE, FSecureCipher

MAGIC = b"FSC2"
VERSION = 0x02
KDF_RAW = 0
KDF_SCRYPT = 1

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 32
_FIXED_HEADER_SIZE = len(MAGIC) + 3  # magic | version | kdf_id | log2N
_MAX_BLOCKS = 1 << 32


class DecryptionError(ValueError):
    """Base class for every reason a blob cannot be decrypted."""


class FormatError(DecryptionError):
    """The blob is not a well-formed FSC2 container (or needs a different kind of key)."""


class InvalidTag(DecryptionError):
    """Authentication failed: wrong password/key, or the data was modified."""


def _ctr_xor(enc_key: bytes, nonce: bytes, data: bytes) -> bytes:
    """CTR mode: XOR data with FSecure-128(enc_key, nonce || counter) for counter = 0, 1, …"""
    n_blocks = -(-len(data) // BLOCK_SIZE)
    if n_blocks > _MAX_BLOCKS:
        raise ValueError("message too long for CTR mode (max 2^32 blocks)")
    cipher = FSecureCipher(enc_key)
    keystream = b"".join(
        cipher.encrypt_block(nonce + i.to_bytes(4, "big")) for i in range(n_blocks)
    )[: len(data)]
    return (int.from_bytes(data, "big") ^ int.from_bytes(keystream, "big")).to_bytes(
        len(data), "big"
    )


def _mac(mac_key: bytes, authenticated: bytes) -> bytes:
    return hmac.new(mac_key, authenticated, hashlib.sha256).digest()


def _seal(header: bytes, enc_key: bytes, mac_key: bytes, data: bytes) -> bytes:
    nonce = secrets.token_bytes(NONCE_SIZE)
    body = header + nonce + _ctr_xor(enc_key, nonce, bytes(data))
    return body + _mac(mac_key, body)


def _parse(blob: bytes) -> tuple[int, int, bytes, bytes, bytes, bytes, bytes]:
    """Split a blob into (kdf_id, log2n, salt, nonce, ciphertext, authenticated, tag)."""
    blob = bytes(blob)
    if len(blob) < _FIXED_HEADER_SIZE or blob[:4] != MAGIC:
        raise FormatError("not an FSC2 container")
    version, kdf_id, log2n = blob[4], blob[5], blob[6]
    if version != VERSION:
        raise FormatError(f"unsupported container version {version}")
    if kdf_id == KDF_SCRYPT:
        salt_size = SALT_SIZE
    elif kdf_id == KDF_RAW and log2n == 0:
        salt_size = 0
    else:
        raise FormatError("invalid key-derivation settings")
    nonce_at = _FIXED_HEADER_SIZE + salt_size
    ct_at = nonce_at + NONCE_SIZE
    if len(blob) < ct_at + TAG_SIZE:
        raise FormatError("container is truncated")
    salt = blob[_FIXED_HEADER_SIZE:nonce_at]
    nonce = blob[nonce_at:ct_at]
    authenticated, tag = blob[:-TAG_SIZE], blob[-TAG_SIZE:]
    return kdf_id, log2n, salt, nonce, blob[ct_at:-TAG_SIZE], authenticated, tag


def _open(mac_key: bytes, enc_key: bytes, nonce, ciphertext, authenticated, tag) -> bytes:
    # Verify before decrypting anything.
    if not hmac.compare_digest(_mac(mac_key, authenticated), tag):
        raise InvalidTag("authentication failed: wrong password/key or modified data")
    return _ctr_xor(enc_key, nonce, ciphertext)


def encrypt(data: bytes, password: str | bytes, *, log2n: int = kdf.DEFAULT_LOG2N) -> bytes:
    """Encrypt and authenticate ``data`` under a password. Returns an FSC2 blob."""
    salt = secrets.token_bytes(SALT_SIZE)
    enc_key, mac_key = kdf.keys_from_password(password, salt, log2n)
    header = MAGIC + bytes([VERSION, KDF_SCRYPT, log2n]) + salt
    return _seal(header, enc_key, mac_key, data)


def decrypt(blob: bytes, password: str | bytes) -> bytes:
    """Verify and decrypt an FSC2 blob made by :func:`encrypt`. Raises DecryptionError."""
    kdf_id, log2n, salt, nonce, ciphertext, authenticated, tag = _parse(blob)
    if kdf_id != KDF_SCRYPT:
        raise FormatError("this blob was encrypted with a raw key, not a password")
    try:
        enc_key, mac_key = kdf.keys_from_password(password, salt, log2n)
    except ValueError as exc:
        raise FormatError(str(exc)) from None
    return _open(mac_key, enc_key, nonce, ciphertext, authenticated, tag)


def encrypt_with_key(data: bytes, key: bytes) -> bytes:
    """Encrypt and authenticate ``data`` under a 16-byte raw key. Returns an FSC2 blob."""
    enc_key, mac_key = kdf.keys_from_raw_key(key)
    header = MAGIC + bytes([VERSION, KDF_RAW, 0])
    return _seal(header, enc_key, mac_key, data)


def decrypt_with_key(blob: bytes, key: bytes) -> bytes:
    """Verify and decrypt an FSC2 blob made by :func:`encrypt_with_key`."""
    kdf_id, _, _, nonce, ciphertext, authenticated, tag = _parse(blob)
    if kdf_id != KDF_RAW:
        raise FormatError("this blob was encrypted with a password, not a raw key")
    enc_key, mac_key = kdf.keys_from_raw_key(key)
    return _open(mac_key, enc_key, nonce, ciphertext, authenticated, tag)
