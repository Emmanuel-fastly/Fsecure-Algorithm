"""Key derivation: scrypt for passwords, HKDF-SHA256 for raw keys (ALGORITHM.md §3.1)."""

import hashlib
import hmac

ENC_KEY_SIZE = 16
MAC_KEY_SIZE = 32
_OUT_SIZE = ENC_KEY_SIZE + MAC_KEY_SIZE

SCRYPT_R = 8
SCRYPT_P = 1
DEFAULT_LOG2N = 17
MIN_LOG2N = 10
MAX_LOG2N = 20

_HKDF_INFO = b"FSC2 enc+mac"


def _split(okm: bytes) -> tuple[bytes, bytes]:
    return okm[:ENC_KEY_SIZE], okm[ENC_KEY_SIZE:]


def hkdf_sha256(ikm: bytes, *, salt: bytes = b"", info: bytes = b"", length: int) -> bytes:
    """HKDF (RFC 5869) with SHA-256."""
    if length > 255 * 32:
        raise ValueError("HKDF output too long")
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    okm, block = b"", b""
    for counter in range(1, -(-length // 32) + 1):
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
    return okm[:length]


def scrypt_maxmem(n: int) -> int:
    """Memory limit for hashlib.scrypt: ~128*r*(N+p+2) bytes plus 1 MiB headroom.

    hashlib rejects maxmem > 2^31 - 1, so this must stay below that for N = 2^MAX_LOG2N.
    """
    return 128 * SCRYPT_R * n + (1 << 20)


def keys_from_password(password: str | bytes, salt: bytes, log2n: int) -> tuple[bytes, bytes]:
    """Derive (enc_key, mac_key) from a password with scrypt."""
    if not MIN_LOG2N <= log2n <= MAX_LOG2N:
        raise ValueError(f"scrypt log2N must be in [{MIN_LOG2N}, {MAX_LOG2N}], got {log2n}")
    if isinstance(password, str):
        password = password.encode("utf-8")
    n = 1 << log2n
    okm = hashlib.scrypt(
        password,
        salt=salt,
        n=n,
        r=SCRYPT_R,
        p=SCRYPT_P,
        maxmem=scrypt_maxmem(n),
        dklen=_OUT_SIZE,
    )
    return _split(okm)


def keys_from_raw_key(key: bytes) -> tuple[bytes, bytes]:
    """Split a 16-byte raw key into independent (enc_key, mac_key) with HKDF."""
    key = bytes(key)
    if len(key) != 16:
        raise ValueError(f"raw key must be exactly 16 bytes, got {len(key)}")
    return _split(hkdf_sha256(key, info=_HKDF_INFO, length=_OUT_SIZE))
