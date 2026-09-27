import os
import secrets

import pytest

import fsecure
from fsecure import aead, kdf
from fsecure.cli import main as cli_main

FAST = 10  # low scrypt cost to keep tests quick; the default is 17
PASSWORD = "correct horse battery staple"


def flip(blob: bytes, index: int) -> bytes:
    b = bytearray(blob)
    b[index] ^= 0x01
    return bytes(b)


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1000])
def test_password_round_trip(size):
    data = secrets.token_bytes(size)
    blob = fsecure.encrypt(data, PASSWORD, log2n=FAST)
    assert len(blob) == 7 + 16 + 12 + size + 32
    assert fsecure.decrypt(blob, PASSWORD) == data


def test_large_message_round_trip():
    data = secrets.token_bytes(1 << 20)
    key = secrets.token_bytes(16)
    assert fsecure.decrypt_with_key(fsecure.encrypt_with_key(data, key), key) == data


def test_unicode_password_and_bytes_password():
    blob = fsecure.encrypt(b"hi", "pässwörd 🔑", log2n=FAST)
    assert fsecure.decrypt(blob, "pässwörd 🔑".encode()) == b"hi"


def test_wrong_password():
    blob = fsecure.encrypt(b"secret", PASSWORD, log2n=FAST)
    with pytest.raises(fsecure.InvalidTag):
        fsecure.decrypt(blob, PASSWORD + "!")


def test_wrong_raw_key():
    blob = fsecure.encrypt_with_key(b"secret", bytes(16))
    with pytest.raises(fsecure.InvalidTag):
        fsecure.decrypt_with_key(blob, b"\x01" + bytes(15))


def test_every_byte_is_authenticated():
    """Flipping any single bit anywhere must be rejected.

    Bytes 0-5 (magic, version, kdf_id) fail parsing; from log2N onwards (log2N, salt,
    nonce, ciphertext, tag) the MAC check must catch it.
    """
    blob = fsecure.encrypt(b"attack at dawn", PASSWORD, log2n=FAST)
    for i in range(len(blob)):
        expected = fsecure.DecryptionError if i < 6 else fsecure.InvalidTag
        with pytest.raises(expected):
            fsecure.decrypt(flip(blob, i), PASSWORD)


def test_truncated_blob():
    blob = fsecure.encrypt(b"attack at dawn", PASSWORD, log2n=FAST)
    for cut in (0, 3, 7, 30, len(blob) - 1):
        with pytest.raises(fsecure.DecryptionError):
            fsecure.decrypt(blob[:cut], PASSWORD)


def test_encryption_is_randomised():
    a = fsecure.encrypt(b"same", PASSWORD, log2n=FAST)
    b = fsecure.encrypt(b"same", PASSWORD, log2n=FAST)
    assert a != b
    key = bytes(16)
    assert fsecure.encrypt_with_key(b"same", key) != fsecure.encrypt_with_key(b"same", key)


def test_kind_mismatch_is_format_error():
    with pytest.raises(fsecure.FormatError):
        fsecure.decrypt(fsecure.encrypt_with_key(b"x", bytes(16)), PASSWORD)
    with pytest.raises(fsecure.FormatError):
        fsecure.decrypt_with_key(fsecure.encrypt(b"x", PASSWORD, log2n=FAST), bytes(16))


def test_unsafe_log2n_rejected():
    blob = bytearray(fsecure.encrypt(b"x", PASSWORD, log2n=FAST))
    blob[6] = 30  # would demand an absurd amount of memory
    with pytest.raises(fsecure.FormatError):
        fsecure.decrypt(bytes(blob), PASSWORD)
    with pytest.raises(ValueError):
        fsecure.encrypt(b"x", PASSWORD, log2n=5)


def test_hkdf_rfc5869_case1():
    okm = kdf.hkdf_sha256(
        bytes.fromhex("0b" * 22),
        salt=bytes.fromhex("000102030405060708090a0b0c"),
        info=bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"),
        length=42,
    )
    assert okm.hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        "34007208d5b887185865"
    )


def test_ctr_first_block_is_cipher_of_nonce_counter():
    enc_key, nonce = bytes(16), bytes(12)
    expected = fsecure.FSecureCipher(enc_key).encrypt_block(nonce + bytes(4))
    assert aead._ctr_xor(enc_key, nonce, bytes(16)) == expected


def test_cli_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("FSECURE_PASSWORD", PASSWORD)
    src, enc, dec = tmp_path / "in.txt", tmp_path / "in.fsc", tmp_path / "out.txt"
    src.write_bytes(b"hello from the CLI\n" * 10)
    assert cli_main(["encrypt", "-i", str(src), "-o", str(enc), "--log2n", str(FAST)]) == 0
    assert cli_main(["decrypt", "-i", str(enc), "-o", str(dec)]) == 0
    assert dec.read_bytes() == src.read_bytes()

    monkeypatch.setenv("FSECURE_PASSWORD", "wrong")
    assert cli_main(["decrypt", "-i", str(enc), "-o", str(tmp_path / "x")]) == 1
    assert not os.path.exists(tmp_path / "x")

    assert cli_main(["decrypt", "-i", str(tmp_path / "missing"), "-o", str(dec)]) == 1


def test_max_scrypt_cost_is_usable():
    """hashlib.scrypt rejects maxmem >= 2^31; the documented maximum must still work."""
    assert kdf.scrypt_maxmem(1 << kdf.MAX_LOG2N) <= 2**31 - 1
