import random

import pytest

from fsecure.cipher import (
    FSecureCipher,
    column_permute,
    derive_permutation,
    expand_key,
    inv_column_permute,
    inv_mix_columns,
    inv_shift_rows,
    mix_columns,
    shift_rows,
)
from fsecure.tables import INV_SBOX, SBOX

FIPS_KEY = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
FIPS_PT = bytes.fromhex("00112233445566778899aabbccddeeff")

rng = random.Random(1234)  # deterministic test data only; never for keys in real use


def rand_bytes(n: int) -> bytes:
    return bytes(rng.getrandbits(8) for _ in range(n))


def bit_diff(a: bytes, b: bytes) -> int:
    return bin(int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).count("1")


# --- tables & primitives --------------------------------------------------------------


def test_sbox_inverse():
    assert all(INV_SBOX[SBOX[x]] == x for x in range(256))


def test_primitive_inverses():
    for _ in range(50):
        s = list(rand_bytes(16))
        assert inv_shift_rows(shift_rows(s)) == s
        assert inv_mix_columns(mix_columns(s)) == s
        perm = derive_permutation(rand_bytes(16))
        assert inv_column_permute(column_permute(s, perm), perm) == s


# --- AES-128 conformance (permute=False) ------------------------------------------------


def test_fips197_appendix_a1_key_expansion():
    round_keys = expand_key(bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"))
    assert round_keys[1].hex() == "a0fafe1788542cb123a339392a6c7605"
    assert round_keys[10][-4:].hex() == "b6630ca6"


def test_fips197_appendix_c1_aes128():
    aes = FSecureCipher(FIPS_KEY, permute=False)
    ct = aes.encrypt_block(FIPS_PT)
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"
    assert aes.decrypt_block(ct) == FIPS_PT


# --- FSecure-128 --------------------------------------------------------------------------


def test_known_answer():
    """Frozen vector (differs from AES's 69c4…): any behaviour change must be deliberate."""
    ct = FSecureCipher(FIPS_KEY).encrypt_block(FIPS_PT)
    assert ct.hex() == "608ba82e88a6524af996d041c2600df1"


def test_worked_example_from_spec():
    key = bytes([0x00, 0x5A, 0x13, 0x2E]) + bytes(12)
    assert derive_permutation(key) == (3, 0, 1, 2)


def test_round_trip_random():
    for _ in range(1000):
        cipher = FSecureCipher(rand_bytes(16))
        block = rand_bytes(16)
        assert cipher.decrypt_block(cipher.encrypt_block(block)) == block


@pytest.mark.parametrize("key", [bytes(16), b"\xff" * 16, b"a" * 16, b"\x01" * 16])
def test_weak_keys_do_not_crash(key):
    """Keys with repeated bytes must still yield valid permutations."""
    cipher = FSecureCipher(key)
    assert cipher.decrypt_block(cipher.encrypt_block(FIPS_PT)) == FIPS_PT


def test_permutations_always_valid():
    for _ in range(500):
        for perm in FSecureCipher(rand_bytes(16)).permutations[1:]:
            assert sorted(perm) == [0, 1, 2, 3]


def test_plaintext_avalanche():
    cipher = FSecureCipher(rand_bytes(16))
    block = rand_bytes(16)
    base = cipher.encrypt_block(block)
    diffs = []
    for bit in range(128):
        flipped = (int.from_bytes(block, "big") ^ (1 << bit)).to_bytes(16, "big")
        diffs.append(bit_diff(base, cipher.encrypt_block(flipped)))
    assert 56 <= sum(diffs) / len(diffs) <= 72
    assert min(diffs) > 30


def test_key_avalanche():
    key, block = rand_bytes(16), rand_bytes(16)
    base = FSecureCipher(key).encrypt_block(block)
    diffs = []
    for bit in range(128):
        flipped = (int.from_bytes(key, "big") ^ (1 << bit)).to_bytes(16, "big")
        diffs.append(bit_diff(base, FSecureCipher(flipped).encrypt_block(block)))
    assert 56 <= sum(diffs) / len(diffs) <= 72


@pytest.mark.parametrize("bad", [b"", b"x" * 15, b"x" * 17])
def test_rejects_wrong_sizes(bad):
    with pytest.raises(ValueError):
        FSecureCipher(bad)
    with pytest.raises(ValueError):
        FSecureCipher(FIPS_KEY).encrypt_block(bad)
