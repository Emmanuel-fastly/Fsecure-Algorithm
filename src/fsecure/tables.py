"""Constant tables for FSecure-128 (identical to AES / FIPS-197)."""

# S-box used by SubBytes and the key schedule.
SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)

# Inverse S-box used by InvSubBytes.
INV_SBOX = bytes.fromhex(
    "52096ad53036a538bf40a39e81f3d7fb7ce339829b2fff87348e4344c4dee9cb"
    "547b9432a6c2233dee4c950b42fac34e082ea16628d924b2765ba2496d8bd125"
    "72f8f66486689816d4a45ccc5d65b6926c704850fdedb9da5e154657a78d9d84"
    "90d8ab008cbcd30af7e45805b8b34506d02c1e8fca3f0f02c1afbd0301138a6b"
    "3a9111414f67dcea97f2cfcef0b4e67396ac7422e7ad3585e2f937e81c75df6e"
    "47f11a711d29c5896fb7620eaa18be1bfc563e4bc6d279209adbc0fe78cd5af4"
    "1fdda8338807c731b11210592780ec5f60517fa919b54a0d2de57a9f93c99cef"
    "a0e03b4dae2af5b0c8ebbb3c83539961172b047eba77d626e169146355210c7d"
)

# Round constants for the AES-128 key schedule (Rcon[1..10]; index 0 unused).
RCON = bytes([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])


def xtime(x: int) -> int:
    """Multiply by 2 in GF(2^8) with the AES polynomial x^8 + x^4 + x^3 + x + 1."""
    x <<= 1
    return (x ^ 0x11B) if x & 0x100 else x


def gf_mul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a = xtime(a)
        b >>= 1
    return result


def _mul_table(factor: int) -> bytes:
    return bytes(gf_mul(x, factor) for x in range(256))


# Precomputed multiplication tables for MixColumns / InvMixColumns.
MUL2 = _mul_table(2)
MUL3 = _mul_table(3)
MUL9 = _mul_table(9)
MUL11 = _mul_table(11)
MUL13 = _mul_table(13)
MUL14 = _mul_table(14)
