"""FSecure-128 block cipher: AES-128 plus a key-dependent column permutation.

See ALGORITHM.md section 2 for the specification. The state is a flat list of 16 bytes in
AES column-major order: ``state[r + 4 * c]`` is row ``r``, column ``c``.
"""

from .tables import INV_SBOX, MUL2, MUL3, MUL9, MUL11, MUL13, MUL14, RCON, SBOX

BLOCK_SIZE = 16
KEY_SIZE = 16
ROUNDS = 10

# ShiftRows: row r rotates left by r, i.e. new[r][c] = old[r][(c + r) % 4].
_SHIFT_ROWS = tuple(r + 4 * ((c + r) % 4) for c in range(4) for r in range(4))
_INV_SHIFT_ROWS = tuple(r + 4 * ((c - r) % 4) for c in range(4) for r in range(4))


def _check_len(data, size: int, what: str) -> bytes:
    data = bytes(data)
    if len(data) != size:
        raise ValueError(f"{what} must be exactly {size} bytes, got {len(data)}")
    return data


# --- key schedule -------------------------------------------------------------------


def expand_key(key: bytes) -> list[bytes]:
    """AES-128 key expansion: 16-byte key -> 11 round keys K0..K10 (16 bytes each)."""
    key = _check_len(key, KEY_SIZE, "key")
    words = [list(key[i : i + 4]) for i in range(0, KEY_SIZE, 4)]
    for i in range(4, 4 * (ROUNDS + 1)):
        temp = list(words[i - 1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]  # RotWord
            temp = [SBOX[b] for b in temp]  # SubWord
            temp[0] ^= RCON[i // 4]
        words.append([a ^ b for a, b in zip(words[i - 4], temp)])
    return [bytes(sum(words[4 * r : 4 * r + 4], [])) for r in range(ROUNDS + 1)]


def derive_permutation(round_key: bytes) -> tuple[int, ...]:
    """Fisher–Yates shuffle of the 4 column indices, driven by round-key bytes 1..3."""
    perm = [0, 1, 2, 3]
    for i in range(3, 0, -1):
        j = round_key[i] % (i + 1)
        perm[i], perm[j] = perm[j], perm[i]
    return tuple(perm)


# --- round operations (each returns a new state list) ------------------------------


def sub_bytes(s: list[int]) -> list[int]:
    return [SBOX[b] for b in s]


def inv_sub_bytes(s: list[int]) -> list[int]:
    return [INV_SBOX[b] for b in s]


def shift_rows(s: list[int]) -> list[int]:
    return [s[i] for i in _SHIFT_ROWS]


def inv_shift_rows(s: list[int]) -> list[int]:
    return [s[i] for i in _INV_SHIFT_ROWS]


def column_permute(s: list[int], perm: tuple[int, ...]) -> list[int]:
    """Output column i is input column perm[i]."""
    return [s[r + 4 * perm[c]] for c in range(4) for r in range(4)]


def inv_column_permute(s: list[int], perm: tuple[int, ...]) -> list[int]:
    """Undo column_permute: input column i goes back to column perm[i]."""
    out = [0] * 16
    for c in range(4):
        for r in range(4):
            out[r + 4 * perm[c]] = s[r + 4 * c]
    return out


def mix_columns(s: list[int]) -> list[int]:
    out = []
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c : c + 4]
        out += (
            MUL2[a0] ^ MUL3[a1] ^ a2 ^ a3,
            a0 ^ MUL2[a1] ^ MUL3[a2] ^ a3,
            a0 ^ a1 ^ MUL2[a2] ^ MUL3[a3],
            MUL3[a0] ^ a1 ^ a2 ^ MUL2[a3],
        )
    return out


def inv_mix_columns(s: list[int]) -> list[int]:
    out = []
    for c in range(0, 16, 4):
        a0, a1, a2, a3 = s[c : c + 4]
        out += (
            MUL14[a0] ^ MUL11[a1] ^ MUL13[a2] ^ MUL9[a3],
            MUL9[a0] ^ MUL14[a1] ^ MUL11[a2] ^ MUL13[a3],
            MUL13[a0] ^ MUL9[a1] ^ MUL14[a2] ^ MUL11[a3],
            MUL11[a0] ^ MUL13[a1] ^ MUL9[a2] ^ MUL14[a3],
        )
    return out


def add_round_key(s: list[int], round_key: bytes) -> list[int]:
    return [a ^ k for a, k in zip(s, round_key)]


# --- the cipher ---------------------------------------------------------------------


class FSecureCipher:
    """FSecure-128 block cipher.

    ``permute=False`` skips the column permutation, which makes this plain AES-128 (used
    to validate the implementation against FIPS-197). Instances hold no per-call state, so
    one instance can be shared freely.
    """

    def __init__(self, key: bytes, *, permute: bool = True):
        self.round_keys = tuple(expand_key(key))
        self.permute = permute
        # permutations[r] belongs to round r (1..10); index 0 is unused.
        self.permutations = (None,) + tuple(
            derive_permutation(k) for k in self.round_keys[1:]
        )

    def encrypt_block(self, block: bytes) -> bytes:
        s = add_round_key(list(_check_len(block, BLOCK_SIZE, "block")), self.round_keys[0])
        for r in range(1, ROUNDS + 1):
            s = shift_rows(sub_bytes(s))
            if self.permute:
                s = column_permute(s, self.permutations[r])
            if r != ROUNDS:
                s = mix_columns(s)
            s = add_round_key(s, self.round_keys[r])
        return bytes(s)

    def decrypt_block(self, block: bytes) -> bytes:
        s = list(_check_len(block, BLOCK_SIZE, "block"))
        for r in range(ROUNDS, 0, -1):
            s = add_round_key(s, self.round_keys[r])
            if r != ROUNDS:
                s = inv_mix_columns(s)
            if self.permute:
                s = inv_column_permute(s, self.permutations[r])
            s = inv_sub_bytes(inv_shift_rows(s))
        return bytes(add_round_key(s, self.round_keys[0]))
