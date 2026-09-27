# FSecure-128 — Algorithm Specification

> **Educational cipher. Not audited. Not constant-time.**
> It exists to learn how block ciphers are built. To protect real data use a vetted AEAD
> such as AES-GCM or ChaCha20-Poly1305 (e.g. from the `cryptography` package).

This document is the spec: the code in `src/fsecure/` implements exactly what is written
here.

---

## 1. Overview

FSecure has two layers:

| Layer | What it does | File |
|---|---|---|
| **Block cipher** (FSecure-128) | Encrypts one 16-byte block with a 16-byte key. AES-128 plus a key-dependent column permutation. | `cipher.py` |
| **Scheme** (FSC2 container) | Encrypts messages of any length: derives keys from a password, runs the block cipher in CTR mode, authenticates with HMAC-SHA256. | `kdf.py`, `aead.py` |

---

## 2. The block cipher

### 2.1 The state

The 16 input bytes `b0 … b15` fill a 4×4 matrix **column by column** (as in AES):

```
        col0 col1 col2 col3
row0  [ b0   b4   b8   b12 ]
row1  [ b1   b5   b9   b13 ]
row2  [ b2   b6   b10  b14 ]
row3  [ b3   b7   b11  b15 ]
```

So `state[r][c] = b[r + 4c]`. Using the same layout as AES means that with the custom step
switched off, the cipher *is* AES-128 and can be checked against the official FIPS-197
test vectors.

### 2.2 Key schedule

The standard AES-128 key expansion turns the 16-byte master key into 44 four-byte words
`w0 … w43`, giving 11 round keys `K0 … K10` (`K_r = w[4r] ‖ … ‖ w[4r+3]`):

- `w0 … w3` are the master key.
- For `i ≥ 4`: `temp = w[i-1]`. If `i % 4 == 0`,
  `temp = SubWord(RotWord(temp)) ⊕ (Rcon[i/4], 0, 0, 0)`.
  Then `w[i] = w[i-4] ⊕ temp`.
  - `RotWord` rotates the word one byte to the left: `[a,b,c,d] → [b,c,d,a]`.
  - `SubWord` applies the S-box to each byte.
  - `Rcon` = `01 02 04 08 10 20 40 80 1b 36`.

### 2.3 Column permutations (the FSecure twist)

Each round `r = 1 … 10` gets a permutation `P_r` of the four columns, derived from its
round key `K_r` with a Fisher–Yates shuffle:

```
P = [0, 1, 2, 3]
for i in 3, 2, 1:
    j = K_r[i] mod (i + 1)
    swap P[i], P[j]
```

This *always* yields a valid permutation, whatever the key, including keys with repeated
bytes such as all zeros.

**Worked example.** Suppose `K_r[1] = 0x5a (90)`, `K_r[2] = 0x13 (19)`, `K_r[3] = 0x2e (46)`:

| step | j | P after swap |
|---|---|---|
| start | | `[0, 1, 2, 3]` |
| i = 3 | 46 mod 4 = 2 | `[0, 1, 3, 2]` |
| i = 2 | 19 mod 3 = 1 | `[0, 3, 1, 2]` |
| i = 1 | 90 mod 2 = 0 | `[3, 0, 1, 2]` |

### 2.4 Round operations

| Operation | Definition | Inverse |
|---|---|---|
| **SubBytes** | Every byte `x → S[x]` (AES S-box). The only non-linear step. | `x → S⁻¹[x]` |
| **ShiftRows** | Row `r` rotates left by `r`: `s'[r][c] = s[r][(c + r) mod 4]`. | rotate right by `r` |
| **ColumnPermute(P)** | Output column `i` is input column `P[i]`: `s'[·][i] = s[·][P[i]]`. With `P = [3,0,1,2]`, new col0 = old col3, new col1 = old col0, … | `s'[·][P[i]] = s[·][i]` |
| **MixColumns** | Each column is multiplied in GF(2⁸) by the matrix `[[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`. Every output byte of a column depends on all 4 input bytes. | matrix `[[14,11,13,9],[9,14,11,13],[13,9,14,11],[11,13,9,14]]` |
| **AddRoundKey(K)** | XOR the state with the 16 bytes of `K` (same column-major layout). | itself |

### 2.5 Encryption and decryption

```
Encrypt(block, key):
    state = block
    AddRoundKey(K0)
    for r = 1 .. 9:
        SubBytes → ShiftRows → ColumnPermute(P_r) → MixColumns → AddRoundKey(K_r)
    SubBytes → ShiftRows → ColumnPermute(P_10) → AddRoundKey(K10)     # final round: no MixColumns

Decrypt(block, key):                      # every step inverted, in reverse order
    state = block
    AddRoundKey(K10) → InvColumnPermute(P_10) → InvShiftRows → InvSubBytes
    for r = 9 .. 1:
        AddRoundKey(K_r) → InvMixColumns → InvColumnPermute(P_r) → InvShiftRows → InvSubBytes
    AddRoundKey(K0)
```

With `permute=False`, `ColumnPermute` is skipped and the cipher is exactly AES-128.

---

## 3. The scheme: encrypting real messages

A block cipher alone only handles 16 bytes, and using it block-by-block (ECB) leaks
patterns and allows undetected tampering. The FSC2 scheme adds a mode, keys and integrity.

### 3.1 Key derivation — two independent keys

| Input | Derivation | Output |
|---|---|---|
| **Password** | `scrypt(password (UTF-8), salt = 16 random bytes, N = 2^log2N, r = 8, p = 1, dklen = 48)` | `enc_key` = first 16 bytes, `mac_key` = last 32 bytes |
| **Raw 16-byte key** | `HKDF-SHA256(ikm = key, salt = "", info = "FSC2 enc+mac", L = 48)` | same split |

- scrypt is slow and memory-hard, which makes guessing weak passwords expensive.
  The default is `log2N = 17` (≈128 MiB, a fraction of a second). Decryption accepts
  `10 ≤ log2N ≤ 20`.
- Separate encryption and MAC keys mean one key is never used for two jobs.

### 3.2 CTR mode — any length, no padding

The 16-byte counter block is `nonce (12 random bytes) ‖ counter (4 bytes, big-endian, from 0)`.

```
keystream_i  = FSecure-128_Encrypt(enc_key, nonce ‖ i)
ciphertext_i = plaintext_i ⊕ keystream_i       (the last block is truncated)
```

- Decryption is the same operation.
- The nonce is fresh and random for every message, so encrypting the same plaintext twice
  gives different ciphertexts. A nonce must never repeat under the same key; with
  password-based keys the random salt also changes the key each time.
- Maximum message size: 2³² blocks (64 GiB).

### 3.3 HMAC-SHA256 — detecting tampering (encrypt-then-MAC)

```
tag = HMAC-SHA256(mac_key, header ‖ nonce ‖ ciphertext)       # 32 bytes
```

On decryption the tag is recomputed and compared with `hmac.compare_digest` (constant-time)
**before** any decryption. Any change to any byte, or a wrong password, raises `InvalidTag`.

### 3.4 Container layout

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | magic | `b"FSC2"` |
| 4 | 1 | version | `0x02` |
| 5 | 1 | kdf_id | `0` = raw key, `1` = scrypt password |
| 6 | 1 | log2N | scrypt cost (`0` for raw key) |
| 7 | 16 or 0 | salt | scrypt salt (absent for raw key) |
| … | 12 | nonce | random CTR nonce |
| … | n | ciphertext | same length as the plaintext |
| end − 32 | 32 | tag | HMAC-SHA256 over everything before it |

Everything before the tag, including the header, is authenticated, so the KDF settings
cannot be changed without detection.

---

## 4. Design rationale

**Why MixColumns is essential.** SubBytes and AddRoundKey work on single bytes, and
ShiftRows and ColumnPermute only move bytes around. MixColumns is the only step that mixes
bytes together. Combined with ShiftRows it spreads a change in one input byte over the
whole block within two rounds (the "avalanche effect"). Without it, each ciphertext byte
would depend on exactly one plaintext byte, and the cipher would fall to a 256-chosen-
plaintext codebook attack regardless of the number of rounds.

**Why the column permutation does not weaken AES.** AES's security argument (the *wide
trail strategy*) relies on ShiftRows sending the four bytes of every column to four
*different* columns, which MixColumns then mixes. That guarantees at least 25 active
S-boxes over any 4 rounds. ColumnPermute moves *whole columns*, so after
`ShiftRows → ColumnPermute` every column still holds exactly one byte from each original
column. The property, and the bound, are preserved.

**What the column permutation does *not* do.** There are only 4! = 24 orders, and they
come from the key, so the permutation adds **no key strength**. The key is still 128 bits.
It is a design signature and a teaching point, not a security feature.

**Why a mode and a MAC.** A block cipher on its own handles 16 bytes; applied block by
block (ECB) it leaks repeated patterns and lets tampering go unnoticed. CTR mode with a
fresh random nonce hides patterns, and HMAC-SHA256 over everything makes any modification
detectable.

**Why the AES state layout.** Matching AES exactly (column-major state, standard key
schedule) means the implementation can be validated against the official FIPS-197 test
vectors with the permutation switched off.
