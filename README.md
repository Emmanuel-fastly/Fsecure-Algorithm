# Fsecure-Algorithm

An educational block cipher built on AES, wrapped in a complete authenticated-encryption
scheme.

> **Educational only — not audited, not constant-time.**
> Use it to learn how ciphers are built. To protect real data use a vetted AEAD such as
> AES-GCM or ChaCha20-Poly1305 (e.g. the [`cryptography`](https://cryptography.io) package).

- **Full specification:** [ALGORITHM.md](ALGORITHM.md)
- **Changes:** [CHANGELOG.md](CHANGELOG.md)

## What it is

| Layer                        | Summary                                                                                                                                                                                                                          |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **FSecure-128 block cipher** | AES-128 plus a key-dependent column permutation each round. With the permutation switched off it is exactly AES-128, verified against the FIPS-197 test vectors.                                                                 |
| **FSC2 scheme**              | A password goes through scrypt (or a raw key through HKDF) to give separate encryption and MAC keys. Messages of any length are encrypted in CTR mode with a random nonce and authenticated with HMAC-SHA256 (encrypt-then-MAC). |

It has no runtime dependencies: only the Python standard library (3.10+).

## Quickstart

```bash
python -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -q
```

### Python

```python
import fsecure

blob = fsecure.encrypt(b"meet me at noon", "my password")
fsecure.decrypt(blob, "my password")           # b"meet me at noon"
fsecure.decrypt(blob, "wrong")                 # raises fsecure.InvalidTag

key = bytes(16)                                # raw 16-byte key variant
fsecure.decrypt_with_key(fsecure.encrypt_with_key(b"hi", key), key)

cipher = fsecure.FSecureCipher(key)            # the raw block cipher (one 16-byte block)
cipher.decrypt_block(cipher.encrypt_block(b"0123456789abcdef"))
```

### Command line

```bash
python -m fsecure encrypt -i notes.txt -o notes.fsc   # prompts for a password
python -m fsecure decrypt -i notes.fsc -o notes.txt
```

## Project layout

```
src/fsecure/
  cipher.py      FSecure-128 block cipher
  tables.py      S-boxes, round constants, GF(2^8) tables
  kdf.py         scrypt (passwords) and HKDF (raw keys)
  aead.py        FSC2 container: CTR mode + HMAC-SHA256
  cli.py         command-line interface
tests/
  test_cipher.py block cipher: FIPS-197 vectors, round-trips, avalanche
  test_aead.py   scheme: round-trips, wrong keys, tampering, KDF, CLI
```

## License

MIT, see [LICENSE](LICENSE).
