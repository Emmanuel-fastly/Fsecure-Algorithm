# Changelog

## 2.0.0

Complete rewrite.

- FSecure-128 block cipher: AES-128 (column-major state, standard key schedule,
  MixColumns) plus a key-dependent column permutation derived by Fisher–Yates. Validated
  against FIPS-197 with the permutation switched off.
- FSC2 authenticated-encryption scheme: CTR mode with a random nonce, HMAC-SHA256
  (encrypt-then-MAC), keys from scrypt (passwords) or HKDF (raw keys).
- `bytes` API for messages of any length.
- CLI: `python -m fsecure encrypt|decrypt`.
- pytest suite, `pyproject.toml` packaging and the `ALGORITHM.md` spec.
