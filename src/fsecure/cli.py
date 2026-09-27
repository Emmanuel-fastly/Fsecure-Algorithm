"""Command-line interface: ``python -m fsecure encrypt|decrypt -i IN -o OUT``."""

import argparse
import getpass
import os
import sys

from . import aead, kdf


def _read_password(confirm: bool) -> str:
    env = os.environ.get("FSECURE_PASSWORD")
    if env is not None:  # for scripts and tests; interactive use should prefer the prompt
        return env
    password = getpass.getpass("Password: ")
    if confirm and password != getpass.getpass("Confirm password: "):
        raise SystemExit("error: passwords do not match")
    return password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fsecure",
        description="Educational FSecure file encryption (not for real secrets).",
    )
    parser.add_argument("command", choices=("encrypt", "decrypt"))
    parser.add_argument("-i", "--input", required=True, help="input file")
    parser.add_argument("-o", "--output", required=True, help="output file")
    parser.add_argument(
        "--log2n",
        type=int,
        default=kdf.DEFAULT_LOG2N,
        help=f"scrypt cost for encryption (default {kdf.DEFAULT_LOG2N})",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.input, "rb") as f:
            data = f.read()
        password = _read_password(confirm=args.command == "encrypt")
        if args.command == "encrypt":
            out = aead.encrypt(data, password, log2n=args.log2n)
        else:
            out = aead.decrypt(data, password)
        # Only written once encryption/decryption has fully succeeded.
        with open(args.output, "wb") as f:
            f.write(out)
    except (OSError, ValueError) as exc:  # DecryptionError is a ValueError
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0
