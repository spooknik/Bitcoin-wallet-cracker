#!/usr/bin/env python3
"""Offline structural validation for SEC-encoded public keys."""

import argparse
import sys

from address_derivation_demo import TEST_VECTOR_PUBLIC_KEY, parse_sec_public_key


def public_key_format(public_key_hex: str) -> str:
    """Return the SEC encoding format after validating its structure."""
    public_key = parse_sec_public_key(public_key_hex)
    return "compressed" if len(public_key) == 33 else "uncompressed"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Validate the hexadecimal structure of an SEC public key offline."
    )
    parser.add_argument(
        "public_key",
        nargs="?",
        default=TEST_VECTOR_PUBLIC_KEY,
        help="Compressed or uncompressed SEC public key in hexadecimal.",
    )
    args = parser.parse_args()

    try:
        encoding = public_key_format(args.public_key)
    except ValueError as error:
        parser.error(str(error))

    print(f"Valid {encoding} SEC public key ({len(bytes.fromhex(args.public_key))} bytes).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
