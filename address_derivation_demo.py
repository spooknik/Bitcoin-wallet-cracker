#!/usr/bin/env python3
"""Offline P2PKH address derivation using a published public-key test vector."""

import argparse
import hashlib
import sys

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
MAINNET_P2PKH_VERSION = b"\x00"

# SEC-encoded generator point. It is a public, non-secret test vector.
TEST_VECTOR_PUBLIC_KEY = (
    "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
)
TEST_VECTOR_ADDRESS = "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"


def parse_sec_public_key(public_key_hex: str) -> bytes:
    """Validate and decode a compressed or uncompressed SEC public key."""
    try:
        public_key = bytes.fromhex(public_key_hex)
    except ValueError as error:
        raise ValueError("Public key must be hexadecimal.") from error

    is_compressed = len(public_key) == 33 and public_key[0] in (2, 3)
    is_uncompressed = len(public_key) == 65 and public_key[0] == 4
    if not (is_compressed or is_uncompressed):
        raise ValueError(
            "Public key must be a 33-byte compressed or 65-byte uncompressed SEC key."
        )
    return public_key


def hash160(data: bytes) -> bytes:
    """Return RIPEMD-160(SHA-256(data))."""
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def base58_encode(data: bytes) -> str:
    """Encode bytes using Bitcoin's Base58 alphabet."""
    leading_zeroes = len(data) - len(data.lstrip(b"\0"))
    number = int.from_bytes(data, "big")
    encoded = ""

    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded

    return "1" * leading_zeroes + (encoded or "")


def p2pkh_address(public_key_hex: str, version: bytes = MAINNET_P2PKH_VERSION) -> str:
    """Derive a Base58Check P2PKH address from a SEC-encoded public key."""
    if len(version) != 1:
        raise ValueError("P2PKH version must be exactly one byte.")

    payload = version + hash160(parse_sec_public_key(public_key_hex))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58_encode(payload + checksum)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Derive an offline P2PKH address from a public test vector."
    )
    parser.add_argument(
        "--public-key",
        default=TEST_VECTOR_PUBLIC_KEY,
        help="Compressed or uncompressed SEC public key in hexadecimal.",
    )
    args = parser.parse_args()

    try:
        address = p2pkh_address(args.public_key)
    except ValueError as error:
        parser.error(str(error))

    print(f"Public key: {args.public_key}")
    print(f"P2PKH address: {address}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
