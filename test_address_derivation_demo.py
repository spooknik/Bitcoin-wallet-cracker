import unittest

from address_derivation_demo import (
    TEST_VECTOR_ADDRESS,
    TEST_VECTOR_PUBLIC_KEY,
    base58_encode,
    hash160,
    p2pkh_address,
)


class AddressDerivationTests(unittest.TestCase):
    def test_hash160_matches_known_public_key_vector(self):
        self.assertEqual(
            hash160(bytes.fromhex(TEST_VECTOR_PUBLIC_KEY)).hex(),
            "751e76e8199196d454941c45d1b3a323f1433bd6",
        )

    def test_p2pkh_address_matches_known_public_key_vector(self):
        self.assertEqual(p2pkh_address(TEST_VECTOR_PUBLIC_KEY), TEST_VECTOR_ADDRESS)

    def test_base58_preserves_leading_zeroes(self):
        self.assertEqual(base58_encode(b"\0\0\x01"), "112")

    def test_invalid_public_key_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Public key"):
            p2pkh_address("deadbeef")


if __name__ == "__main__":
    unittest.main()
