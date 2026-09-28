import unittest

from address_derivation_demo import TEST_VECTOR_PUBLIC_KEY
from public_key_validator import public_key_format


class PublicKeyValidatorTests(unittest.TestCase):
    def test_accepts_compressed_sec_public_key(self):
        self.assertEqual(public_key_format(TEST_VECTOR_PUBLIC_KEY), "compressed")

    def test_accepts_uncompressed_sec_public_key(self):
        self.assertEqual(
            public_key_format(
                "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"
            ),
            "uncompressed",
        )

    def test_rejects_invalid_hexadecimal(self):
        with self.assertRaisesRegex(ValueError, "hexadecimal"):
            public_key_format("not-a-public-key")

    def test_rejects_invalid_sec_length(self):
        with self.assertRaisesRegex(ValueError, "33-byte"):
            public_key_format("02" + "00" * 31)


if __name__ == "__main__":
    unittest.main()
