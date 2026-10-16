"""
Unit tests for suite-crypto-security hash computation.
"""

import sys
import unittest
from pathlib import Path

SUITE_ROOT = Path(__file__).resolve().parent.parent
if str(SUITE_ROOT) not in sys.path:
    sys.path.insert(0, str(SUITE_ROOT))

from core.hasher import compute_hashes


class TestHasher(unittest.TestCase):
    def test_standard_ascii_hash(self):
        res = compute_hashes("DeveloperOS")
        self.assertEqual(res["input_length"], 11)
        self.assertEqual(len(res["sha256"]), 64)
        self.assertEqual(len(res["sha512"]), 128)
        self.assertEqual(len(res["sha1"]), 40)
        self.assertEqual(len(res["md5"]), 32)
        self.assertIsNone(res["hmac_sha256"])

    def test_empty_string_hashes(self):
        res = compute_hashes("")
        self.assertEqual(res["input_length"], 0)
        self.assertEqual(res["md5"], "d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(res["sha256"], "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_hmac_computation(self):
        res = compute_hashes("Hello DeveloperOS", hmac_key="super_secret_key")
        self.assertIsNotNone(res["hmac_sha256"])
        self.assertIsNotNone(res["hmac_sha512"])
        self.assertEqual(len(res["hmac_sha256"]), 64)
        self.assertEqual(len(res["hmac_sha512"]), 128)

    def test_unicode_and_emojis(self):
        text = "DeveloperOS 🚀 印度 개발자"
        res = compute_hashes(text)
        self.assertGreater(res["byte_length"], res["input_length"])
        self.assertEqual(len(res["sha256"]), 64)

    def test_modern_hashes(self):
        res = compute_hashes("test")
        self.assertIn("sha3_256", res)
        self.assertIn("blake2b", res)
        self.assertEqual(len(res["sha3_256"]), 64)
        self.assertEqual(len(res["blake2b"]), 128)

    def test_none_input_fallback(self):
        res = compute_hashes(None)
        self.assertEqual(res["input_length"], 0)
        self.assertEqual(res["md5"], "d41d8cd98f00b204e9800998ecf8427e")


if __name__ == "__main__":
    unittest.main()
