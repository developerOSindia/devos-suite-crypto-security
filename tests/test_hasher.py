"""
Unit tests for suite-crypto-security business logic.
"""

import sys
import unittest
from pathlib import Path

# Ensure suite root is in sys.path
SUITE_ROOT = Path(__file__).resolve().parent.parent
if str(SUITE_ROOT) not in sys.path:
    sys.path.insert(0, str(SUITE_ROOT))

from core.hasher import compute_hashes


class TestHasher(unittest.TestCase):
    def test_compute_hashes_known_value(self):
        # Known SHA-256 for "hello" is 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        res = compute_hashes("hello")
        self.assertEqual(res["sha256"], "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
        self.assertEqual(res["md5"], "5d41402abc4b2a76b9719d911017c592")
        self.assertIsNone(res["hmac_sha256"])

    def test_compute_hmac(self):
        res = compute_hashes("hello", hmac_key="secret")
        self.assertIsNotNone(res["hmac_sha256"])
        self.assertEqual(len(res["hmac_sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
