"""
Pure business logic for cryptographic hash computation.
Zero Streamlit or UI dependencies.
"""

import hashlib
import hmac
from typing import Dict, Any, Optional


def compute_hashes(data: str, hmac_key: Optional[str] = None) -> Dict[str, Any]:
    """Computes cryptographic hashes across major algorithms with optional HMAC."""
    raw_bytes = data.encode("utf-8")
    
    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    sha512 = hashlib.sha512(raw_bytes).hexdigest()
    sha1 = hashlib.sha1(raw_bytes).hexdigest()
    md5 = hashlib.md5(raw_bytes).hexdigest()

    hmac_sha256 = None
    if hmac_key:
        key_bytes = hmac_key.encode("utf-8")
        hmac_sha256 = hmac.new(key_bytes, raw_bytes, hashlib.sha256).hexdigest()

    return {
        "input_length": len(data),
        "sha256": sha256,
        "sha512": sha512,
        "sha1": sha1,
        "md5": md5,
        "hmac_sha256": hmac_sha256,
    }
