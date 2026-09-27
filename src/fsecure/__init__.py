"""FSecure — an educational AES-based cipher with authenticated encryption.

Not audited and not constant-time. For real data use AES-GCM or ChaCha20-Poly1305.
"""

from .aead import (
    DecryptionError,
    FormatError,
    InvalidTag,
    decrypt,
    decrypt_with_key,
    encrypt,
    encrypt_with_key,
)
from .cipher import FSecureCipher

__version__ = "2.0.0"

__all__ = [
    "DecryptionError",
    "FSecureCipher",
    "FormatError",
    "InvalidTag",
    "decrypt",
    "decrypt_with_key",
    "encrypt",
    "encrypt_with_key",
]
