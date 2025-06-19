"""
Cryptographic Operations Module

This module implements all cryptographic functionality for Privatus-chat,
including the Signal Protocol (Double Ratchet + X3DH), key management,
and secure random number generation.

Security Requirements:
- All operations must use established cryptographic libraries
- Constant-time operations for secret data processing
- Secure key deletion and memory management
- Forward secrecy and post-compromise security
"""

# Import main classes and functions for external use
from .secure_random import SecureRandom, secure_random_bytes, secure_random_int
from .key_management import (
    KeyManager, 
    IdentityKey, 
    PreKey, 
    KeyPair
)
from .encryption import (
    MessageEncryption, 
    KeyDerivation,
    EncryptionError,
    DecryptionError,
    encrypt_message,
    decrypt_message
)

# Version information
__version__ = "0.1.0"

# Public API
__all__ = [
    # Secure random number generation
    'SecureRandom',
    'secure_random_bytes', 
    'secure_random_int',
    
    # Key management
    'KeyManager',
    'IdentityKey',
    'PreKey', 
    'KeyPair',
    
    # Encryption and decryption
    'MessageEncryption',
    'KeyDerivation', 
    'EncryptionError',
    'DecryptionError',
    'encrypt_message',
    'decrypt_message',
]


# Convenience functions for common operations
def initialize_crypto_system(storage_path, password=None):
    """
    Initialize the cryptographic system with key management.
    
    Args:
        storage_path: Path to store encrypted keys
        password: Optional password for key encryption
        
    Returns:
        KeyManager: Initialized key manager instance
    """
    from pathlib import Path
    return KeyManager(Path(storage_path), password)


def generate_secure_key(length=32):
    """
    Generate a secure random key of specified length.
    
    Args:
        length: Key length in bytes (default 32 for AES-256)
        
    Returns:
        bytes: Cryptographically secure random key
    """
    return SecureRandom.generate_bytes(length)


def verify_entropy():
    """
    Check system entropy availability.
    
    Returns:
        float: Estimated entropy bits available
    """
    return SecureRandom.estimate_entropy()

# Module will be populated during Week 2: Basic Cryptographic Implementation 