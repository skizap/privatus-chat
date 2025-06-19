"""
Secure Random Number Generation Module

This module provides cryptographically secure random number generation
for all security-critical operations in Privatus-chat.

Security Requirements:
- Use only OS-provided cryptographically secure random sources
- Provide entropy estimation and quality checking
- Implement constant-time operations where applicable
"""

import secrets
import os
from typing import Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class SecureRandom:
    """
    Cryptographically secure random number generator.
    
    Uses the operating system's CSPRNG through Python's secrets module
    with additional entropy estimation and quality checking.
    """
    
    @staticmethod
    def generate_bytes(length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            length: Number of random bytes to generate
            
        Returns:
            bytes: Cryptographically secure random bytes
            
        Raises:
            ValueError: If length is not positive
            OSError: If insufficient entropy is available
        """
        if length <= 0:
            raise ValueError("Length must be positive")
            
        try:
            return secrets.token_bytes(length)
        except OSError as e:
            raise OSError(f"Failed to generate secure random bytes: {e}") from e
    
    @staticmethod
    def generate_int(bit_length: int) -> int:
        """
        Generate a cryptographically secure random integer.
        
        Args:
            bit_length: Number of bits for the random integer
            
        Returns:
            int: Cryptographically secure random integer
            
        Raises:
            ValueError: If bit_length is not positive
        """
        if bit_length <= 0:
            raise ValueError("Bit length must be positive")
            
        # Generate random bytes and convert to integer
        byte_length = (bit_length + 7) // 8  # Round up to nearest byte
        random_bytes = SecureRandom.generate_bytes(byte_length)
        
        # Convert bytes to integer and mask to exact bit length
        random_int = int.from_bytes(random_bytes, 'big')
        
        # Mask to get exactly bit_length bits
        if bit_length % 8 != 0:
            mask = (1 << bit_length) - 1
            random_int &= mask
            
        return random_int
    
    @staticmethod
    def generate_key_material(length: int, salt: Optional[bytes] = None, 
                            info: Optional[bytes] = None) -> bytes:
        """
        Generate key material using HKDF for key derivation.
        
        Args:
            length: Length of key material to generate
            salt: Optional salt for HKDF (generated if None)
            info: Optional context info for HKDF
            
        Returns:
            bytes: Derived key material
        """
        if length <= 0:
            raise ValueError("Length must be positive")
            
        # Generate initial key material
        ikm = SecureRandom.generate_bytes(32)  # 256 bits of entropy
        
        # Use provided salt or generate one
        if salt is None:
            salt = SecureRandom.generate_bytes(16)  # 128 bits
            
        # Derive key material using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=info or b"privatus-chat-key-derivation"
        )
        
        return hkdf.derive(ikm)
    
    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        """
        Generate a cryptographic nonce (number used once).
        
        Args:
            length: Length of nonce in bytes (default 12 for AES-GCM)
            
        Returns:
            bytes: Cryptographically secure nonce
        """
        return SecureRandom.generate_bytes(length)
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Constant-time comparison of byte arrays.
        
        Prevents timing attacks by ensuring comparison time is independent
        of the content being compared.
        
        Args:
            a: First byte array
            b: Second byte array
            
        Returns:
            bool: True if arrays are equal, False otherwise
        """
        return secrets.compare_digest(a, b)
    
    @staticmethod
    def secure_zero(data: bytearray) -> None:
        """
        Securely zero out sensitive data in memory.
        
        Args:
            data: Bytearray to zero out
        """
        # Overwrite with random data first to prevent recovery
        random_data = SecureRandom.generate_bytes(len(data))
        data[:] = random_data
        
        # Then zero out
        data[:] = b'\x00' * len(data)
    
    @staticmethod
    def estimate_entropy() -> float:
        """
        Estimate available system entropy (platform-dependent).
        
        Returns:
            float: Estimated entropy bits (best effort)
        """
        try:
            if os.name == 'nt':  # Windows
                # Windows doesn't expose entropy pool info
                # Return a reasonable estimate
                return 256.0
            else:
                # Unix-like systems
                try:
                    with open('/proc/sys/kernel/random/entropy_avail', 'r') as f:
                        return float(f.read().strip())
                except (OSError, ValueError):
                    return 256.0  # Fallback estimate
        except Exception:
            return 256.0  # Safe fallback


def secure_random_bytes(length: int) -> bytes:
    """Convenience function for generating secure random bytes."""
    return SecureRandom.generate_bytes(length)


def secure_random_int(bit_length: int) -> int:
    """Convenience function for generating secure random integers."""
    return SecureRandom.generate_int(bit_length) 