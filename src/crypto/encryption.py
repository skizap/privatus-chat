"""
Basic Encryption and Decryption Module

This module provides symmetric encryption capabilities using AES-256-GCM
for secure message encryption in Privatus-chat.

Security Features:
- AES-256-GCM authenticated encryption
- Secure nonce generation
- Constant-time operations
- Proper key handling and destruction
"""

from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .secure_random import SecureRandom


class EncryptionError(Exception):
    """Base exception for encryption operations."""
    pass


class DecryptionError(Exception):
    """Base exception for decryption operations."""
    pass


class MessageEncryption:
    """
    Handles symmetric encryption and decryption of messages using AES-256-GCM.
    """
    
    @staticmethod
    def generate_key() -> bytes:
        """
        Generate a new 256-bit encryption key.
        
        Returns:
            bytes: 32-byte encryption key
        """
        return SecureRandom.generate_bytes(32)  # 256 bits
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, 
                associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt plaintext using AES-256-GCM.
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key
            associated_data: Optional additional authenticated data
            
        Returns:
            Tuple[bytes, bytes]: (nonce, ciphertext) where ciphertext includes auth tag
            
        Raises:
            EncryptionError: If encryption fails
        """
        if len(key) != 32:
            raise EncryptionError("Key must be 32 bytes (256 bits)")
        
        try:
            # Generate random nonce (12 bytes for GCM)
            nonce = SecureRandom.generate_nonce(12)
            
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Encrypt with authentication
            ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
            
            return nonce, ciphertext
            
        except Exception as e:
            raise EncryptionError(f"Encryption failed: {e}") from e
    
    @staticmethod
    def decrypt(nonce: bytes, ciphertext: bytes, key: bytes,
                associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext using AES-256-GCM.
        
        Args:
            nonce: 12-byte nonce used for encryption
            ciphertext: Encrypted data with authentication tag
            key: 32-byte encryption key
            associated_data: Optional additional authenticated data
            
        Returns:
            bytes: Decrypted plaintext
            
        Raises:
            DecryptionError: If decryption or authentication fails
        """
        if len(key) != 32:
            raise DecryptionError("Key must be 32 bytes (256 bits)")
        
        if len(nonce) != 12:
            raise DecryptionError("Nonce must be 12 bytes for GCM")
        
        try:
            # Create AESGCM cipher
            aesgcm = AESGCM(key)
            
            # Decrypt and verify authentication
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            
            return plaintext
            
        except InvalidTag:
            raise DecryptionError("Authentication failed - message may be tampered")
        except Exception as e:
            raise DecryptionError(f"Decryption failed: {e}") from e
    
    @staticmethod
    def encrypt_with_header(plaintext: bytes, key: bytes,
                          header_data: Optional[bytes] = None) -> bytes:
        """
        Encrypt message with nonce prepended for easy transport.
        
        Args:
            plaintext: Data to encrypt
            key: 32-byte encryption key
            header_data: Optional data to authenticate but not encrypt
            
        Returns:
            bytes: nonce + ciphertext (with embedded auth tag)
        """
        nonce, ciphertext = MessageEncryption.encrypt(plaintext, key, header_data)
        return nonce + ciphertext
    
    @staticmethod
    def decrypt_with_header(encrypted_data: bytes, key: bytes,
                          header_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt message with nonce prepended.
        
        Args:
            encrypted_data: nonce + ciphertext (with embedded auth tag)
            key: 32-byte encryption key
            header_data: Optional data that was authenticated but not encrypted
            
        Returns:
            bytes: Decrypted plaintext
        """
        if len(encrypted_data) < 12:
            raise DecryptionError("Encrypted data too short to contain nonce")
        
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        
        return MessageEncryption.decrypt(nonce, ciphertext, key, header_data)


class KeyDerivation:
    """
    Key derivation utilities for creating encryption keys from shared secrets.
    """
    
    @staticmethod
    def derive_keys(shared_secret: bytes, salt: bytes, 
                   info: bytes, num_keys: int = 1, 
                   key_length: int = 32) -> list[bytes]:
        """
        Derive multiple keys from a shared secret using HKDF.
        
        Args:
            shared_secret: Input key material
            salt: Random salt value
            info: Context information
            num_keys: Number of keys to derive
            key_length: Length of each key in bytes
            
        Returns:
            list[bytes]: List of derived keys
        """
        keys = []
        total_length = num_keys * key_length
        
        # Use SecureRandom's key derivation
        key_material = SecureRandom.generate_key_material(
            length=total_length,
            salt=salt,
            info=info
        )
        
        # Split into individual keys
        for i in range(num_keys):
            start = i * key_length
            end = start + key_length
            keys.append(key_material[start:end])
        
        return keys
    
    @staticmethod
    def derive_message_key(chain_key: bytes, counter: int) -> Tuple[bytes, bytes]:
        """
        Derive message key and next chain key from current chain key.
        
        This implements the KDF chain used in the Double Ratchet algorithm.
        
        Args:
            chain_key: Current chain key
            counter: Message counter for uniqueness
            
        Returns:
            Tuple[bytes, bytes]: (message_key, next_chain_key)
        """
        # Create info parameter with counter
        info = f"message-key-{counter}".encode('utf-8')
        next_info = f"chain-key-{counter + 1}".encode('utf-8')
        
        # Generate salt from counter
        salt = counter.to_bytes(4, 'big')
        
        # Derive both keys
        keys = KeyDerivation.derive_keys(
            shared_secret=chain_key,
            salt=salt,
            info=info + next_info,
            num_keys=2,
            key_length=32
        )
        
        message_key = keys[0]
        next_chain_key = keys[1]
        
        return message_key, next_chain_key


def encrypt_message(message: bytes, key: bytes) -> bytes:
    """Convenience function for message encryption."""
    return MessageEncryption.encrypt_with_header(message, key)


def decrypt_message(encrypted_data: bytes, key: bytes) -> bytes:
    """Convenience function for message decryption."""
    return MessageEncryption.decrypt_with_header(encrypted_data, key) 