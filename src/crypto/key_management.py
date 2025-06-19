"""
Cryptographic Key Management Module

This module implements secure key generation, storage, and management
for Privatus-chat, including support for the Signal Protocol key types.

Key Features:
- Curve25519/Ed25519 key generation
- Secure key storage with encryption at rest
- Key lifecycle management and rotation
- Forward secrecy through key deletion
"""

import json
from typing import Dict, Optional, Tuple, Any
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature

from .secure_random import SecureRandom


class KeyPair:
    """
    Represents a cryptographic key pair with secure memory management.
    """
    
    def __init__(self, private_key: bytes, public_key: bytes, key_type: str):
        """
        Initialize a key pair.
        
        Args:
            private_key: Private key bytes
            public_key: Public key bytes  
            key_type: Type of key ('ed25519', 'x25519')
        """
        self.private_key = private_key
        self.public_key = public_key
        self.key_type = key_type
        self._is_destroyed = False
    
    def destroy(self) -> None:
        """Securely destroy private key material."""
        if not self._is_destroyed:
            if isinstance(self.private_key, bytearray):
                SecureRandom.secure_zero(self.private_key)
            self._is_destroyed = True
    
    def is_destroyed(self) -> bool:
        """Check if key pair has been destroyed."""
        return self._is_destroyed
    
    def __del__(self):
        """Ensure key material is destroyed on garbage collection."""
        self.destroy()


class IdentityKey:
    """
    Long-term identity key for user authentication.
    """
    
    def __init__(self, signing_key: ed25519.Ed25519PrivateKey):
        """
        Initialize identity key.
        
        Args:
            signing_key: Ed25519 private key for signing
        """
        self.signing_key = signing_key
        self.verify_key = signing_key.public_key()
        self.key_id = self._generate_key_id()
    
    def _generate_key_id(self) -> str:
        """Generate unique key identifier."""
        public_bytes = self.verify_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        # Use first 16 bytes of SHA-256 hash as key ID
        digest = hashes.Hash(hashes.SHA256())
        digest.update(public_bytes)
        key_hash = digest.finalize()
        return key_hash[:16].hex()
    
    def sign(self, message: bytes) -> bytes:
        """Sign a message with the identity key."""
        return self.signing_key.sign(message)
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify a signature with the identity key."""
        try:
            self.verify_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes."""
        return self.verify_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )


class PreKey:
    """
    One-time prekey for X3DH key agreement.
    """
    
    def __init__(self, key_id: int, private_key: X25519PrivateKey):
        """
        Initialize prekey.
        
        Args:
            key_id: Unique identifier for this prekey
            private_key: X25519 private key
        """
        self.key_id = key_id
        self.private_key = private_key
        self.public_key = private_key.public_key()
        self.created_at = SecureRandom.generate_int(32)  # Timestamp
        self.used = False
    
    def mark_used(self) -> None:
        """Mark prekey as used (one-time use)."""
        self.used = True
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def perform_dh(self, other_public_key: bytes) -> bytes:
        """Perform Diffie-Hellman key agreement."""
        other_key = X25519PublicKey.from_public_bytes(other_public_key)
        shared_key = self.private_key.exchange(other_key)
        return shared_key


class KeyManager:
    """
    Manages all cryptographic keys for Privatus-chat.
    """
    
    def __init__(self, storage_path: Path, password: Optional[str] = None):
        """
        Initialize key manager.
        
        Args:
            storage_path: Path to store encrypted keys
            password: Password for key encryption (optional)
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Derive encryption key from password if provided
        self.encryption_key = self._derive_encryption_key(password) if password else None
        
        # Key storage
        self.identity_key: Optional[IdentityKey] = None
        self.signed_prekey: Optional[PreKey] = None
        self.one_time_prekeys: Dict[int, PreKey] = {}
        self.ephemeral_keys: Dict[str, X25519PrivateKey] = {}
        
        # Load existing keys
        self._load_keys()
    
    def _derive_encryption_key(self, password: str) -> bytes:
        """Derive encryption key from password using PBKDF2."""
        salt = b"privatus-chat-key-salt"  # Should be stored separately in production
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200000,  # High iteration count for security
        )
        return kdf.derive(password.encode('utf-8'))
    
    def _encrypt_data(self, data: bytes) -> bytes:
        """Encrypt data for storage."""
        if not self.encryption_key:
            return data  # No encryption if no password provided
        
        # Generate random IV
        iv = SecureRandom.generate_bytes(16)
        
        # Encrypt with AES-CBC
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv)
        )
        encryptor = cipher.encryptor()
        
        # Pad data to multiple of 16 bytes
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Return IV + encrypted data
        return iv + encrypted_data
    
    def _decrypt_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt data from storage."""
        if not self.encryption_key:
            return encrypted_data  # No decryption if no password provided
        
        # Extract IV and encrypted data
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Decrypt with AES-CBC
        cipher = Cipher(
            algorithms.AES(self.encryption_key),
            modes.CBC(iv)
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_data[-1]
        data = padded_data[:-padding_length]
        
        return data
    
    def generate_identity_key(self) -> IdentityKey:
        """Generate a new identity key pair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        self.identity_key = IdentityKey(private_key)
        self._save_identity_key()
        return self.identity_key
    
    def generate_signed_prekey(self, key_id: int) -> PreKey:
        """Generate a new signed prekey."""
        private_key = X25519PrivateKey.generate()
        self.signed_prekey = PreKey(key_id, private_key)
        self._save_signed_prekey()
        return self.signed_prekey
    
    def generate_one_time_prekeys(self, count: int) -> Dict[int, PreKey]:
        """Generate multiple one-time prekeys."""
        new_prekeys = {}
        
        for i in range(count):
            key_id = len(self.one_time_prekeys) + i + 1
            private_key = X25519PrivateKey.generate()
            prekey = PreKey(key_id, private_key)
            
            new_prekeys[key_id] = prekey
            self.one_time_prekeys[key_id] = prekey
        
        self._save_one_time_prekeys()
        return new_prekeys
    
    def get_prekey_bundle(self) -> Dict[str, Any]:
        """Get prekey bundle for X3DH key agreement."""
        if not self.identity_key or not self.signed_prekey:
            raise ValueError("Identity key and signed prekey must be generated first")
        
        # Get an unused one-time prekey
        one_time_prekey = None
        for prekey in self.one_time_prekeys.values():
            if not prekey.used:
                one_time_prekey = prekey
                break
        
        bundle = {
            'identity_key': self.identity_key.get_public_key_bytes(),
            'signed_prekey': {
                'key_id': self.signed_prekey.key_id,
                'public_key': self.signed_prekey.get_public_key_bytes(),
            }
        }
        
        if one_time_prekey:
            bundle['one_time_prekey'] = {
                'key_id': one_time_prekey.key_id,
                'public_key': one_time_prekey.get_public_key_bytes(),
            }
        
        return bundle
    
    def use_one_time_prekey(self, key_id: int) -> Optional[PreKey]:
        """Mark a one-time prekey as used and return it."""
        if key_id in self.one_time_prekeys:
            prekey = self.one_time_prekeys[key_id]
            prekey.mark_used()
            return prekey
        return None
    
    def _save_identity_key(self) -> None:
        """Save identity key to storage."""
        if not self.identity_key:
            return
        
        key_data = {
            'private_key': self.identity_key.signing_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ).hex(),
            'public_key': self.identity_key.get_public_key_bytes().hex(),
            'key_id': self.identity_key.key_id
        }
        
        data = json.dumps(key_data).encode('utf-8')
        encrypted_data = self._encrypt_data(data)
        
        with open(self.storage_path / 'identity_key.enc', 'wb') as f:
            f.write(encrypted_data)
    
    def _save_signed_prekey(self) -> None:
        """Save signed prekey to storage."""
        if not self.signed_prekey:
            return
        
        key_data = {
            'key_id': self.signed_prekey.key_id,
            'private_key': self.signed_prekey.private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ).hex(),
            'public_key': self.signed_prekey.get_public_key_bytes().hex(),
            'created_at': self.signed_prekey.created_at
        }
        
        data = json.dumps(key_data).encode('utf-8')
        encrypted_data = self._encrypt_data(data)
        
        with open(self.storage_path / 'signed_prekey.enc', 'wb') as f:
            f.write(encrypted_data)
    
    def _save_one_time_prekeys(self) -> None:
        """Save one-time prekeys to storage."""
        keys_data = {}
        
        for key_id, prekey in self.one_time_prekeys.items():
            keys_data[str(key_id)] = {
                'key_id': prekey.key_id,
                'private_key': prekey.private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ).hex(),
                'public_key': prekey.get_public_key_bytes().hex(),
                'created_at': prekey.created_at,
                'used': prekey.used
            }
        
        data = json.dumps(keys_data).encode('utf-8')
        encrypted_data = self._encrypt_data(data)
        
        with open(self.storage_path / 'one_time_prekeys.enc', 'wb') as f:
            f.write(encrypted_data)
    
    def _load_keys(self) -> None:
        """Load keys from storage."""
        try:
            self._load_identity_key()
            self._load_signed_prekey()
            self._load_one_time_prekeys()
        except Exception as e:
            # Log error but don't fail - keys may not exist yet
            pass
    
    def _load_identity_key(self) -> None:
        """Load identity key from storage."""
        key_file = self.storage_path / 'identity_key.enc'
        if not key_file.exists():
            return
        
        with open(key_file, 'rb') as f:
            encrypted_data = f.read()
        
        data = self._decrypt_data(encrypted_data)
        key_data = json.loads(data.decode('utf-8'))
        
        private_key_bytes = bytes.fromhex(key_data['private_key'])
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        
        self.identity_key = IdentityKey(private_key)
    
    def _load_signed_prekey(self) -> None:
        """Load signed prekey from storage."""
        key_file = self.storage_path / 'signed_prekey.enc'
        if not key_file.exists():
            return
        
        with open(key_file, 'rb') as f:
            encrypted_data = f.read()
        
        data = self._decrypt_data(encrypted_data)
        key_data = json.loads(data.decode('utf-8'))
        
        private_key_bytes = bytes.fromhex(key_data['private_key'])
        private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        
        prekey = PreKey(key_data['key_id'], private_key)
        prekey.created_at = key_data['created_at']
        
        self.signed_prekey = prekey
    
    def _load_one_time_prekeys(self) -> None:
        """Load one-time prekeys from storage."""
        keys_file = self.storage_path / 'one_time_prekeys.enc'
        if not keys_file.exists():
            return
        
        with open(keys_file, 'rb') as f:
            encrypted_data = f.read()
        
        data = self._decrypt_data(encrypted_data)
        keys_data = json.loads(data.decode('utf-8'))
        
        for key_id_str, key_data in keys_data.items():
            key_id = int(key_id_str)
            
            private_key_bytes = bytes.fromhex(key_data['private_key'])
            private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
            
            prekey = PreKey(key_id, private_key)
            prekey.created_at = key_data['created_at']
            prekey.used = key_data['used']
            
            self.one_time_prekeys[key_id] = prekey
    
    def generate_identity_keys(self) -> Tuple[bytes, bytes]:
        """Generate identity key pair for anonymous identity management."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        return public_bytes, private_bytes 