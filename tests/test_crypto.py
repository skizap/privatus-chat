"""
Cryptographic Module Tests

Tests for all cryptographic operations including:
- Key generation and management
- Signal Protocol implementation
- Encryption/decryption operations
- Security property validation
"""

import pytest
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Import crypto modules
from src.crypto import (
    SecureRandom, 
    KeyManager, 
    IdentityKey, 
    PreKey, 
    MessageEncryption,
    KeyDerivation,
    EncryptionError,
    DecryptionError,
    encrypt_message,
    decrypt_message,
    generate_secure_key,
    verify_entropy
)


class TestSecureRandom:
    """Test suite for secure random number generation."""
    
    def test_generate_bytes(self):
        """Test secure byte generation."""
        # Test various lengths
        for length in [1, 16, 32, 64, 128]:
            random_bytes = SecureRandom.generate_bytes(length)
            assert len(random_bytes) == length
            assert isinstance(random_bytes, bytes)
        
        # Test that different calls produce different results
        bytes1 = SecureRandom.generate_bytes(32)
        bytes2 = SecureRandom.generate_bytes(32)
        assert bytes1 != bytes2
    
    def test_generate_bytes_invalid_length(self):
        """Test error handling for invalid lengths."""
        with pytest.raises(ValueError):
            SecureRandom.generate_bytes(0)
        
        with pytest.raises(ValueError):
            SecureRandom.generate_bytes(-1)
    
    def test_generate_int(self):
        """Test secure integer generation."""
        # Test various bit lengths
        for bit_length in [8, 16, 32, 64, 128, 256]:
            random_int = SecureRandom.generate_int(bit_length)
            assert isinstance(random_int, int)
            assert 0 <= random_int < (2 ** bit_length)
        
        # Test that different calls produce different results
        int1 = SecureRandom.generate_int(32)
        int2 = SecureRandom.generate_int(32)
        assert int1 != int2  # Very high probability
    
    def test_generate_nonce(self):
        """Test nonce generation."""
        nonce = SecureRandom.generate_nonce()
        assert len(nonce) == 12  # Default GCM nonce length
        
        # Test custom length
        nonce16 = SecureRandom.generate_nonce(16)
        assert len(nonce16) == 16
        
        # Test uniqueness
        nonce1 = SecureRandom.generate_nonce()
        nonce2 = SecureRandom.generate_nonce()
        assert nonce1 != nonce2
    
    def test_constant_time_compare(self):
        """Test constant-time comparison."""
        data1 = b"hello world"
        data2 = b"hello world"
        data3 = b"hello earth"
        
        assert SecureRandom.constant_time_compare(data1, data2) is True
        assert SecureRandom.constant_time_compare(data1, data3) is False
        assert SecureRandom.constant_time_compare(b"", b"") is True
    
    def test_secure_zero(self):
        """Test secure memory zeroing."""
        data = bytearray(b"sensitive data")
        original_length = len(data)
        
        SecureRandom.secure_zero(data)
        
        assert len(data) == original_length
        assert data == bytearray(b'\x00' * original_length)
    
    def test_estimate_entropy(self):
        """Test entropy estimation."""
        entropy = SecureRandom.estimate_entropy()
        assert isinstance(entropy, float)
        assert entropy > 0


class TestIdentityKey:
    """Test suite for identity key operations."""
    
    def test_identity_key_creation(self):
        """Test identity key creation and properties."""
        signing_key = ed25519.Ed25519PrivateKey.generate()
        identity_key = IdentityKey(signing_key)
        
        assert identity_key.signing_key == signing_key
        assert identity_key.verify_key == signing_key.public_key()
        assert isinstance(identity_key.key_id, str)
        assert len(identity_key.key_id) == 32  # 16 bytes as hex
    
    def test_identity_key_signing(self):
        """Test message signing and verification."""
        signing_key = ed25519.Ed25519PrivateKey.generate()
        identity_key = IdentityKey(signing_key)
        
        message = b"test message"
        signature = identity_key.sign(message)
        
        assert isinstance(signature, bytes)
        assert identity_key.verify(message, signature) is True
        
        # Test with wrong message
        assert identity_key.verify(b"wrong message", signature) is False
        
        # Test with corrupted signature
        corrupted_signature = signature[:-1] + b'\x00'
        assert identity_key.verify(message, corrupted_signature) is False
    
    def test_get_public_key_bytes(self):
        """Test public key serialization."""
        signing_key = ed25519.Ed25519PrivateKey.generate()
        identity_key = IdentityKey(signing_key)
        
        public_bytes = identity_key.get_public_key_bytes()
        assert isinstance(public_bytes, bytes)
        assert len(public_bytes) == 32  # Ed25519 public key length


class TestPreKey:
    """Test suite for prekey operations."""
    
    def test_prekey_creation(self):
        """Test prekey creation and properties."""
        key_id = 42
        private_key = X25519PrivateKey.generate()
        prekey = PreKey(key_id, private_key)
        
        assert prekey.key_id == key_id
        assert prekey.private_key == private_key
        assert prekey.public_key == private_key.public_key()
        assert prekey.used is False
    
    def test_prekey_usage(self):
        """Test prekey usage tracking."""
        private_key = X25519PrivateKey.generate()
        prekey = PreKey(1, private_key)
        
        assert prekey.used is False
        prekey.mark_used()
        assert prekey.used is True
    
    def test_prekey_dh(self):
        """Test Diffie-Hellman key agreement."""
        # Create two prekeys
        prekey1 = PreKey(1, X25519PrivateKey.generate())
        prekey2 = PreKey(2, X25519PrivateKey.generate())
        
        # Perform DH from both sides
        shared1 = prekey1.perform_dh(prekey2.get_public_key_bytes())
        shared2 = prekey2.perform_dh(prekey1.get_public_key_bytes())
        
        # Should produce the same shared secret
        assert shared1 == shared2
        assert len(shared1) == 32  # X25519 shared secret length


class TestKeyManager:
    """Test suite for key manager operations."""
    
    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            yield Path(temp_dir)
    
    def test_key_manager_creation(self, temp_storage):
        """Test key manager initialization."""
        manager = KeyManager(temp_storage)
        assert manager.storage_path == temp_storage
        assert manager.identity_key is None
    
    def test_key_manager_with_password(self, temp_storage):
        """Test key manager with password encryption."""
        password = "test_password"
        manager = KeyManager(temp_storage, password)
        assert manager.encryption_key is not None
        assert len(manager.encryption_key) == 32
    
    def test_identity_key_generation(self, temp_storage):
        """Test identity key generation and storage."""
        manager = KeyManager(temp_storage)
        
        # Generate identity key
        identity_key = manager.generate_identity_key()
        assert isinstance(identity_key, IdentityKey)
        assert manager.identity_key == identity_key
        
        # Check that key file was created
        key_file = temp_storage / 'identity_key.enc'
        assert key_file.exists()
    
    def test_signed_prekey_generation(self, temp_storage):
        """Test signed prekey generation."""
        manager = KeyManager(temp_storage)
        
        signed_prekey = manager.generate_signed_prekey(1)
        assert isinstance(signed_prekey, PreKey)
        assert signed_prekey.key_id == 1
        assert manager.signed_prekey == signed_prekey
    
    def test_one_time_prekeys_generation(self, temp_storage):
        """Test one-time prekey generation."""
        manager = KeyManager(temp_storage)
        
        prekeys = manager.generate_one_time_prekeys(5)
        assert len(prekeys) == 5
        assert len(manager.one_time_prekeys) == 5
        
        # Check that all have unique IDs
        key_ids = set(prekey.key_id for prekey in prekeys.values())
        assert len(key_ids) == 5
    
    def test_prekey_bundle(self, temp_storage):
        """Test prekey bundle creation."""
        manager = KeyManager(temp_storage)
        
        # Generate required keys
        manager.generate_identity_key()
        manager.generate_signed_prekey(1)
        manager.generate_one_time_prekeys(3)
        
        bundle = manager.get_prekey_bundle()
        
        assert 'identity_key' in bundle
        assert 'signed_prekey' in bundle
        assert 'one_time_prekey' in bundle
        
        assert len(bundle['identity_key']) == 32
        assert bundle['signed_prekey']['key_id'] == 1
    
    def test_key_persistence(self, temp_storage):
        """Test key storage and loading."""
        password = "test_password"
        
        # Create manager and generate keys
        manager1 = KeyManager(temp_storage, password)
        identity_key = manager1.generate_identity_key()
        signed_prekey = manager1.generate_signed_prekey(1)
        one_time_prekeys = manager1.generate_one_time_prekeys(2)
        
        # Create new manager and load keys
        manager2 = KeyManager(temp_storage, password)
        
        # Verify keys were loaded correctly
        assert manager2.identity_key is not None
        assert manager2.identity_key.key_id == identity_key.key_id
        assert manager2.signed_prekey is not None
        assert manager2.signed_prekey.key_id == signed_prekey.key_id
        assert len(manager2.one_time_prekeys) == 2


class TestMessageEncryption:
    """Test suite for message encryption operations."""
    
    def test_key_generation(self):
        """Test encryption key generation."""
        key = MessageEncryption.generate_key()
        assert isinstance(key, bytes)
        assert len(key) == 32  # 256 bits
        
        # Test uniqueness
        key2 = MessageEncryption.generate_key()
        assert key != key2
    
    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption."""
        key = MessageEncryption.generate_key()
        plaintext = b"Hello, encrypted world!"
        
        nonce, ciphertext = MessageEncryption.encrypt(plaintext, key)
        decrypted = MessageEncryption.decrypt(nonce, ciphertext, key)
        
        assert decrypted == plaintext
        assert len(nonce) == 12
        assert len(ciphertext) > len(plaintext)  # Includes auth tag
    
    def test_encrypt_with_associated_data(self):
        """Test encryption with additional authenticated data."""
        key = MessageEncryption.generate_key()
        plaintext = b"secret message"
        associated_data = b"header information"
        
        nonce, ciphertext = MessageEncryption.encrypt(plaintext, key, associated_data)
        decrypted = MessageEncryption.decrypt(nonce, ciphertext, key, associated_data)
        
        assert decrypted == plaintext
        
        # Test that wrong associated data fails
        with pytest.raises(DecryptionError):
            MessageEncryption.decrypt(nonce, ciphertext, key, b"wrong header")
    
    def test_encrypt_with_header(self):
        """Test convenience encryption with header."""
        key = MessageEncryption.generate_key()
        plaintext = b"test message"
        
        encrypted_data = MessageEncryption.encrypt_with_header(plaintext, key)
        decrypted = MessageEncryption.decrypt_with_header(encrypted_data, key)
        
        assert decrypted == plaintext
        assert len(encrypted_data) > len(plaintext) + 12  # nonce + auth tag
    
    def test_invalid_key_length(self):
        """Test error handling for invalid key lengths."""
        short_key = b"short"
        plaintext = b"test"
        
        with pytest.raises(EncryptionError):
            MessageEncryption.encrypt(plaintext, short_key)
        
        with pytest.raises(DecryptionError):
            MessageEncryption.decrypt(b"x" * 12, b"x" * 16, short_key)
    
    def test_tampering_detection(self):
        """Test authentication and tampering detection."""
        key = MessageEncryption.generate_key()
        plaintext = b"important message"
        
        nonce, ciphertext = MessageEncryption.encrypt(plaintext, key)
        
        # Tamper with ciphertext
        tampered_ciphertext = ciphertext[:-1] + b'\x00'
        
        with pytest.raises(DecryptionError):
            MessageEncryption.decrypt(nonce, tampered_ciphertext, key)


class TestKeyDerivation:
    """Test suite for key derivation operations."""
    
    def test_derive_keys(self):
        """Test key derivation from shared secret."""
        shared_secret = SecureRandom.generate_bytes(32)
        salt = SecureRandom.generate_bytes(16)
        info = b"test context"
        
        keys = KeyDerivation.derive_keys(shared_secret, salt, info, 3, 32)
        
        assert len(keys) == 3
        assert all(len(key) == 32 for key in keys)
        assert all(isinstance(key, bytes) for key in keys)
        
        # All keys should be different
        assert keys[0] != keys[1] != keys[2]
    
    def test_derive_message_key(self):
        """Test message key derivation for Double Ratchet."""
        chain_key = SecureRandom.generate_bytes(32)
        counter = 42
        
        message_key, next_chain_key = KeyDerivation.derive_message_key(chain_key, counter)
        
        assert len(message_key) == 32
        assert len(next_chain_key) == 32
        assert isinstance(message_key, bytes)
        assert isinstance(next_chain_key, bytes)
        assert message_key != next_chain_key
        assert message_key != chain_key
        assert next_chain_key != chain_key


class TestConvenienceFunctions:
    """Test suite for convenience functions."""
    
    def test_encrypt_decrypt_message(self):
        """Test convenience message encryption functions."""
        key = generate_secure_key()
        message = b"test message for convenience functions"
        
        encrypted = encrypt_message(message, key)
        decrypted = decrypt_message(encrypted, key)
        
        assert decrypted == message
    
    def test_generate_secure_key(self):
        """Test secure key generation convenience function."""
        key = generate_secure_key()
        assert len(key) == 32
        
        key16 = generate_secure_key(16)
        assert len(key16) == 16
    
    def test_verify_entropy(self):
        """Test entropy verification convenience function."""
        entropy = verify_entropy()
        assert isinstance(entropy, float)
        assert entropy > 0


class TestSecurityProperties:
    """Test suite for security properties and edge cases."""
    
    def test_different_keys_produce_different_results(self):
        """Test that different keys produce different encrypted outputs."""
        plaintext = b"same message"
        key1 = MessageEncryption.generate_key()
        key2 = MessageEncryption.generate_key()
        
        encrypted1 = encrypt_message(plaintext, key1)
        encrypted2 = encrypt_message(plaintext, key2)
        
        assert encrypted1 != encrypted2
    
    def test_same_message_different_nonces(self):
        """Test that encrypting the same message produces different outputs."""
        plaintext = b"same message"
        key = MessageEncryption.generate_key()
        
        encrypted1 = encrypt_message(plaintext, key)
        encrypted2 = encrypt_message(plaintext, key)
        
        # Should be different due to different nonces
        assert encrypted1 != encrypted2
        
        # But both should decrypt to the same plaintext
        assert decrypt_message(encrypted1, key) == plaintext
        assert decrypt_message(encrypted2, key) == plaintext
    
    def test_empty_message_encryption(self):
        """Test encryption of empty messages."""
        key = MessageEncryption.generate_key()
        empty_message = b""
        
        encrypted = encrypt_message(empty_message, key)
        decrypted = decrypt_message(encrypted, key)
        
        assert decrypted == empty_message
    
    def test_large_message_encryption(self):
        """Test encryption of large messages."""
        key = MessageEncryption.generate_key()
        large_message = b"x" * (1024 * 1024)  # 1MB message
        
        encrypted = encrypt_message(large_message, key)
        decrypted = decrypt_message(encrypted, key)
        
        assert decrypted == large_message 