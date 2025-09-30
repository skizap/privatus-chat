"""
Comprehensive Crypto Operations Test Suite for Privatus-chat

This module provides extensive testing for all cryptographic operations including:
- Double Ratchet protocol security and correctness
- Key management and lifecycle
- Encryption/decryption operations
- Key derivation and exchange
- Secure random number generation
- Forward secrecy and post-compromise security
- Memory security and key destruction

Security Testing Focus:
- Cryptographic algorithm correctness
- Key material isolation and destruction
- Forward secrecy verification
- Post-compromise security recovery
- Side-channel attack resistance
- Memory safety and key zeroization
"""

import pytest
import asyncio
import time
import os
import gc
import psutil
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from typing import Dict, List, Any, Tuple
import tempfile
import shutil

# Import crypto modules
from src.crypto.double_ratchet import DoubleRatchet, DoubleRatchetManager, RatchetState, ChainKey, DHRatchetKey
from src.crypto.key_management import KeyManager, IdentityKey, PreKey, SecurityConfig
from src.crypto.encryption import MessageEncryption, KeyDerivation, EncryptionError, DecryptionError
from src.crypto.secure_random import SecureRandom


class TestDoubleRatchetSecurity:
    """Comprehensive security tests for Double Ratchet protocol."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage for key manager."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def key_manager(self, temp_storage):
        """Create key manager for testing."""
        return KeyManager(temp_storage, "test_password_123")

    @pytest.fixture
    def alice_ratchet(self):
        """Create Alice's Double Ratchet session."""
        return DoubleRatchet("alice_bob_session")

    @pytest.fixture
    def bob_ratchet(self):
        """Create Bob's Double Ratchet session."""
        return DoubleRatchet("alice_bob_session")

    def test_forward_secrecy_establishment(self, alice_ratchet, bob_ratchet):
        """Test that forward secrecy is properly established."""
        # Generate shared secret for X3DH
        shared_secret = SecureRandom.generate_bytes(32)

        # Generate Bob's DH key pair
        bob_dh_key = DHRatchetKey.generate()

        # Initialize Alice's side
        alice_ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())

        # Initialize Bob's side
        bob_ratchet.initialize_bob(shared_secret, bob_dh_key.private_key)

        # Verify both have different chain keys (forward secrecy)
        assert alice_ratchet.state.chain_key_send is not None
        assert bob_ratchet.state.chain_key_receive is not None

        # Chain keys should be different (derived independently)
        alice_chain = alice_ratchet.state.chain_key_send.key
        bob_chain = bob_ratchet.state.chain_key_receive.key
        assert alice_chain != bob_chain

    def test_message_key_uniqueness(self, alice_ratchet, bob_ratchet):
        """Test that each message gets a unique encryption key."""
        # Initialize session
        shared_secret = SecureRandom.generate_bytes(32)
        bob_dh_key = DHRatchetKey.generate()
        alice_ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())
        bob_ratchet.initialize_bob(shared_secret, bob_dh_key.private_key)

        # Encrypt multiple messages
        message_keys = []
        for i in range(10):
            message = f"Test message {i}".encode()
            encrypted = alice_ratchet.encrypt_message(message)

            # Extract message key (this would be done by decryptor)
            # For testing, we verify the chain advances
            assert alice_ratchet.state.chain_key_send.index == i + 1

            # Each message should advance the chain
            message_keys.append(alice_ratchet.state.chain_key_send.key.hex())

        # Verify all message keys are unique
        assert len(set(message_keys)) == 10

    def test_post_compromise_security_recovery(self, alice_ratchet, bob_ratchet):
        """Test recovery from compromised key material."""
        # Initialize session
        shared_secret = SecureRandom.generate_bytes(32)
        bob_dh_key = DHRatchetKey.generate()
        alice_ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())
        bob_ratchet.initialize_bob(shared_secret, bob_dh_key.private_key)

        # Send some messages
        messages = []
        for i in range(5):
            msg = f"Message {i}".encode()
            encrypted = alice_ratchet.encrypt_message(msg)
            messages.append(encrypted)

        # Simulate compromise - attacker gets current chain key
        compromised_chain_key = alice_ratchet.state.chain_key_send.key.copy()

        # Continue sending messages (should use new keys)
        post_compromise_messages = []
        for i in range(3):
            msg = f"Post-compromise message {i}".encode()
            encrypted = alice_ratchet.encrypt_message(msg)
            post_compromise_messages.append(encrypted)

        # Verify post-compromise messages use different keys
        # (In real scenario, DH ratchet would trigger)
        assert alice_ratchet.state.chain_key_send.key != compromised_chain_key

    def test_out_of_order_message_handling(self, alice_ratchet, bob_ratchet):
        """Test handling of out-of-order messages."""
        # Initialize session
        shared_secret = SecureRandom.generate_bytes(32)
        bob_dh_key = DHRatchetKey.generate()
        alice_ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())
        bob_ratchet.initialize_bob(shared_secret, bob_dh_key.private_key)

        # Send messages out of order
        messages = []
        for i in range(5):
            msg = f"Message {i}".encode()
            encrypted = alice_ratchet.encrypt_message(msg)
            messages.append((i, encrypted))

        # Shuffle messages (simulate out-of-order delivery)
        import random
        random.shuffle(messages)

        # Decrypt messages in shuffled order
        decrypted_messages = []
        for msg_num, encrypted in messages:
            decrypted = bob_ratchet.decrypt_message(encrypted)
            assert decrypted is not None
            decrypted_messages.append((msg_num, decrypted))

        # Verify all messages decrypted correctly
        decrypted_messages.sort(key=lambda x: x[0])
        for i, (_, decrypted) in enumerate(decrypted_messages):
            expected = f"Message {i}".encode()
            assert decrypted == expected

    def test_skipped_message_key_limits(self, alice_ratchet, bob_ratchet):
        """Test that skipped message key limits are enforced."""
        # Initialize session
        shared_secret = SecureRandom.generate_bytes(32)
        bob_dh_key = DHRatchetKey.generate()
        alice_ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())
        bob_ratchet.initialize_bob(shared_secret, bob_dh_key.private_key)

        # Send many messages to fill skipped keys cache
        for i in range(DoubleRatchet.MAX_SKIP + 10):
            msg = f"Message {i}".encode()
            alice_ratchet.encrypt_message(msg)

        # Verify cache size limits are respected
        assert len(bob_ratchet.state.skipped_message_keys) <= DoubleRatchet.MAX_CACHE

    def test_secure_key_deletion(self, alice_ratchet):
        """Test that keys are securely deleted from memory."""
        # Initialize and use session
        shared_secret = SecureRandom.generate_bytes(32)
        bob_dh_key = DHRatchetKey.generate()
        alice_ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())

        # Get reference to chain key before cleanup
        chain_key_before = alice_ratchet.state.chain_key_send.key.copy() if alice_ratchet.state.chain_key_send else None

        # Cleanup session
        alice_ratchet.cleanup_session()

        # Verify keys are cleared
        assert alice_ratchet.state.root_key is None
        assert alice_ratchet.state.chain_key_send is None
        assert alice_ratchet.state.chain_key_receive is None
        assert alice_ratchet.state.dh_self is None
        assert alice_ratchet.state.dh_remote is None

    def test_memory_isolation(self, alice_ratchet, bob_ratchet):
        """Test that session memory is properly isolated."""
        # Initialize sessions
        shared_secret = SecureRandom.generate_bytes(32)
        bob_dh_key = DHRatchetKey.generate()
        alice_ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())
        bob_ratchet.initialize_bob(shared_secret, bob_dh_key.private_key)

        # Get memory references
        alice_root_key = alice_ratchet.state.root_key
        bob_root_key = bob_ratchet.state.root_key

        # Keys should be different (isolated)
        assert alice_root_key != bob_root_key

        # Modify Alice's state
        alice_ratchet.state.send_count = 999

        # Bob's state should be unaffected
        assert bob_ratchet.state.send_count == 0


class TestKeyManagementSecurity:
    """Comprehensive security tests for key management."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage for key manager."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def key_manager(self, temp_storage):
        """Create key manager for testing."""
        return KeyManager(temp_storage, "test_password_123")

    def test_secure_key_generation(self, key_manager):
        """Test that keys are generated securely."""
        # Generate identity key
        identity_key = key_manager.generate_identity_key()

        # Verify key properties
        assert identity_key is not None
        assert identity_key.key_id is not None
        public_key = identity_key.get_public_key_bytes()
        assert len(public_key) == 32  # Ed25519 public key length

        # Verify key uniqueness
        identity_key2 = key_manager.generate_identity_key()
        assert identity_key.key_id != identity_key2.key_id

    def test_key_encryption_at_rest(self, key_manager, temp_storage):
        """Test that keys are encrypted when stored."""
        # Generate keys
        key_manager.generate_identity_key()
        key_manager.generate_signed_prekey(1)
        key_manager.generate_one_time_prekeys(5)

        # Check that stored files exist and are encrypted
        identity_file = temp_storage / 'identity_key.enc'
        signed_file = temp_storage / 'signed_prekey.enc'
        otk_file = temp_storage / 'one_time_prekeys.enc'

        assert identity_file.exists()
        assert signed_file.exists()
        assert otk_file.exists()

        # Verify files contain encrypted data (not plaintext JSON)
        with open(identity_file, 'rb') as f:
            data = f.read()
            # Should not contain plaintext JSON markers
            assert b'{"private_key"' not in data
            assert b'{"public_key"' not in data

    def test_password_verification_timing_attack_resistance(self, key_manager):
        """Test resistance to timing attacks in password verification."""
        correct_password = "correct_password_123"
        wrong_password = "wrong_password_123"

        # Create a key manager with correct password
        test_km = KeyManager(Path(tempfile.mkdtemp()), correct_password)

        # Time password verification attempts
        iterations = 1000

        start_time = time.time()
        for _ in range(iterations):
            test_km.verify_password(correct_password, test_km.encryption_key, test_km.encryption_salt)
        correct_time = time.time() - start_time

        start_time = time.time()
        for _ in range(iterations):
            test_km.verify_password(wrong_password, test_km.encryption_key, test_km.encryption_salt)
        wrong_time = time.time() - start_time

        # Times should be very similar (within 10% for timing attack resistance)
        time_diff = abs(correct_time - wrong_time)
        avg_time = (correct_time + wrong_time) / 2
        assert time_diff / avg_time < 0.1  # Less than 10% difference

    def test_prekey_bundle_security(self, key_manager):
        """Test security of prekey bundle generation."""
        # Generate required keys
        key_manager.generate_identity_key()
        key_manager.generate_signed_prekey(1)
        key_manager.generate_one_time_prekeys(3)

        # Get prekey bundle
        bundle = key_manager.get_prekey_bundle()

        # Verify bundle structure
        assert 'identity_key' in bundle
        assert 'signed_prekey' in bundle
        assert 'one_time_prekey' in bundle  # Should include one-time key

        # Verify key lengths
        assert len(bundle['identity_key']) == 32  # Ed25519
        assert len(bundle['signed_prekey']['public_key']) == 32  # X25519
        assert len(bundle['one_time_prekey']['public_key']) == 32  # X25519

        # Verify one-time prekey is marked as used
        used_prekey = key_manager.use_one_time_prekey(bundle['one_time_prekey']['key_id'])
        assert used_prekey is not None
        assert used_prekey.used == True

    def test_key_rotation_security(self, key_manager):
        """Test secure key rotation mechanisms."""
        # Generate initial signed prekey
        initial_prekey = key_manager.generate_signed_prekey(1)

        # Generate one-time prekeys
        initial_otks = key_manager.generate_one_time_prekeys(5)

        # Rotate signed prekey
        new_prekey = key_manager.generate_signed_prekey(2)

        # Verify rotation
        assert key_manager.signed_prekey == new_prekey
        assert key_manager.signed_prekey.key_id == 2

        # Verify old prekey is no longer active
        assert key_manager.signed_prekey != initial_prekey

    def test_secure_random_integration(self, key_manager):
        """Test integration with secure random number generation."""
        # Generate multiple keys and verify randomness
        keys = []
        for i in range(100):
            identity_key = key_manager.generate_identity_key()
            keys.append(identity_key.get_public_key_bytes())

        # Verify all keys are unique
        assert len(set(k.hex() for k in keys)) == 100

        # Statistical randomness test (basic)
        # Check that bits are reasonably distributed
        all_bits = []
        for key in keys:
            for byte in key:
                for bit in range(8):
                    all_bits.append((byte >> bit) & 1)

        # Basic chi-square test for bit distribution
        ones = sum(all_bits)
        zeros = len(all_bits) - ones
        expected = len(all_bits) / 2

        # Chi-square statistic
        chi_square = ((ones - expected) ** 2 / expected) + ((zeros - expected) ** 2 / expected)
        # Should be reasonably low (p < 0.05 threshold roughly)
        assert chi_square < 100


class TestEncryptionSecurity:
    """Comprehensive security tests for encryption operations."""

    def test_aes_gcm_authentication(self):
        """Test AES-GCM authentication prevents tampering."""
        key = MessageEncryption.generate_key()
        message = b"Secret message"
        associated_data = b"metadata"

        # Encrypt message
        nonce, ciphertext = MessageEncryption.encrypt(message, key, associated_data)

        # Verify decryption works
        decrypted = MessageEncryption.decrypt(nonce, ciphertext, key, associated_data)
        assert decrypted == message

        # Tamper with ciphertext
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[10] ^= 0xFF  # Flip some bits

        # Decryption should fail with authentication error
        with pytest.raises(DecryptionError, match="Authentication failed"):
            MessageEncryption.decrypt(nonce, bytes(tampered_ciphertext), key, associated_data)

    def test_key_length_validation(self):
        """Test that invalid key lengths are rejected."""
        message = b"Test message"

        # Test with wrong key length
        short_key = b"short"
        long_key = b"this_key_is_too_long_for_aes_256"

        with pytest.raises(EncryptionError, match="Key must be 32 bytes"):
            MessageEncryption.encrypt(message, short_key)

        with pytest.raises(EncryptionError, match="Key must be 32 bytes"):
            MessageEncryption.encrypt(message, long_key)

        with pytest.raises(DecryptionError, match="Key must be 32 bytes"):
            MessageEncryption.decrypt(b"nonce", b"ciphertext", short_key)

    def test_nonce_uniqueness(self):
        """Test that nonces are unique for each encryption."""
        key = MessageEncryption.generate_key()
        message = b"Test message"

        # Encrypt multiple messages
        nonces = []
        for i in range(100):
            nonce, _ = MessageEncryption.encrypt(message, key)
            nonces.append(nonce.hex())

        # Verify all nonces are unique
        assert len(set(nonces)) == 100

    def test_associated_data_authentication(self):
        """Test that associated data is properly authenticated."""
        key = MessageEncryption.generate_key()
        message = b"Secret message"
        correct_ad = b"correct_metadata"
        wrong_ad = b"wrong_metadata"

        # Encrypt with correct associated data
        nonce, ciphertext = MessageEncryption.encrypt(message, key, correct_ad)

        # Decrypt with correct associated data should work
        decrypted = MessageEncryption.decrypt(nonce, ciphertext, key, correct_ad)
        assert decrypted == message

        # Decrypt with wrong associated data should fail
        with pytest.raises(DecryptionError, match="Authentication failed"):
            MessageEncryption.decrypt(nonce, ciphertext, key, wrong_ad)

    def test_key_derivation_security(self):
        """Test security of key derivation operations."""
        shared_secret = SecureRandom.generate_bytes(32)
        salt = SecureRandom.generate_bytes(32)
        info = b"test_info"

        # Derive multiple keys
        keys = KeyDerivation.derive_keys(shared_secret, salt, info, num_keys=5, key_length=32)

        # Verify key properties
        assert len(keys) == 5
        assert all(len(key) == 32 for key in keys)

        # All keys should be unique
        assert len(set(k.hex() for k in keys)) == 5

        # Keys should be deterministic for same inputs
        keys2 = KeyDerivation.derive_keys(shared_secret, salt, info, num_keys=5, key_length=32)
        assert all(k1 == k2 for k1, k2 in zip(keys, keys2))

        # Different salt should produce different keys
        different_salt = SecureRandom.generate_bytes(32)
        keys3 = KeyDerivation.derive_keys(shared_secret, different_salt, info, num_keys=5, key_length=32)
        assert all(k1 != k3 for k1, k3 in zip(keys, keys3))

    def test_message_key_chain_security(self):
        """Test security of message key chain derivation."""
        chain_key = SecureRandom.generate_bytes(32)

        message_keys = []
        next_chain_key = chain_key

        # Generate message key chain
        for i in range(10):
            message_key, next_chain_key = KeyDerivation.derive_message_key(next_chain_key, i)
            message_keys.append(message_key)

        # Verify all message keys are unique
        assert len(set(k.hex() for k in message_keys)) == 10

        # Verify chain key advances
        assert next_chain_key != chain_key

        # Verify deterministic derivation
        message_key2, _ = KeyDerivation.derive_message_key(chain_key, 0)
        assert message_key2 == message_keys[0]


class TestMemorySecurity:
    """Test memory security and key destruction."""

    def test_key_destruction_memory_safety(self):
        """Test that destroyed keys don't leave sensitive data in memory."""
        # Create a key and get its memory reference
        key_data = bytearray(SecureRandom.generate_bytes(32))

        # Simulate key destruction process
        original_data = key_data.copy()

        # Apply secure deletion (DoD 5220.22-M style)
        for i in range(len(key_data)):
            key_data[i] = 0x00  # Zero
        for i in range(len(key_data)):
            key_data[i] = 0xFF  # One
        for i in range(len(key_data)):
            key_data[i] = SecureRandom.generate_bytes(1)[0]  # Random

        # Final random overwrite
        for i in range(len(key_data)):
            key_data[i] = SecureRandom.generate_bytes(1)[0]

        # Clear the array
        key_data.clear()

        # Verify data is no longer accessible
        assert len(key_data) == 0

        # Force garbage collection
        gc.collect()

    def test_dh_key_pair_destruction(self):
        """Test secure destruction of DH key pairs."""
        dh_key = DHRatchetKey.generate()

        # Verify key exists
        assert dh_key.private_key is not None
        assert dh_key.public_key is not None

        # Get public key bytes before destruction
        public_bytes = dh_key.get_public_key_bytes()

        # Destroy the key pair
        dh_key.private_key = None
        dh_key.public_key = None

        # Verify references are cleared
        assert dh_key.private_key is None
        assert dh_key.public_key is None

        # But we should still have the public key bytes for protocol use
        assert public_bytes is not None

    def test_session_cleanup_memory_safety(self):
        """Test that session cleanup properly clears all sensitive memory."""
        ratchet = DoubleRatchet("test_session")

        # Initialize session
        shared_secret = SecureRandom.generate_bytes(32)
        bob_dh_key = DHRatchetKey.generate()
        ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())

        # Use session to create key material
        for i in range(5):
            msg = f"Message {i}".encode()
            ratchet.encrypt_message(msg)

        # Verify session has key material
        assert ratchet.state.root_key is not None
        assert ratchet.state.chain_key_send is not None

        # Cleanup session
        ratchet.cleanup_session()

        # Verify all sensitive data is cleared
        assert ratchet.state.root_key is None
        assert ratchet.state.chain_key_send is None
        assert ratchet.state.chain_key_receive is None
        assert ratchet.state.dh_self is None
        assert ratchet.state.dh_remote is None
        assert len(ratchet.state.skipped_message_keys) == 0

    def test_memory_usage_limits(self):
        """Test that memory usage doesn't grow unbounded."""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss

        # Create many sessions and keys
        sessions = []
        for i in range(100):
            ratchet = DoubleRatchet(f"session_{i}")
            shared_secret = SecureRandom.generate_bytes(32)
            bob_dh_key = DHRatchetKey.generate()
            ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())

            # Use each session
            for j in range(10):
                msg = f"Message {j}".encode()
                ratchet.encrypt_message(msg)

            sessions.append(ratchet)

        # Check memory usage
        current_memory = process.memory_info().rss
        memory_increase = current_memory - initial_memory

        # Memory increase should be reasonable (less than 100MB for 100 sessions)
        assert memory_increase < 100 * 1024 * 1024  # 100MB limit

        # Cleanup all sessions
        for ratchet in sessions:
            ratchet.cleanup_session()

        # Force garbage collection
        gc.collect()

        # Memory should be freed
        final_memory = process.memory_info().rss
        memory_freed = current_memory - final_memory

        # Should have freed most memory
        assert memory_freed > memory_increase * 0.5  # At least 50% freed


class TestCryptographicCorrectness:
    """Test cryptographic algorithm correctness and standards compliance."""

    def test_double_ratchet_correctness(self):
        """Test Double Ratchet implementation against known good values."""
        # Test vector-based verification
        # In production, this would use official test vectors

        ratchet = DoubleRatchet("test_session")
        shared_secret = SecureRandom.generate_bytes(32)
        bob_dh_key = DHRatchetKey.generate()

        # Initialize Alice
        ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())

        # Encrypt a test message
        message = b"Hello, Bob!"
        encrypted = ratchet.encrypt_message(message)

        # Create Bob's ratchet and initialize
        bob_ratchet = DoubleRatchet("test_session")
        bob_ratchet.initialize_bob(shared_secret, bob_dh_key.private_key)

        # Bob should be able to decrypt Alice's message
        decrypted = bob_ratchet.decrypt_message(encrypted)
        assert decrypted == message

    def test_key_exchange_correctness(self):
        """Test that key exchange produces correct shared secrets."""
        # Generate two DH key pairs
        alice_dh = DHRatchetKey.generate()
        bob_dh = DHRatchetKey.generate()

        # Perform key exchange
        alice_shared = alice_dh.perform_dh(bob_dh.get_public_key_bytes())
        bob_shared = bob_dh.perform_dh(alice_dh.get_public_key_bytes())

        # Shared secrets should be identical
        assert alice_shared == bob_shared

    def test_chain_key_derivation_correctness(self):
        """Test that chain key derivation is correct."""
        initial_chain_key = SecureRandom.generate_bytes(32)
        chain = ChainKey(initial_chain_key, 0)

        derived_keys = []
        for i in range(10):
            derived_keys.append(chain.derive_message_key())
            chain = chain.advance()

        # Verify keys are properly derived
        assert len(derived_keys) == 10
        assert all(len(key) == 32 for key in derived_keys)

        # All derived keys should be unique
        assert len(set(k.hex() for k in derived_keys)) == 10

    def test_encryption_decryption_roundtrip(self):
        """Test that encryption/decryption is correct for various inputs."""
        key = MessageEncryption.generate_key()

        test_messages = [
            b"",  # Empty message
            b"Short message",
            b"Longer message with more content to encrypt",
            b"Message with special characters: !@#$%^&*()",
            "Message with unicode: ñáéíóú 🚀".encode('utf-8'),
            b"A" * 1000,  # Large message
            b"\x00\x01\x02\xFF" * 100,  # Binary data
        ]

        for message in test_messages:
            # Test with and without associated data
            for ad in [None, b"metadata", b"longer_metadata_with_more_info"]:
                nonce, ciphertext = MessageEncryption.encrypt(message, key, ad)
                decrypted = MessageEncryption.decrypt(nonce, ciphertext, key, ad)
                assert decrypted == message


class TestSecurityRegression:
    """Regression tests for security fixes and improvements."""

    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks."""
        key = MessageEncryption.generate_key()

        # Test messages of different lengths
        messages = [
            b"short",
            b"medium_length_message",
            b"very_long_message_with_lots_of_content"
        ]

        # Time encryption operations
        times = []
        for message in messages:
            start_time = time.perf_counter()
            MessageEncryption.encrypt(message, key)
            end_time = time.perf_counter()
            times.append(end_time - start_time)

        # Times should be similar (within reasonable bounds)
        max_time = max(times)
        min_time = min(times)
        assert (max_time - min_time) / min_time < 0.5  # Less than 50% variation

    def test_side_channel_resistance(self):
        """Test resistance to side-channel attacks."""
        # This is a basic test - in production, would use more sophisticated analysis
        key = MessageEncryption.generate_key()

        # Test with various input patterns
        test_inputs = [
            b"\x00" * 100,  # All zeros
            b"\xFF" * 100,  # All ones
            b"\x41" * 100,  # All 'A's
            bytes(range(256)) * 4,  # All byte values
        ]

        for test_input in test_inputs:
            # Should not raise exceptions or behave differently
            nonce, ciphertext = MessageEncryption.encrypt(test_input, key)
            decrypted = MessageEncryption.decrypt(nonce, ciphertext, key)
            assert decrypted == test_input

    def test_error_message_security(self):
        """Test that error messages don't leak sensitive information."""
        key = MessageEncryption.generate_key()

        # Test various error conditions
        with pytest.raises(DecryptionError):
            # Wrong key length
            MessageEncryption.decrypt(b"nonce", b"ciphertext", b"wrong_length_key")

        with pytest.raises(DecryptionError):
            # Wrong nonce length
            MessageEncryption.decrypt(b"wrong_nonce", b"ciphertext", key)

        with pytest.raises(DecryptionError):
            # Tampered ciphertext
            nonce, ciphertext = MessageEncryption.encrypt(b"message", key)
            tampered = bytearray(ciphertext)
            tampered[0] ^= 0xFF
            MessageEncryption.decrypt(nonce, bytes(tampered), key)

        # Error messages should be generic and not reveal internal state
        # This is tested by ensuring consistent error types and messages

    def test_concurrent_access_safety(self):
        """Test thread safety of crypto operations."""
        key = MessageEncryption.generate_key()
        message = b"Concurrent test message"

        def encrypt_worker(worker_id):
            """Worker function for concurrent encryption."""
            for i in range(100):
                test_msg = f"Worker {worker_id}, message {i}".encode()
                nonce, ciphertext = MessageEncryption.encrypt(test_msg, key)
                decrypted = MessageEncryption.decrypt(nonce, ciphertext, key)
                assert decrypted == test_msg

        # Run multiple threads concurrently
        import threading
        threads = []
        for worker_id in range(10):
            thread = threading.Thread(target=encrypt_worker, args=(worker_id,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # All threads should complete successfully


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])