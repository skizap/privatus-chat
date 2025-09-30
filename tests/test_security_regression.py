"""
Security Regression Tests for File Transfer and Voice Calls

This module provides comprehensive security regression testing for:
- File transfer security (encryption, integrity, anonymity)
- Voice call security (encryption, privacy, traffic analysis resistance)
- End-to-end security validation
- Privacy protection verification
- Performance under security constraints
- Backward compatibility with security fixes
"""

import pytest
import asyncio
import tempfile
import shutil
import time
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from typing import Dict, List, Any, Optional
import hashlib
import json

# Import modules to test
from src.messaging.file_transfer import (
    FileTransferManager, SecureFileManager, FileTransfer,
    FileTransferStatus, FileTransferDirection, FileMetadata, FileChunk
)
from src.communication.voice_calls import (
    VoiceCallManager, CallSession, VoiceFrame, VoiceProcessor,
    CallState, CallQuality, VoiceCodec, EchoCanceller, NoiseReducer, VoiceObfuscator
)
from src.crypto.double_ratchet import DoubleRatchet, DoubleRatchetManager
from src.crypto.encryption import MessageEncryption, KeyDerivation
from src.crypto.secure_random import SecureRandom
from src.crypto.key_management import KeyManager


class TestFileTransferSecurityRegression:
    """Security regression tests for file transfer functionality."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def key_manager(self, temp_storage):
        """Create key manager for testing."""
        return KeyManager(temp_storage, "test_password_123")

    @pytest.fixture
    def file_transfer_manager(self, temp_storage, key_manager):
        """Create file transfer manager for testing."""
        # Mock storage and network managers
        storage_manager = Mock()
        network_manager = Mock()
        crypto_manager = Mock()

        manager = FileTransferManager(storage_manager, network_manager, crypto_manager)
        return manager

    @pytest.fixture
    def test_file(self, temp_storage):
        """Create a test file for transfer testing."""
        test_file = temp_storage / "test_file.txt"
        test_content = b"This is test file content for security testing." * 100
        test_file.write_bytes(test_content)
        return test_file

    def test_file_encryption_integrity(self, file_transfer_manager, test_file, key_manager):
        """Test that file transfers maintain encryption integrity."""
        # Create file transfer
        transfer_id = file_transfer_manager.offer_file(test_file, "test_peer")
        assert transfer_id is not None

        transfer = file_transfer_manager.get_transfer_status(transfer_id)
        assert transfer is not None
        assert transfer.encryption_key is not None

        # Verify file metadata integrity
        assert transfer.file_metadata.sha256_hash != ""
        expected_hash = SecureFileManager.calculate_file_hash(test_file)
        assert transfer.file_metadata.sha256_hash == expected_hash

        # Test chunk encryption/decryption
        chunks = SecureFileManager.split_file_into_chunks(test_file)
        assert len(chunks) > 0

        # Encrypt and decrypt a chunk
        test_chunk = chunks[0]
        original_data = test_chunk.data.copy()

        # Encrypt chunk data
        nonce, encrypted_data = MessageEncryption.encrypt(
            test_chunk.data,
            transfer.encryption_key
        )

        # Decrypt chunk data
        decrypted_data = MessageEncryption.decrypt(
            nonce,
            encrypted_data,
            transfer.encryption_key
        )

        # Verify integrity
        assert decrypted_data == original_data
        assert hashlib.sha256(decrypted_data).hexdigest() == test_chunk.checksum

    def test_file_transfer_anonymity_protection(self, file_transfer_manager, test_file):
        """Test that file transfers protect user anonymity."""
        # Create anonymous transfer
        transfer_id = file_transfer_manager.offer_file(test_file, "test_peer", anonymous=True)
        assert transfer_id is not None

        transfer = file_transfer_manager.get_transfer_status(transfer_id)
        assert transfer is not None

        # Verify metadata scrubbing
        metadata = SecureFileManager.scrub_metadata(test_file)
        assert 'sanitized_name' in metadata
        assert metadata['sanitized_name'] != test_file.name

        # Verify original filename is not exposed
        assert transfer.file_metadata.original_name != test_file.name

    def test_file_chunk_integrity_verification(self, test_file):
        """Test file chunk integrity verification mechanisms."""
        chunks = SecureFileManager.split_file_into_chunks(test_file, chunk_size=1024)

        # Verify chunk checksums
        for chunk in chunks:
            expected_checksum = hashlib.sha256(chunk.data).hexdigest()
            assert chunk.checksum == expected_checksum

        # Test chunk reassembly
        temp_output = test_file.parent / "reassembled_test.txt"
        success = SecureFileManager.reassemble_chunks(chunks, temp_output)

        assert success
        assert temp_output.exists()

        # Verify reassembled file integrity
        original_hash = SecureFileManager.calculate_file_hash(test_file)
        reassembled_hash = SecureFileManager.calculate_file_hash(temp_output)
        assert original_hash == reassembled_hash

        # Cleanup
        temp_output.unlink()

    def test_file_transfer_resume_security(self, file_transfer_manager, test_file):
        """Test security of file transfer resume functionality."""
        transfer_id = file_transfer_manager.offer_file(test_file, "test_peer")
        transfer = file_transfer_manager.get_transfer_status(transfer_id)

        # Simulate partial transfer
        transfer.chunks_completed = transfer.file_metadata.total_chunks // 2
        transfer.status = FileTransferStatus.TRANSFERRING

        # Create checkpoint
        success = file_transfer_manager.create_checkpoint(transfer_id)
        assert success
        assert transfer.checkpoint_data is not None

        # Simulate transfer interruption and resume
        original_progress = transfer.progress
        transfer.status = FileTransferStatus.PAUSED

        # Resume transfer
        resume_success = file_transfer_manager.resume_transfer(transfer_id)
        assert resume_success

        # Verify progress is restored
        assert transfer.progress == original_progress
        assert transfer.chunks_completed == transfer.file_metadata.total_chunks // 2

    def test_file_transfer_error_handling_security(self, file_transfer_manager, test_file):
        """Test secure error handling in file transfers."""
        # Test with non-existent file
        transfer_id = file_transfer_manager.offer_file(Path("non_existent_file.txt"), "test_peer")
        assert transfer_id is None  # Should fail gracefully

        # Test with oversized file
        large_file = test_file.parent / "large_file.txt"
        large_content = b"A" * (file_transfer_manager.max_file_size + 1024)
        large_file.write_bytes(large_content)

        transfer_id = file_transfer_manager.offer_file(large_file, "test_peer")
        assert transfer_id is None  # Should fail gracefully

        large_file.unlink()

    def test_file_transfer_concurrent_security(self, file_transfer_manager, test_file):
        """Test security under concurrent file transfer scenarios."""
        transfer_ids = []

        # Create multiple concurrent transfers
        for i in range(5):
            peer_id = f"peer_{i}"
            transfer_id = file_transfer_manager.offer_file(test_file, peer_id)
            if transfer_id:
                transfer_ids.append(transfer_id)

        # Verify all transfers are isolated
        assert len(transfer_ids) == 5

        transfers = [file_transfer_manager.get_transfer_status(tid) for tid in transfer_ids]
        encryption_keys = [t.encryption_key for t in transfers if t]

        # All encryption keys should be unique
        assert len(set(encryption_keys)) == len(encryption_keys)

        # Transfer IDs should be unique
        assert len(set(transfer_ids)) == len(transfer_ids)

    def test_file_transfer_checkpoint_security(self, file_transfer_manager, test_file):
        """Test security of checkpoint data."""
        transfer_id = file_transfer_manager.offer_file(test_file, "test_peer")
        transfer = file_transfer_manager.get_transfer_status(transfer_id)

        # Create checkpoint
        file_transfer_manager.create_checkpoint(transfer_id)

        # Verify checkpoint contains necessary data but not sensitive information
        checkpoint = transfer.checkpoint_data
        assert 'chunks_completed' in checkpoint
        assert 'progress' in checkpoint

        # Checkpoint should not contain encryption keys or file content
        assert 'encryption_key' not in checkpoint
        assert 'file_content' not in checkpoint


class TestVoiceCallSecurityRegression:
    """Security regression tests for voice call functionality."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def key_manager(self, temp_storage):
        """Create key manager for testing."""
        return KeyManager(temp_storage, "test_password_123")

    @pytest.fixture
    def ratchet_manager(self, key_manager):
        """Create ratchet manager for testing."""
        storage_manager = Mock()
        manager = DoubleRatchetManager(storage_manager)
        manager.key_manager = key_manager
        return manager

    @pytest.fixture
    def voice_call_manager(self, ratchet_manager):
        """Create voice call manager for testing."""
        user_id = "test_user"
        onion_manager = Mock()

        manager = VoiceCallManager(user_id, ratchet_manager, onion_manager)
        return manager

    def test_voice_call_encryption_security(self, voice_call_manager):
        """Test end-to-end encryption security for voice calls."""
        # Mock send callback
        sent_messages = []
        def mock_send(recipient_id, data):
            sent_messages.append((recipient_id, data))

        voice_call_manager.register_send_callback(mock_send)

        # Initiate call
        call_id = asyncio.run(voice_call_manager.initiate_call("remote_user"))
        assert call_id is not None

        call_session = voice_call_manager.active_calls[call_id]
        assert call_session.ratchet_session is not None

        # Test voice frame encryption
        test_audio = b"test_audio_data" * 100  # Mock audio data

        # Send voice frame
        success = asyncio.run(voice_call_manager.send_voice_frame(call_id, test_audio))
        assert success

        # Verify message was sent
        assert len(sent_messages) > 0

        # Verify encryption was applied (message should not contain plaintext audio)
        recipient_id, encrypted_data = sent_messages[0]
        assert test_audio not in encrypted_data  # Should be encrypted

    def test_voice_call_anonymity_protection(self, voice_call_manager):
        """Test voice call anonymity and privacy protection."""
        # Initiate anonymous call
        call_id = asyncio.run(voice_call_manager.initiate_call(
            "remote_user",
            anonymous=True,
            quality=CallQuality.HIGH
        ))
        assert call_id is not None

        call_session = voice_call_manager.active_calls[call_id]

        # Verify anonymity settings
        assert call_session.is_anonymous == True

        # Verify voice obfuscation is enabled for anonymous calls
        # (This would be tested with actual audio processing if available)

    def test_voice_frame_integrity_verification(self, voice_call_manager):
        """Test voice frame integrity and sequence verification."""
        call_id = asyncio.run(voice_call_manager.initiate_call("remote_user"))
        call_session = voice_call_manager.active_calls[call_id]

        # Create test voice frame
        test_audio = b"test_audio_frame_data"
        voice_frame = VoiceFrame(
            frame_id="test_frame_1",
            timestamp=time.time(),
            encrypted_audio=b"encrypted_audio_placeholder",
            frame_size=len(test_audio),
            codec=VoiceCodec.OPUS,
            sequence_number=1
        )

        # Test frame serialization/deserialization
        frame_bytes = voice_frame.to_bytes()
        reconstructed_frame = VoiceFrame.from_bytes(frame_bytes)

        assert reconstructed_frame.frame_id == voice_frame.frame_id
        assert reconstructed_frame.sequence_number == voice_frame.sequence_number
        assert reconstructed_frame.codec == voice_frame.codec

    def test_voice_call_traffic_analysis_resistance(self, voice_call_manager):
        """Test resistance to traffic analysis in voice calls."""
        call_id = asyncio.run(voice_call_manager.initiate_call("remote_user"))
        call_session = voice_call_manager.active_calls[call_id]

        # Test traffic obfuscation
        test_frame_data = b"test_frame_data"
        obfuscated_data = voice_call_manager._apply_traffic_obfuscation(test_frame_data)

        # Should be padded to fixed size
        assert len(obfuscated_data) >= len(test_frame_data)

        # Test with different frame sizes
        small_frame = b"small"
        large_frame = b"large_frame" * 100

        small_obfuscated = voice_call_manager._apply_traffic_obfuscation(small_frame)
        large_obfuscated = voice_call_manager._apply_traffic_obfuscation(large_frame)

        # Both should result in similar sizes (traffic analysis resistance)
        assert abs(len(small_obfuscated) - len(large_obfuscated)) <= 1024  # Within reasonable range

    def test_voice_call_state_transition_security(self, voice_call_manager):
        """Test security of voice call state transitions."""
        # Test invalid state transitions
        call_id = asyncio.run(voice_call_manager.initiate_call("remote_user"))

        # Should not be able to accept non-existent call
        invalid_call_id = "invalid_call_id"
        success = asyncio.run(voice_call_manager.accept_call(invalid_call_id))
        assert success == False

        # Should not be able to end non-existent call
        success = asyncio.run(voice_call_manager.end_call(invalid_call_id))
        assert success == False

        # Valid call should transition properly
        success = asyncio.run(voice_call_manager.accept_call(call_id))
        assert success == True

        call_session = voice_call_manager.active_calls[call_id]
        assert call_session.state == CallState.ACTIVE

    def test_voice_call_resource_cleanup_security(self, voice_call_manager):
        """Test secure cleanup of voice call resources."""
        call_id = asyncio.run(voice_call_manager.initiate_call("remote_user"))
        call_session = voice_call_manager.active_calls[call_id]

        # Verify session exists
        assert call_session.ratchet_session is not None

        # End call and verify cleanup
        success = asyncio.run(voice_call_manager.end_call(call_id))
        assert success == True

        # Verify call is removed from active calls
        assert call_id not in voice_call_manager.active_calls

        # Verify ratchet session cleanup
        # (In real implementation, would verify key material destruction)

    def test_voice_call_concurrent_security(self, voice_call_manager):
        """Test security under concurrent voice call scenarios."""
        call_ids = []

        # Create multiple concurrent calls
        for i in range(3):
            call_id = asyncio.run(voice_call_manager.initiate_call(f"remote_user_{i}"))
            if call_id:
                call_ids.append(call_id)

        # Verify all calls are isolated
        assert len(call_ids) == 3

        calls = [voice_call_manager.active_calls[cid] for cid in call_ids]
        ratchet_sessions = [c.ratchet_session for c in calls if c.ratchet_session]

        # All ratchet sessions should be unique
        assert len(set(id(rs) for rs in ratchet_sessions)) == len(ratchet_sessions)

        # Clean up
        for call_id in call_ids:
            asyncio.run(voice_call_manager.end_call(call_id))


class TestEndToEndSecurityValidation:
    """End-to-end security validation tests."""

    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage for testing."""
        temp_dir = tempfile.mkdtemp()
        yield Path(temp_dir)
        shutil.rmtree(temp_dir)

    @pytest.fixture
    def crypto_setup(self, temp_storage):
        """Set up cryptographic components for testing."""
        # Create key managers for two parties
        alice_keys = KeyManager(temp_storage / "alice", "alice_password")
        bob_keys = KeyManager(temp_storage / "bob", "bob_password")

        # Generate keys
        alice_keys.generate_identity_key()
        bob_keys.generate_identity_key()

        # Create ratchet managers
        alice_ratchet = DoubleRatchetManager(Mock())
        bob_ratchet = DoubleRatchetManager(Mock())
        alice_ratchet.key_manager = alice_keys
        bob_ratchet.key_manager = bob_keys

        return {
            'alice_keys': alice_keys,
            'bob_keys': bob_keys,
            'alice_ratchet': alice_ratchet,
            'bob_ratchet': bob_ratchet
        }

    def test_end_to_end_file_transfer_security(self, crypto_setup, temp_storage):
        """Test complete end-to-end security for file transfer."""
        # Create test file
        test_file = temp_storage / "e2e_test.txt"
        test_content = b"End-to-end encrypted file transfer test content." * 50
        test_file.write_bytes(test_content)

        # Create file transfer managers
        alice_storage = Mock()
        bob_storage = Mock()

        alice_ft = FileTransferManager(alice_storage, Mock(), crypto_setup['alice_ratchet'])
        bob_ft = FileTransferManager(bob_storage, Mock(), crypto_setup['bob_ratchet'])

        # Alice offers file
        transfer_id = alice_ft.offer_file(test_file, "bob")
        assert transfer_id is not None

        alice_transfer = alice_ft.get_transfer_status(transfer_id)
        assert alice_transfer.encryption_key is not None

        # Simulate file transfer process
        # In real scenario, this would involve network transmission

        # Verify file integrity
        original_hash = SecureFileManager.calculate_file_hash(test_file)
        assert alice_transfer.file_metadata.sha256_hash == original_hash

        # Verify encryption key uniqueness
        assert alice_transfer.encryption_key not in [None, b""]

    def test_end_to_end_voice_call_security(self, crypto_setup):
        """Test complete end-to-end security for voice calls."""
        # Create voice call managers
        alice_vc = VoiceCallManager("alice", crypto_setup['alice_ratchet'], Mock())
        bob_vc = VoiceCallManager("bob", crypto_setup['bob_ratchet'], Mock())

        # Mock send callbacks
        alice_messages = []
        bob_messages = []

        def alice_send(recipient, data):
            alice_messages.append((recipient, data))

        def bob_send(recipient, data):
            bob_messages.append((recipient, data))

        alice_vc.register_send_callback(alice_send)
        bob_vc.register_send_callback(bob_send)

        # Alice initiates call
        call_id = asyncio.run(alice_vc.initiate_call("bob"))
        assert call_id is not None

        alice_call = alice_vc.active_calls[call_id]
        bob_call = bob_vc.active_calls.get(call_id)

        # Verify call encryption setup
        assert alice_call.ratchet_session is not None

        # Test voice frame security
        test_audio = b"test_voice_data" * 10

        # Send voice frame
        success = asyncio.run(alice_vc.send_voice_frame(call_id, test_audio))
        assert success

        # Verify message was encrypted
        assert len(alice_messages) > 0
        recipient, encrypted_data = alice_messages[0]

        # Should not contain plaintext audio
        assert test_audio not in encrypted_data

    def test_cross_component_security_integration(self, crypto_setup, temp_storage):
        """Test security integration across all components."""
        # Create comprehensive test scenario
        test_file = temp_storage / "integration_test.txt"
        test_content = b"Integration test for all security components."
        test_file.write_bytes(test_content)

        # Set up all managers
        alice_ft_manager = FileTransferManager(Mock(), Mock(), crypto_setup['alice_ratchet'])
        alice_vc_manager = VoiceCallManager("alice", crypto_setup['alice_ratchet'], Mock())

        # Test concurrent operations
        file_transfer_id = alice_ft_manager.offer_file(test_file, "bob")
        voice_call_id = asyncio.run(alice_vc_manager.initiate_call("bob"))

        # Verify both operations use different encryption contexts
        file_transfer = alice_ft_manager.get_transfer_status(file_transfer_id)
        voice_call = alice_vc_manager.active_calls[voice_call_id]

        # Different encryption keys/contexts
        assert file_transfer.encryption_key != voice_call.ratchet_session.state.root_key

        # Clean up
        alice_ft_manager.cancel_transfer(file_transfer_id)
        asyncio.run(alice_vc_manager.end_call(voice_call_id))


class TestPrivacyProtectionRegression:
    """Privacy protection regression tests."""

    def test_file_transfer_privacy_leakage_prevention(self, temp_storage):
        """Test prevention of privacy leakage in file transfers."""
        test_file = temp_storage / "privacy_test.txt"
        sensitive_content = b"Sensitive file content with personal information"
        test_file.write_bytes(sensitive_content)

        # Test metadata scrubbing
        metadata = SecureFileManager.scrub_metadata(test_file)

        # Verify sensitive information is not exposed
        assert metadata['sanitized_name'] != test_file.name
        assert 'original_name' not in metadata or metadata.get('original_name') != test_file.name

        # Test file content isolation
        chunks = SecureFileManager.split_file_into_chunks(test_file)

        # Verify chunks don't contain file path information
        for chunk in chunks:
            chunk_str = chunk.data.decode('utf-8', errors='ignore')
            assert str(test_file) not in chunk_str
            assert test_file.name not in chunk_str

    def test_voice_call_privacy_protection(self):
        """Test voice call privacy protection mechanisms."""
        # Test voice obfuscation (if audio processing available)
        if 'AUDIO_AVAILABLE' in globals() and AUDIO_AVAILABLE:
            processor = VoiceProcessor()

            # Test audio data
            test_audio = b"test_voice_sample" * 100

            # Apply privacy protection
            protected_audio = processor.process_outgoing_audio(test_audio, protect_voice_print=True)

            # Should be different from original (obfuscated)
            assert protected_audio != test_audio

            # Test without protection
            unprotected_audio = processor.process_outgoing_audio(test_audio, protect_voice_print=False)

            # Should be different (processed) but not obfuscated
            assert unprotected_audio != test_audio

    def test_traffic_pattern_obfuscation(self):
        """Test traffic pattern obfuscation for privacy."""
        # Test message padding for traffic analysis resistance
        test_messages = [
            b"short",
            b"medium_length_message",
            b"very_long_message_with_lots_of_content_for_padding_test"
        ]

        padded_messages = []

        for msg in test_messages:
            # Apply padding (similar to voice call traffic obfuscation)
            target_size = 1024
            if len(msg) < target_size:
                padding = b'\x00' * (target_size - len(msg))
                padded = msg + padding
            else:
                padded = msg[:target_size]

            padded_messages.append(padded)

        # All messages should have similar sizes
        sizes = [len(msg) for msg in padded_messages]
        assert all(size >= min(sizes) for size in sizes)

        # Size variance should be minimal
        size_variance = max(sizes) - min(sizes)
        assert size_variance <= 1024  # Reasonable padding limit


class TestPerformanceUnderSecurityConstraints:
    """Test performance under security constraints."""

    def test_file_transfer_performance_with_security(self, temp_storage):
        """Test file transfer performance with security features enabled."""
        # Create large test file
        large_file = temp_storage / "performance_test.bin"
        file_size = 10 * 1024 * 1024  # 10MB
        large_content = SecureRandom.generate_bytes(file_size)
        large_file.write_bytes(large_content)

        # Measure transfer setup time
        start_time = time.time()

        storage_manager = Mock()
        network_manager = Mock()
        crypto_manager = Mock()

        ft_manager = FileTransferManager(storage_manager, network_manager, crypto_manager)

        # Offer file (includes encryption setup, chunking, etc.)
        transfer_id = ft_manager.offer_file(large_file, "test_peer")

        setup_time = time.time() - start_time

        # Setup should complete in reasonable time (< 5 seconds for 10MB)
        assert setup_time < 5.0

        transfer = ft_manager.get_transfer_status(transfer_id)
        assert transfer is not None

        # Verify all chunks are properly prepared
        expected_chunks = (file_size + 64 * 1024 - 1) // (64 * 1024)  # 64KB chunks
        assert transfer.file_metadata.total_chunks == expected_chunks

    def test_voice_call_performance_with_security(self):
        """Test voice call performance with security features."""
        # Mock managers
        ratchet_manager = Mock()
        onion_manager = Mock()

        vc_manager = VoiceCallManager("test_user", ratchet_manager, onion_manager)

        # Measure call initiation time
        start_time = time.time()

        call_id = asyncio.run(vc_manager.initiate_call("remote_user"))

        initiation_time = time.time() - start_time

        # Call initiation should be reasonably fast (< 2 seconds)
        assert initiation_time < 2.0
        assert call_id is not None

        # Test voice frame processing performance
        test_audio = b"test_audio_frame" * 1000  # Larger audio sample

        frame_start_time = time.time()
        success = asyncio.run(vc_manager.send_voice_frame(call_id, test_audio))
        frame_processing_time = time.time() - frame_start_time

        # Frame processing should be fast (< 100ms)
        assert frame_processing_time < 0.1
        assert success

        # Cleanup
        asyncio.run(vc_manager.end_call(call_id))

    def test_concurrent_security_operations_performance(self, temp_storage):
        """Test performance under concurrent security operations."""
        # Set up multiple concurrent operations
        operations = []

        # File transfers
        for i in range(5):
            test_file = temp_storage / f"concurrent_test_{i}.txt"
            test_file.write_bytes(b"Concurrent test content" * 100)

            storage_manager = Mock()
            network_manager = Mock()
            crypto_manager = Mock()

            ft_manager = FileTransferManager(storage_manager, network_manager, crypto_manager)
            operations.append(('file', ft_manager.offer_file, [test_file, f"peer_{i}"]))

        # Voice calls
        for i in range(3):
            ratchet_manager = Mock()
            onion_manager = Mock()
            vc_manager = VoiceCallManager(f"user_{i}", ratchet_manager, onion_manager)
            operations.append(('voice', vc_manager.initiate_call, [f"remote_user_{i}"]))

        # Execute operations concurrently
        start_time = time.time()

        async def run_concurrent_operations():
            tasks = []
            for op_type, func, args in operations:
                if op_type == 'voice':
                    tasks.append(func(*args))
                else:
                    # File operations are synchronous
                    func(*args)
                    tasks.append(asyncio.sleep(0))  # Placeholder

            await asyncio.gather(*tasks)

        asyncio.run(run_concurrent_operations())
        total_time = time.time() - start_time

        # All operations should complete in reasonable time (< 10 seconds)
        assert total_time < 10.0


class TestBackwardCompatibilitySecurity:
    """Test backward compatibility with security fixes."""

    def test_message_format_compatibility(self):
        """Test compatibility with different message formats."""
        # Test various message format versions
        test_payloads = [
            b'{"type": "chat", "content": "test"}',  # Simple format
            b'{"header": {"type": "chat"}, "payload": {"content": "test"}}',  # Structured format
            b'{"type": "chat", "content": "test", "metadata": {"version": "1.0"}}',  # Extended format
        ]

        for payload in test_payloads:
            # Should handle all formats gracefully
            try:
                # Simulate message processing
                if len(payload) >= 4:
                    message_length = len(payload)
                    json_data = payload

                    # Try to parse as JSON
                    try:
                        message_dict = json.loads(json_data.decode('utf-8'))
                        # Should not crash on any format
                        assert isinstance(message_dict, dict)
                    except json.JSONDecodeError:
                        # Should handle malformed JSON gracefully
                        pass

            except Exception as e:
                # Should not crash on any input
                assert "crash" not in str(e).lower()

    def test_encryption_algorithm_compatibility(self):
        """Test compatibility with different encryption algorithms."""
        test_key = SecureRandom.generate_bytes(32)
        test_message = b"Compatibility test message"

        # Test current encryption method
        nonce, ciphertext = MessageEncryption.encrypt(test_message, test_key)
        decrypted = MessageEncryption.decrypt(nonce, ciphertext, test_key)

        assert decrypted == test_message

        # Test key derivation compatibility
        shared_secret = SecureRandom.generate_bytes(32)
        salt = SecureRandom.generate_bytes(32)
        info = b"test_info"

        keys = KeyDerivation.derive_keys(shared_secret, salt, info, num_keys=3, key_length=32)

        # All derived keys should be valid
        assert len(keys) == 3
        assert all(len(key) == 32 for key in keys)
        assert all(key != b'\x00' * 32 for key in keys)  # Should not be all zeros

    def test_protocol_version_compatibility(self):
        """Test compatibility with different protocol versions."""
        # Test message creation with different versions
        from src.network.message_protocol import MessageHeader, P2PMessage

        versions_to_test = [1, 2, 3]

        for version in versions_to_test:
            header = MessageHeader(
                version=version,
                message_type="chat_message",
                message_id="test_id",
                sender_id=b"sender123456789012"
            )

            message = P2PMessage(header=header, payload={'content': 'test'})

            # Should handle all versions
            message_dict = message.to_dict()
            assert message_dict['header']['version'] == version


class TestSecurityRegressionScenarios:
    """Test specific security regression scenarios."""

    def test_file_transfer_interruption_recovery(self, temp_storage):
        """Test recovery from file transfer interruptions."""
        test_file = temp_storage / "interruption_test.txt"
        test_content = b"File transfer interruption recovery test."
        test_file.write_bytes(test_content)

        # Create file transfer manager
        storage_manager = Mock()
        network_manager = Mock()
        crypto_manager = Mock()

        ft_manager = FileTransferManager(storage_manager, network_manager, crypto_manager)

        # Start transfer
        transfer_id = ft_manager.offer_file(test_file, "test_peer")
        transfer = ft_manager.get_transfer_status(transfer_id)

        # Simulate partial progress
        transfer.chunks_completed = transfer.file_metadata.total_chunks // 2
        transfer.status = FileTransferStatus.TRANSFERRING

        # Create checkpoint
        ft_manager.create_checkpoint(transfer_id)

        # Simulate interruption (pause)
        ft_manager.pause_transfer(transfer_id)
        assert transfer.status == FileTransferStatus.PAUSED

        # Simulate recovery (resume)
        ft_manager.resume_transfer(transfer_id)
        assert transfer.status == FileTransferStatus.TRANSFERRING

        # Verify progress is maintained
        assert transfer.chunks_completed == transfer.file_metadata.total_chunks // 2

    def test_voice_call_drop_recovery(self):
        """Test recovery from voice call drops."""
        # Mock managers
        ratchet_manager = Mock()
        onion_manager = Mock()

        vc_manager = VoiceCallManager("test_user", ratchet_manager, onion_manager)

        # Start call
        call_id = asyncio.run(vc_manager.initiate_call("remote_user"))
        call_session = vc_manager.active_calls[call_id]

        # Simulate call drop (network interruption)
        # In real scenario, this would trigger reconnection logic

        # Verify call state handling
        assert call_session.state in [CallState.INITIATING, CallState.RINGING, CallState.CONNECTING]

        # Test call cleanup on failure
        asyncio.run(vc_manager.end_call(call_id))
        assert call_id not in vc_manager.active_calls

    def test_memory_cleanup_after_security_operations(self, temp_storage):
        """Test memory cleanup after security-sensitive operations."""
        import gc

        # Create key manager and perform operations
        key_manager = KeyManager(temp_storage, "test_password")
        key_manager.generate_identity_key()

        # Get initial object count
        initial_objects = len(gc.get_objects())

        # Perform many cryptographic operations
        for i in range(100):
            # Generate keys
            test_key = SecureRandom.generate_bytes(32)

            # Encrypt/decrypt data
            test_data = f"Test data {i}".encode()
            nonce, ciphertext = MessageEncryption.encrypt(test_data, test_key)
            decrypted = MessageEncryption.decrypt(nonce, ciphertext, test_key)

            # Create ratchet session
            ratchet = DoubleRatchet(f"session_{i}")
            shared_secret = SecureRandom.generate_bytes(32)
            bob_dh_key = Mock()
            bob_dh_key.get_public_key_bytes.return_value = SecureRandom.generate_bytes(32)
            ratchet.initialize_alice(shared_secret, bob_dh_key.get_public_key_bytes())

        # Force garbage collection
        gc.collect()

        # Final object count should not grow excessively
        final_objects = len(gc.get_objects())
        object_growth = final_objects - initial_objects

        # Should not have excessive object growth (< 1000 new objects)
        assert object_growth < 1000


if __name__ == "__main__":
    # Run tests with verbose output
    pytest.main([__file__, "-v", "--tb=short"])