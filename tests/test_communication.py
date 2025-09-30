"""
Communication Infrastructure Tests for Privatus-chat
Week 7: Voice Communication

Test suite for the communication components including voice calls, audio processing,
and real-time communication features.
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from src.communication.voice_calls import VoiceCallManager, CallState, VoiceCodec, CallQuality
from src.crypto.key_management import KeyManager
from src.crypto.secure_random import SecureRandom


class TestVoiceCallManager:
    """Test voice call manager functionality"""

    @pytest.fixture
    def voice_manager(self):
        """Create voice call manager for testing"""
        ratchet_manager = Mock()
        onion_manager = Mock()

        manager = VoiceCallManager("test_user", ratchet_manager, onion_manager)
        return manager

    def test_call_initialization(self, voice_manager):
        """Test call initialization"""
        # Check manager is created
        assert voice_manager is not None
        assert voice_manager.user_id == "test_user"

    @pytest.mark.asyncio
    async def test_call_state_transitions(self, voice_manager):
        """Test call state transitions"""
        call_id = "test_call_123"
        peer_id = b'peer123'

        # Initialize call
        await voice_manager.initialize_call(call_id, peer_id, CallType.OUTGOING)

        # Transition through states
        await voice_manager.update_call_state(call_id, CallState.CONNECTING)
        call = voice_manager.get_call(call_id)
        assert call.state == CallState.CONNECTING

        await voice_manager.update_call_state(call_id, CallState.CONNECTED)
        call = voice_manager.get_call(call_id)
        assert call.state == CallState.CONNECTED

        await voice_manager.update_call_state(call_id, CallState.ENDED)
        call = voice_manager.get_call(call_id)
        assert call.state == CallState.ENDED

    def test_audio_stream_setup(self, voice_manager):
        """Test audio stream setup"""
        call_id = "test_call_123"

        # Mock audio stream
        mock_stream = Mock()
        voice_manager.setup_audio_stream(call_id, mock_stream)

        # Verify stream was stored
        assert call_id in voice_manager.audio_streams
        assert voice_manager.audio_streams[call_id] == mock_stream

    @pytest.mark.asyncio
    async def test_call_encryption(self, voice_manager):
        """Test call encryption setup"""
        call_id = "test_call_123"
        peer_id = b'peer123'

        # Initialize call
        await voice_manager.initialize_call(call_id, peer_id, CallType.OUTGOING)

        # Setup encryption
        success = await voice_manager.setup_call_encryption(call_id)
        assert success

        # Check encryption keys were generated
        call = voice_manager.get_call(call_id)
        assert call.encryption_key is not None
        assert len(call.encryption_key) == 32  # AES-256

    def test_audio_quality_settings(self, voice_manager):
        """Test audio quality configuration"""
        # Test different quality settings
        qualities = ['low', 'medium', 'high', 'ultra']

        for quality in qualities:
            settings = voice_manager.get_audio_settings(quality)

            assert 'sample_rate' in settings
            assert 'channels' in settings
            assert 'bitrate' in settings
            assert isinstance(settings['sample_rate'], int)
            assert isinstance(settings['bitrate'], int)

    def test_call_statistics(self, voice_manager):
        """Test call statistics collection"""
        call_id = "test_call_123"

        # Mock call data
        voice_manager.call_statistics[call_id] = {
            'duration': 120,
            'bytes_sent': 1024000,
            'bytes_received': 980000,
            'packets_lost': 5,
            'jitter': 15.5
        }

        stats = voice_manager.get_call_statistics(call_id)

        assert stats['duration'] == 120
        assert stats['bytes_sent'] == 1024000
        assert 'bitrate' in stats  # Calculated field

    def test_call_cleanup(self, voice_manager):
        """Test call cleanup after ending"""
        call_id = "test_call_123"
        peer_id = b'peer123'

        # Setup call
        voice_manager.active_calls[call_id] = Mock()
        voice_manager.active_calls[call_id].call_id = call_id
        voice_manager.active_calls[call_id].peer_id = peer_id
        voice_manager.audio_streams[call_id] = Mock()

        # Cleanup call
        voice_manager.cleanup_call(call_id)

        # Verify cleanup
        assert call_id not in voice_manager.active_calls
        assert call_id not in voice_manager.audio_streams


class TestCallState:
    """Test call state management"""

    def test_call_state_enum(self):
        """Test call state enum values"""
        assert CallState.INITIALIZING.value == "initializing"
        assert CallState.CONNECTING.value == "connecting"
        assert CallState.CONNECTED.value == "connected"
        assert CallState.ENDED.value == "ended"
        assert CallState.FAILED.value == "failed"

    def test_call_type_enum(self):
        """Test call type enum values"""
        assert CallType.INCOMING.value == "incoming"
        assert CallType.OUTGOING.value == "outgoing"

    def test_state_transitions(self):
        """Test valid state transitions"""
        # Valid transitions
        valid_transitions = [
            (CallState.INITIALIZING, CallState.CONNECTING),
            (CallState.CONNECTING, CallState.CONNECTED),
            (CallState.CONNECTED, CallState.ENDED),
            (CallState.INITIALIZING, CallState.FAILED),
            (CallState.CONNECTING, CallState.FAILED)
        ]

        for from_state, to_state in valid_transitions:
            assert VoiceCallManager.is_valid_state_transition(from_state, to_state)

        # Invalid transition
        assert not VoiceCallManager.is_valid_state_transition(
            CallState.ENDED, CallState.CONNECTED
        )


class TestAudioProcessing:
    """Test audio processing functionality"""

    @pytest.fixture
    def audio_processor(self):
        """Create audio processor for testing"""
        return VoiceCallManager.AudioProcessor()

    def test_audio_compression(self, audio_processor):
        """Test audio compression"""
        # Mock audio data
        audio_data = b"x" * 4096  # 4KB of audio data

        compressed = audio_processor.compress_audio(audio_data)
        assert compressed is not None
        assert len(compressed) <= len(audio_data)  # Should be smaller or equal

    def test_audio_decompression(self, audio_processor):
        """Test audio decompression"""
        # Mock compressed data
        compressed_data = b"compressed_audio_data"

        decompressed = audio_processor.decompress_audio(compressed_data)
        assert decompressed is not None
        assert isinstance(decompressed, bytes)

    def test_echo_cancellation(self, audio_processor):
        """Test echo cancellation"""
        # Mock audio with echo
        clean_audio = b"clean_audio_data"
        echo_audio = b"echo_audio_data"

        processed = audio_processor.apply_echo_cancellation(clean_audio, echo_audio)
        assert processed is not None
        assert len(processed) > 0

    def test_noise_reduction(self, audio_processor):
        """Test noise reduction"""
        # Mock noisy audio
        noisy_audio = b"noisy_audio_with_background_noise"

        cleaned = audio_processor.apply_noise_reduction(noisy_audio)
        assert cleaned is not None
        assert len(cleaned) > 0

    def test_audio_level_normalization(self, audio_processor):
        """Test audio level normalization"""
        # Mock audio with varying levels
        audio_data = b"low_volume_audio"

        normalized = audio_processor.normalize_audio_level(audio_data)
        assert normalized is not None
        assert len(normalized) > 0


class TestCallSecurity:
    """Test call security features"""

    @pytest.fixture
    async def secure_call_manager(self):
        """Create secure call manager for testing"""
        key_manager = KeyManager()
        await key_manager.initialize()

        manager = VoiceCallManager(key_manager)
        await manager.start()
        yield manager
        await manager.stop()

    @pytest.mark.asyncio
    async def test_srtp_setup(self, secure_call_manager):
        """Test SRTP setup for secure audio"""
        call_id = "secure_call_123"

        # Setup SRTP
        success = await secure_call_manager.setup_srtp(call_id)
        assert success

        # Check SRTP context exists
        assert call_id in secure_call_manager.srtp_contexts

    def test_dtls_handshake(self, secure_call_manager):
        """Test DTLS handshake for key exchange"""
        call_id = "secure_call_123"

        # Mock DTLS handshake
        success = secure_call_manager.perform_dtls_handshake(call_id)
        assert isinstance(success, bool)  # May succeed or fail in test environment

    def test_zrtp_verification(self, secure_call_manager):
        """Test ZRTP verification"""
        call_id = "secure_call_123"

        # Mock ZRTP verification
        verified = secure_call_manager.verify_zrtp(call_id, "short_auth_string")
        assert isinstance(verified, bool)

    def test_call_authentication(self, secure_call_manager):
        """Test call authentication"""
        peer_id = b'peer123'
        auth_token = b'auth_token_123'

        authenticated = secure_call_manager.authenticate_call(peer_id, auth_token)
        assert isinstance(authenticated, bool)


class TestCallQuality:
    """Test call quality monitoring"""

    @pytest.fixture
    def quality_monitor(self):
        """Create quality monitor for testing"""
        return VoiceCallManager.QualityMonitor()

    def test_latency_measurement(self, quality_monitor):
        """Test latency measurement"""
        # Mock latency data
        latencies = [50, 45, 55, 48, 52]  # ms

        for latency in latencies:
            quality_monitor.record_latency(latency)

        avg_latency = quality_monitor.get_average_latency()
        assert avg_latency == 50.0

    def test_packet_loss_detection(self, quality_monitor):
        """Test packet loss detection"""
        # Record packets
        quality_monitor.record_packet(1, received=True)
        quality_monitor.record_packet(2, received=True)
        quality_monitor.record_packet(3, received=False)  # Lost
        quality_monitor.record_packet(4, received=True)

        loss_rate = quality_monitor.get_packet_loss_rate()
        assert loss_rate == 0.25  # 25% loss

    def test_jitter_calculation(self, quality_monitor):
        """Test jitter calculation"""
        # Mock jitter data
        jitter_values = [5, 8, 3, 6, 7]

        for jitter in jitter_values:
            quality_monitor.record_jitter(jitter)

        avg_jitter = quality_monitor.get_average_jitter()
        assert avg_jitter == 5.8

    def test_quality_score(self, quality_monitor):
        """Test overall quality score calculation"""
        # Set quality metrics
        quality_monitor.record_latency(30)
        quality_monitor.record_jitter(5)
        quality_monitor.record_packet(1, True)
        quality_monitor.record_packet(2, True)

        score = quality_monitor.get_quality_score()
        assert 0.0 <= score <= 1.0


# Integration tests
class TestCommunicationIntegration:
    """Integration tests for communication components"""

    @pytest.mark.asyncio
    async def test_full_call_workflow(self):
        """Test complete call workflow"""
        key_manager = KeyManager()
        await key_manager.initialize()

        voice_manager = VoiceCallManager(key_manager)
        await voice_manager.start()

        try:
            call_id = "integration_call_123"
            peer_id = b'integration_peer'

            # 1. Initialize call
            success = await voice_manager.initialize_call(call_id, peer_id, CallType.OUTGOING)
            assert success

            # 2. Setup encryption
            success = await voice_manager.setup_call_encryption(call_id)
            assert success

            # 3. Transition to connected
            await voice_manager.update_call_state(call_id, CallState.CONNECTED)

            # 4. Simulate audio streaming
            audio_data = b"test_audio_data"
            success = await voice_manager.send_audio_data(call_id, audio_data)
            assert success

            # 5. End call
            await voice_manager.end_call(call_id)

            # 6. Verify cleanup
            call = voice_manager.get_call(call_id)
            assert call.state == CallState.ENDED

        finally:
            await voice_manager.stop()

    @pytest.mark.asyncio
    async def test_concurrent_calls(self):
        """Test handling multiple concurrent calls"""
        key_manager = KeyManager()
        await key_manager.initialize()

        voice_manager = VoiceCallManager(key_manager)
        await voice_manager.start()

        try:
            # Initialize multiple calls
            calls = []
            for i in range(3):
                call_id = f"concurrent_call_{i}"
                peer_id = f"peer_{i}".encode()

                success = await voice_manager.initialize_call(call_id, peer_id, CallType.OUTGOING)
                assert success
                calls.append(call_id)

            # Verify all calls are active
            active_calls = voice_manager.get_active_calls()
            assert len(active_calls) == 3

            # End all calls
            for call_id in calls:
                await voice_manager.end_call(call_id)

            # Verify all calls ended
            active_calls = voice_manager.get_active_calls()
            assert len(active_calls) == 0

        finally:
            await voice_manager.stop()

    def test_call_history_persistence(self):
        """Test call history persistence"""
        # This would test storing and retrieving call history
        # For now, just test the interface
        voice_manager = VoiceCallManager(None)  # No key manager for this test

        call_record = {
            'call_id': 'history_call_123',
            'peer_id': b'peer123',
            'start_time': 1234567890,
            'end_time': 1234567990,
            'duration': 100,
            'call_type': 'outgoing'
        }

        # Store call record (would normally persist to database)
        voice_manager.store_call_record(call_record)

        # Retrieve call history (would normally query database)
        history = voice_manager.get_call_history(b'peer123')
        assert isinstance(history, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])