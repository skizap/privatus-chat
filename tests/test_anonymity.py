"""
Anonymity Infrastructure Tests for Privatus-chat
Week 4: Anonymous Messaging and Onion Routing

Test suite for the anonymity components including onion routing, traffic analysis
resistance, anonymous identity management, and privacy controls.
"""

import pytest
import pytest_asyncio
import asyncio
import time
from unittest.mock import Mock, patch

from src.crypto.key_management import KeyManager
from src.crypto.secure_random import SecureRandom
from src.anonymity.onion_routing import (
    OnionRoutingManager, OnionRelay, OnionCircuit, CircuitState, RelayType, CircuitHop
)
from src.anonymity.traffic_analysis import (
    TrafficAnalysisResistance, MessagePadder, TimingObfuscator, 
    DummyTrafficGenerator, TrafficPattern
)
from src.anonymity.anonymous_identity import (
    AnonymousIdentityManager, AnonymousIdentity, IdentityType, IdentityCredential
)
from src.anonymity.privacy_controls import (
    PrivacyController, PrivacySettings, PrivacyLevel, AnonymityStatus
)

class TestOnionRouting:
    """Test onion routing functionality"""
    
    @pytest_asyncio.fixture
    async def onion_manager(self):
        """Create onion routing manager for testing"""
        node_id = SecureRandom().generate_bytes(20)
        key_manager = KeyManager()
        await key_manager.initialize()

        manager = OnionRoutingManager(node_id, key_manager)
        await manager.start()
        yield manager
        await manager.stop()
    
    def test_onion_relay_creation(self):
        """Test onion relay creation and properties"""
        node_id = SecureRandom().generate_bytes(20)
        public_key = SecureRandom().generate_bytes(32)
        
        relay = OnionRelay(
            node_id=node_id,
            address="127.0.0.1",
            port=8000,
            public_key=public_key,
            relay_type=RelayType.ENTRY,
            reputation=0.9,
            uptime=86400
        )
        
        assert relay.node_id == node_id
        assert relay.address == "127.0.0.1"
        assert relay.port == 8000
        assert relay.relay_type == RelayType.ENTRY
        assert relay.is_suitable_for_type(RelayType.ENTRY)
        assert relay.is_suitable_for_type(RelayType.EXIT)  # Has sufficient uptime and reputation
    
    def test_circuit_creation_and_properties(self):
        """Test circuit creation and property checking"""
        # Create mock hops
        hops = []
        for i in range(3):
            relay = OnionRelay(
                node_id=SecureRandom().generate_bytes(20),
                address=f"127.0.0.{i+1}",
                port=8000 + i,
                public_key=SecureRandom().generate_bytes(32),
                relay_type=RelayType.ENTRY
            )
            hop = CircuitHop(relay=relay, circuit_key=SecureRandom().generate_bytes(32))
            hops.append(hop)
        
        circuit = OnionCircuit(circuit_id=1, hops=hops)
        
        assert circuit.circuit_id == 1
        assert len(circuit.hops) == 3
        assert circuit.state == CircuitState.BUILDING
        assert not circuit.is_established
        assert not circuit.is_expired
        
        # Test circuit establishment
        circuit.state = CircuitState.ESTABLISHED
        assert circuit.is_established
        
        # Test usage tracking
        circuit.update_usage(bytes_sent=1024, bytes_received=512)
        assert circuit.bytes_sent == 1024
        assert circuit.bytes_received == 512
        assert circuit.usage_count == 1
    
    @pytest.mark.asyncio
    async def test_relay_management(self, onion_manager):
        """Test relay addition and management"""
        # Add a relay
        relay = OnionRelay(
            node_id=SecureRandom().generate_bytes(20),
            address="127.0.0.1",
            port=8000,
            public_key=SecureRandom().generate_bytes(32),
            relay_type=RelayType.ENTRY,
            reputation=0.8,
            uptime=86400
        )
        
        onion_manager.add_relay(relay)
        
        assert relay.node_id in onion_manager.known_relays
        assert relay in onion_manager.relay_selection_pool
    
    @pytest.mark.asyncio
    async def test_circuit_building_insufficient_relays(self, onion_manager):
        """Test circuit building with insufficient relays"""
        # Try to build circuit without enough relays
        circuit = await onion_manager.build_circuit()
        assert circuit is None
    
    @pytest.mark.asyncio
    async def test_circuit_statistics(self, onion_manager):
        """Test circuit statistics collection"""
        stats = onion_manager.get_circuit_statistics()
        
        assert 'total_circuits_built' in stats
        assert 'active_circuits' in stats
        assert 'failed_circuits' in stats
        assert 'total_messages_sent' in stats
        assert 'known_relays' in stats
        assert 'circuit_success_rate' in stats
        
        assert stats['total_circuits_built'] >= 0
        assert stats['active_circuits'] >= 0

class TestTrafficAnalysisResistance:
    """Test traffic analysis resistance functionality"""
    
    @pytest.fixture
    def message_padder(self):
        """Create message padder for testing"""
        return MessagePadder()
    
    @pytest.fixture
    def timing_obfuscator(self):
        """Create timing obfuscator for testing"""
        return TimingObfuscator()
    
    @pytest.fixture
    def traffic_resistance(self):
        """Create traffic analysis resistance for testing"""
        def mock_callback(message, msg_type):
            pass
        return TrafficAnalysisResistance(mock_callback)
    
    def test_message_padding(self, message_padder):
        """Test message padding functionality"""
        # Test various message sizes
        test_messages = [
            b"short",
            b"medium length message",
            b"this is a much longer message that should be padded appropriately"
        ]
        
        for msg in test_messages:
            padded = message_padder.pad_message(msg)
            
            # Padded message should be larger or equal
            assert len(padded) >= len(msg)
            
            # Should be padded to standard size (including 4-byte length prefix)
            expected_sizes = [size + 4 for size in message_padder.padding_sizes] + [message_padder.max_padding_size + 4]
            assert len(padded) in expected_sizes
    
    def test_timing_obfuscation(self, timing_obfuscator):
        """Test timing obfuscation calculations"""
        # Test different urgency levels
        immediate_delay = timing_obfuscator.get_send_delay(512, "immediate")
        normal_delay = timing_obfuscator.get_send_delay(512, "normal")
        low_delay = timing_obfuscator.get_send_delay(512, "low")
        
        assert immediate_delay == 0.0
        assert normal_delay > 0
        assert low_delay > normal_delay
        
        # Test size influence
        small_delay = timing_obfuscator.get_send_delay(100, "normal")
        large_delay = timing_obfuscator.get_send_delay(2000, "normal")
        
        # Larger messages may have different delays
        assert isinstance(small_delay, float)
        assert isinstance(large_delay, float)
    
    @pytest.mark.asyncio
    async def test_traffic_resistance_start_stop(self, traffic_resistance):
        """Test traffic analysis resistance start and stop"""
        await traffic_resistance.start()
        assert traffic_resistance.running
        
        await traffic_resistance.stop()
        assert not traffic_resistance.running
    
    @pytest.mark.asyncio
    async def test_protected_message_sending(self, traffic_resistance):
        """Test sending messages with protection"""
        await traffic_resistance.start()
        
        # Send a test message
        test_message = b"test message for protection"
        result = await traffic_resistance.send_message_with_protection(test_message)
        
        assert result is True
        
        # Check that traffic event was recorded
        assert len(traffic_resistance.traffic_events) > 0
        event = traffic_resistance.traffic_events[-1]
        assert event.direction == "send"
        assert not event.is_dummy
        
        await traffic_resistance.stop()
    
    def test_traffic_statistics(self, traffic_resistance):
        """Test traffic statistics collection"""
        stats = traffic_resistance.get_traffic_statistics()
        
        assert 'total_events' in stats
        assert 'real_messages' in stats
        assert 'dummy_messages' in stats
        assert 'total_bytes' in stats
        assert 'protection_efficiency' in stats
        
        assert stats['total_events'] >= 0
        assert stats['protection_efficiency'] >= 0.0
    
    def test_protection_configuration(self, traffic_resistance):
        """Test protection configuration"""
        traffic_resistance.configure_protection(
            padding=True,
            timing=True,
            cover_traffic=True,
            cover_pattern=TrafficPattern.BURST
        )
        
        assert traffic_resistance.padding_enabled
        assert traffic_resistance.timing_obfuscation_enabled
        assert traffic_resistance.cover_traffic_enabled
        assert traffic_resistance.cover_traffic_pattern == TrafficPattern.BURST

class TestAnonymousIdentityManagement:
    """Test anonymous identity management"""
    
    @pytest_asyncio.fixture
    async def identity_manager(self):
        """Create identity manager for testing"""
        key_manager = KeyManager()
        await key_manager.initialize()

        manager = AnonymousIdentityManager(key_manager)
        return manager
    
    def test_identity_creation(self, identity_manager):
        """Test identity creation"""
        identity = identity_manager.create_identity(
            IdentityType.PERSISTENT,
            nickname="TestUser"
        )
        
        assert identity.identity_type == IdentityType.PERSISTENT
        assert identity.nickname == "TestUser"
        assert len(identity.identity_id) == 32  # SHA-256 hash
        assert len(identity.public_key) > 0
        assert len(identity.private_key) > 0
        assert identity.reputation_score == 1.0
        
        # Check that identity was stored
        assert identity.identity_id in identity_manager.identities
        assert identity.identity_id in identity_manager.reputation_scores
    
    def test_identity_types_and_expiration(self, identity_manager):
        """Test different identity types and their expiration behavior"""
        # Create different types
        persistent = identity_manager.create_identity(IdentityType.PERSISTENT)
        ephemeral = identity_manager.create_identity(IdentityType.EPHEMERAL)
        disposable = identity_manager.create_identity(IdentityType.DISPOSABLE)
        
        # Check initial expiration status
        assert not persistent.is_expired
        assert not ephemeral.is_expired
        assert not disposable.is_expired
        
        # Test disposable expiration after use
        disposable.update_usage()
        assert disposable.is_expired
    
    def test_identity_rotation(self, identity_manager):
        """Test identity rotation"""
        original = identity_manager.create_identity(IdentityType.PERSISTENT)
        original_id = original.identity_id
        
        # Set up reputation
        identity_manager.update_reputation(original_id, 1.5)
        original_reputation = identity_manager.get_reputation_score(original_id)
        
        # Rotate identity
        new_identity = identity_manager.rotate_identity(original_id, preserve_reputation=True)
        
        assert new_identity is not None
        assert new_identity.identity_id != original_id
        assert new_identity.identity_type == original.identity_type
        
        # Check reputation preservation
        new_reputation = identity_manager.get_reputation_score(new_identity.identity_id)
        assert new_reputation == original_reputation
    
    def test_context_identity_management(self, identity_manager):
        """Test context-based identity management"""
        # Get identity for conversation
        conv_id = "test_conversation_123"
        identity1 = identity_manager.get_identity_for_conversation(conv_id)
        identity2 = identity_manager.get_identity_for_conversation(conv_id)
        
        # Should return same identity for same conversation
        assert identity1.identity_id == identity2.identity_id
        
        # Should be ephemeral type
        assert identity1.identity_type == IdentityType.EPHEMERAL
        
        # Check context mapping
        retrieved = identity_manager.get_identity_by_context(conv_id)
        assert retrieved.identity_id == identity1.identity_id
    
    def test_credential_system(self, identity_manager):
        """Test anonymous credential system"""
        identity = identity_manager.create_identity(IdentityType.PERSISTENT)
        
        # Issue credential
        attributes = {"role": "verified_user", "level": 2}
        credential = identity_manager.issue_credential(
            identity.identity_id,
            attributes,
            validity_hours=24
        )
        
        assert credential is not None
        assert credential.identity_id == identity.identity_id
        assert credential.attributes == attributes
        assert credential.is_valid
        
        # Verify credential
        is_valid = identity_manager.verify_credential(credential.credential_id)
        assert is_valid
        
        # Test invalid credential
        fake_credential_id = SecureRandom().generate_bytes(32)
        is_valid = identity_manager.verify_credential(fake_credential_id)
        assert not is_valid
    
    def test_reputation_system(self, identity_manager):
        """Test reputation system"""
        identity = identity_manager.create_identity(IdentityType.PERSISTENT)
        identity_id = identity.identity_id
        
        # Initial reputation should be 1.0
        assert identity_manager.get_reputation_score(identity_id) == 1.0
        
        # Update reputation positively
        identity_manager.update_reputation(identity_id, 1.5)
        score = identity_manager.get_reputation_score(identity_id)
        assert score > 1.0
        
        # Update reputation negatively
        identity_manager.update_reputation(identity_id, 0.5)
        new_score = identity_manager.get_reputation_score(identity_id)
        assert new_score < score
        
        # Check history
        assert identity_id in identity_manager.reputation_history
        assert len(identity_manager.reputation_history[identity_id]) > 0
    
    def test_identity_statistics(self, identity_manager):
        """Test identity statistics"""
        # Create some identities
        identity_manager.create_identity(IdentityType.PERSISTENT)
        identity_manager.create_identity(IdentityType.EPHEMERAL)
        identity_manager.create_identity(IdentityType.DISPOSABLE)
        
        stats = identity_manager.get_identity_statistics()
        
        assert 'total_identities_created' in stats
        assert 'active_identities' in stats
        assert 'identities_by_type' in stats
        assert 'issued_credentials' in stats
        
        assert stats['total_identities_created'] == 3
        assert stats['active_identities'] == 3
        assert stats['identities_by_type']['persistent'] == 1
        assert stats['identities_by_type']['ephemeral'] == 1
        assert stats['identities_by_type']['disposable'] == 1

class TestPrivacyControls:
    """Test privacy controls and audit system"""
    
    @pytest_asyncio.fixture
    async def privacy_controller(self):
        """Create privacy controller for testing"""
        # Create mock components
        key_manager = KeyManager()
        await key_manager.initialize()

        onion_manager = Mock()
        onion_manager.get_circuit_statistics.return_value = {
            'active_circuits': 2,
            'total_circuits_built': 5,
            'failed_circuits': 1
        }

        traffic_resistance = Mock()
        traffic_resistance.get_traffic_statistics.return_value = {
            'total_events': 100,
            'protection_efficiency': 0.8
        }
        traffic_resistance.analyze_traffic_patterns.return_value = {
            'analysis': 'complete',
            'vulnerability_score': 0.3,
            'recommendations': ['Enable timing randomization']
        }

        identity_manager = Mock()
        identity_manager.get_identity_statistics.return_value = {
            'total_identities_created': 3,
            'identity_rotations': 1
        }

        controller = PrivacyController(
            onion_manager=onion_manager,
            traffic_resistance=traffic_resistance,
            identity_manager=identity_manager
        )

        return controller
    
    def test_privacy_level_configuration(self, privacy_controller):
        """Test privacy level configuration"""
        # Test minimal level
        privacy_controller.configure_privacy_level(PrivacyLevel.MINIMAL)
        settings = privacy_controller.settings
        
        assert settings.privacy_level == PrivacyLevel.MINIMAL
        assert not settings.use_anonymous_identities
        assert not settings.use_onion_routing
        assert not settings.message_padding
        
        # Test maximum level
        privacy_controller.configure_privacy_level(PrivacyLevel.MAXIMUM)
        settings = privacy_controller.settings
        
        assert settings.privacy_level == PrivacyLevel.MAXIMUM
        assert settings.use_anonymous_identities
        assert settings.use_onion_routing
        assert settings.message_padding
        assert settings.timing_obfuscation
        assert settings.dummy_traffic
    
    def test_anonymity_status_updates(self, privacy_controller):
        """Test anonymity status updates"""
        status_changes = []
        
        def status_callback(status):
            status_changes.append(status)
        
        privacy_controller.register_status_callback(status_callback)
        
        # Configure different levels and check status changes
        privacy_controller.configure_privacy_level(PrivacyLevel.MINIMAL)
        privacy_controller.configure_privacy_level(PrivacyLevel.STANDARD)
        privacy_controller.configure_privacy_level(PrivacyLevel.HIGH)
        
        # Should have received status change notifications
        assert len(status_changes) > 0
    
    def test_privacy_audit(self, privacy_controller):
        """Test privacy audit functionality"""
        # Configure for good privacy
        privacy_controller.configure_privacy_level(PrivacyLevel.HIGH)
        
        audit_result = privacy_controller.perform_privacy_audit()
        
        assert isinstance(audit_result.overall_score, float)
        assert 0.0 <= audit_result.overall_score <= 1.0
        assert audit_result.anonymity_level in AnonymityStatus
        assert isinstance(audit_result.vulnerabilities, list)
        assert isinstance(audit_result.recommendations, list)
        assert isinstance(audit_result.protection_details, dict)
    
    def test_privacy_recommendations(self, privacy_controller):
        """Test privacy recommendations"""
        # Configure minimal privacy to generate recommendations
        privacy_controller.configure_privacy_level(PrivacyLevel.MINIMAL)
        
        recommendations = privacy_controller.get_privacy_recommendations()
        
        assert isinstance(recommendations, list)
        assert len(recommendations) <= 5  # Should be limited
        assert all(isinstance(rec, str) for rec in recommendations)
    
    def test_privacy_status_reporting(self, privacy_controller):
        """Test privacy status reporting"""
        status = privacy_controller.get_privacy_status()
        
        assert 'privacy_level' in status
        assert 'anonymity_status' in status
        assert 'timestamp' in status
        assert 'protections_active' in status
        
        protections = status['protections_active']
        assert 'anonymous_identities' in protections
        assert 'onion_routing' in protections
        assert 'message_padding' in protections
    
    def test_settings_export_import(self, privacy_controller):
        """Test settings export and import"""
        # Configure specific settings
        privacy_controller.configure_privacy_level(PrivacyLevel.HIGH)
        
        # Export settings
        exported = privacy_controller.export_privacy_settings()
        
        assert 'privacy_level' in exported
        assert exported['privacy_level'] == 'high'
        assert 'use_onion_routing' in exported
        assert 'message_padding' in exported
        
        # Change settings
        privacy_controller.configure_privacy_level(PrivacyLevel.MINIMAL)
        
        # Import back
        success = privacy_controller.import_privacy_settings(exported)
        assert success
        
        # Verify settings were restored
        assert privacy_controller.settings.privacy_level == PrivacyLevel.HIGH
    
    def test_privacy_metrics(self, privacy_controller):
        """Test privacy metrics collection"""
        metrics = privacy_controller.get_privacy_metrics()
        
        assert 'current_privacy_level' in metrics
        assert 'current_anonymity_status' in metrics
        assert 'privacy_events_24h' in metrics
        assert 'privacy_score' in metrics
        
        assert isinstance(metrics['privacy_score'], float)
        assert 0.0 <= metrics['privacy_score'] <= 1.0

class TestAnonymityIntegration:
    """Integration tests for anonymity components"""
    
    @pytest.mark.asyncio
    async def test_full_anonymity_stack_initialization(self):
        """Test initializing the complete anonymity stack"""
        # Create components
        node_id = SecureRandom().generate_bytes(20)
        key_manager = KeyManager()
        await key_manager.initialize()
        
        onion_manager = OnionRoutingManager(node_id, key_manager)
        
        def mock_send_callback(message, msg_type):
            pass
        
        traffic_resistance = TrafficAnalysisResistance(mock_send_callback)
        identity_manager = AnonymousIdentityManager(key_manager)
        
        privacy_controller = PrivacyController(
            onion_manager=onion_manager,
            traffic_resistance=traffic_resistance,
            identity_manager=identity_manager
        )
        
        # Start all components
        await onion_manager.start()
        await traffic_resistance.start()
        await privacy_controller.start()
        
        # Verify all components are running
        assert onion_manager.running
        assert traffic_resistance.running
        assert privacy_controller is not None
        
        # Test integrated functionality
        privacy_controller.configure_privacy_level(PrivacyLevel.HIGH)
        audit = privacy_controller.perform_privacy_audit()
        
        assert audit.overall_score >= 0.0
        
        # Clean shutdown
        await privacy_controller.stop()
        await traffic_resistance.stop()
        await onion_manager.stop()
        
        assert not onion_manager.running
        assert not traffic_resistance.running
    
    @pytest.mark.asyncio
    async def test_anonymous_message_flow(self):
        """Test complete anonymous message flow"""
        # Setup minimal components for message flow
        key_manager = KeyManager()
        await key_manager.initialize()
        
        identity_manager = AnonymousIdentityManager(key_manager)
        
        # Create identity for conversation
        identity = identity_manager.get_identity_for_conversation("test_conv")
        
        # Create message with traffic protection
        messages_sent = []
        
        def capture_message(message, msg_type):
            messages_sent.append((message, msg_type))
        
        traffic_resistance = TrafficAnalysisResistance(capture_message)
        await traffic_resistance.start()
        
        # Send protected message
        test_message = b"Anonymous test message"
        success = await traffic_resistance.send_message_with_protection(test_message)
        
        assert success
        assert len(messages_sent) > 0
        
        # Verify message was padded
        sent_message, msg_type = messages_sent[0]
        assert len(sent_message) >= len(test_message)
        assert msg_type == "real"
        
        # Update identity reputation
        identity_manager.update_reputation(identity.identity_id, 1.2)
        reputation = identity_manager.get_reputation_score(identity.identity_id)
        assert reputation > 1.0
        
        await traffic_resistance.stop()

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 