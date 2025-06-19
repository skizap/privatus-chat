#!/usr/bin/env python3
"""
Week 4 Anonymity and Onion Routing Demo for Privatus-chat

This script demonstrates the complete anonymity infrastructure implemented
in Week 4, including onion routing, traffic analysis resistance, anonymous
identity management, and privacy controls.

Features Demonstrated:
- Onion routing circuit construction and management
- Traffic analysis resistance with padding and timing obfuscation
- Anonymous identity management with reputation system
- Privacy controls and audit system
- Integration between all anonymity components

Usage:
    python examples/week4_anonymity_demo.py
"""

import asyncio
import logging
import sys
import os
from pathlib import Path

# Add the src directory to the path so we can import our modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from crypto.key_management import KeyManager
from crypto.secure_random import SecureRandom
from anonymity.onion_routing import OnionRoutingManager, OnionRelay, RelayType
from anonymity.traffic_analysis import TrafficAnalysisResistance, TrafficPattern
from anonymity.anonymous_identity import AnonymousIdentityManager, IdentityType
from anonymity.privacy_controls import PrivacyController, PrivacyLevel, AnonymityStatus

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('week4_anonymity_demo.log')
    ]
)

logger = logging.getLogger(__name__)

class AnonymityDemo:
    """Demonstration of Week 4 anonymity features"""
    
    def __init__(self):
        self.node_id = SecureRandom().generate_bytes(20)
        self.key_manager = KeyManager(Path("demo_keys"))
        
        # Initialize anonymity components
        self.onion_manager = None
        self.traffic_resistance = None
        self.identity_manager = None
        self.privacy_controller = None
        
        # Demo message counter
        self.messages_sent = 0
        
    async def initialize_components(self):
        """Initialize all anonymity components"""
        logger.info("Initializing anonymity components...")
        
        # Key manager is already initialized in constructor
        
        # Create onion routing manager
        self.onion_manager = OnionRoutingManager(self.node_id, self.key_manager)
        
        # Create traffic analysis resistance
        self.traffic_resistance = TrafficAnalysisResistance(self._send_message_callback)
        
        # Create anonymous identity manager
        self.identity_manager = AnonymousIdentityManager(self.key_manager)
        
        # Create privacy controller
        self.privacy_controller = PrivacyController(
            onion_manager=self.onion_manager,
            traffic_resistance=self.traffic_resistance,
            identity_manager=self.identity_manager
        )
        
        # Register for anonymity status updates
        self.privacy_controller.register_status_callback(self._on_anonymity_status_change)
        
        # Generate required keys for demo
        if not self.key_manager.identity_key:
            self.key_manager.generate_identity_key()
        if not self.key_manager.signed_prekey:
            self.key_manager.generate_signed_prekey(1)
        
        logger.info("Anonymity components initialized successfully")
    
    def _send_message_callback(self, message: bytes, message_type: str):
        """Callback for sending messages through the network"""
        self.messages_sent += 1
        logger.debug(f"Sending {message_type} message ({len(message)} bytes) - Total: {self.messages_sent}")
    
    def _on_anonymity_status_change(self, status: AnonymityStatus):
        """Callback for anonymity status changes"""
        logger.info(f"Anonymity status changed to: {status.value}")
    
    async def start_components(self):
        """Start all anonymity components"""
        logger.info("Starting anonymity components...")
        
        await self.onion_manager.start()
        await self.traffic_resistance.start()
        await self.privacy_controller.start()
        
        logger.info("All anonymity components started")
    
    async def stop_components(self):
        """Stop all anonymity components"""
        logger.info("Stopping anonymity components...")
        
        await self.privacy_controller.stop()
        await self.traffic_resistance.stop()
        await self.onion_manager.stop()
        
        logger.info("All anonymity components stopped")
    
    async def demo_onion_routing(self):
        """Demonstrate onion routing functionality"""
        logger.info("=== Onion Routing Demo ===")
        
        # Add some mock relays for demonstration
        await self._add_mock_relays()
        
        # Build a circuit
        logger.info("Building onion routing circuit...")
        circuit = await self.onion_manager.build_circuit()
        
        if circuit:
            logger.info(f"Successfully built circuit {circuit.circuit_id}")
            logger.info(f"Circuit hops: {len(circuit.hops)}")
            
            # Send a message through the circuit
            test_message = {"content": "Hello from onion routing!", "timestamp": "2024-01-01T12:00:00Z"}
            destination = SecureRandom().generate_bytes(20)
            
            success = await self.onion_manager.send_message_through_circuit(
                circuit, destination, test_message
            )
            
            if success:
                logger.info("Message sent successfully through onion circuit")
            else:
                logger.error("Failed to send message through onion circuit")
                
            # Show circuit statistics
            stats = self.onion_manager.get_circuit_statistics()
            logger.info(f"Onion routing statistics: {stats}")
            
        else:
            logger.error("Failed to build onion routing circuit")
    
    async def _add_mock_relays(self):
        """Add mock relays for demonstration purposes"""
        logger.info("Adding mock relays for demonstration...")
        
        # Create mock relays
        for i in range(5):
            node_id = SecureRandom().generate_bytes(20)
            public_key = SecureRandom().generate_bytes(32)
            
            relay = OnionRelay(
                node_id=node_id,
                address=f"127.0.0.{i+1}",
                port=8000 + i,
                public_key=public_key,
                relay_type=RelayType.ENTRY if i < 2 else RelayType.MIDDLE if i < 4 else RelayType.EXIT,
                reputation=0.8 + (i * 0.05),
                uptime=86400,  # 24 hours
                bandwidth=1000000  # 1MB/s
            )
            
            self.onion_manager.add_relay(relay)
        
        logger.info("Added 5 mock relays to the network")
    
    async def demo_traffic_analysis_resistance(self):
        """Demonstrate traffic analysis resistance"""
        logger.info("=== Traffic Analysis Resistance Demo ===")
        
        # Configure different protection levels
        logger.info("Testing message padding...")
        test_messages = [
            b"Short message",
            b"This is a medium length message for testing",
            b"This is a much longer message that will be padded to the next size category for traffic analysis resistance"
        ]
        
        for msg in test_messages:
            padded = self.traffic_resistance.padder.pad_message(msg)
            logger.info(f"Original: {len(msg)} bytes -> Padded: {len(padded)} bytes")
        
        # Test timing obfuscation
        logger.info("Testing timing obfuscation...")
        for urgency in ["immediate", "normal", "low"]:
            delay = self.traffic_resistance.timing_obfuscator.get_send_delay(512, urgency)
            logger.info(f"Timing delay for {urgency} message: {delay:.3f} seconds")
        
        # Send protected messages
        logger.info("Sending messages with traffic analysis protection...")
        for i, msg in enumerate(test_messages):
            await self.traffic_resistance.send_message_with_protection(msg)
            logger.info(f"Sent protected message {i+1}")
        
        # Configure cover traffic
        logger.info("Configuring cover traffic...")
        self.traffic_resistance.configure_protection(
            padding=True,
            timing=True,
            cover_traffic=True,
            cover_pattern=TrafficPattern.RANDOM
        )
        
        # Let cover traffic run for a moment
        await asyncio.sleep(2)
        
        # Show traffic statistics
        stats = self.traffic_resistance.get_traffic_statistics()
        logger.info(f"Traffic analysis resistance statistics: {stats}")
        
        # Analyze traffic patterns
        analysis = self.traffic_resistance.analyze_traffic_patterns()
        logger.info(f"Traffic pattern analysis: {analysis}")
    
    async def demo_anonymous_identities(self):
        """Demonstrate anonymous identity management"""
        logger.info("=== Anonymous Identity Management Demo ===")
        
        # Create different types of identities
        logger.info("Creating anonymous identities...")
        
        persistent_identity = self.identity_manager.create_identity(
            IdentityType.PERSISTENT,
            nickname="SecureUser"
        )
        logger.info(f"Created persistent identity: {persistent_identity.identity_id.hex()[:16]}")
        
        ephemeral_identity = self.identity_manager.create_identity(
            IdentityType.EPHEMERAL,
            context="conversation_123"
        )
        logger.info(f"Created ephemeral identity: {ephemeral_identity.identity_id.hex()[:16]}")
        
        disposable_identity = self.identity_manager.create_identity(
            IdentityType.DISPOSABLE
        )
        logger.info(f"Created disposable identity: {disposable_identity.identity_id.hex()[:16]}")
        
        # Test identity rotation
        logger.info("Testing identity rotation...")
        new_identity = self.identity_manager.rotate_identity(
            persistent_identity.identity_id,
            preserve_reputation=True
        )
        
        if new_identity:
            logger.info(f"Rotated identity: {persistent_identity.identity_id.hex()[:16]} -> "
                       f"{new_identity.identity_id.hex()[:16]}")
        
        # Test reputation system
        logger.info("Testing reputation system...")
        self.identity_manager.update_reputation(ephemeral_identity.identity_id, 1.5)  # Good interaction
        self.identity_manager.update_reputation(ephemeral_identity.identity_id, 0.8)  # Mixed interaction
        
        reputation = self.identity_manager.get_reputation_score(ephemeral_identity.identity_id)
        logger.info(f"Identity reputation score: {reputation:.2f}")
        
        # Issue and verify credential
        logger.info("Testing anonymous credentials...")
        credential = self.identity_manager.issue_credential(
            ephemeral_identity.identity_id,
            {"role": "verified_user", "level": 2},
            validity_hours=24
        )
        
        if credential:
            logger.info(f"Issued credential: {credential.credential_id.hex()[:16]}")
            
            is_valid = self.identity_manager.verify_credential(credential.credential_id)
            logger.info(f"Credential verification: {'Valid' if is_valid else 'Invalid'}")
        
        # Show identity statistics
        stats = self.identity_manager.get_identity_statistics()
        logger.info(f"Identity management statistics: {stats}")
    
    async def demo_privacy_controls(self):
        """Demonstrate privacy controls and audit system"""
        logger.info("=== Privacy Controls Demo ===")
        
        # Test different privacy levels
        privacy_levels = [PrivacyLevel.MINIMAL, PrivacyLevel.STANDARD, 
                         PrivacyLevel.HIGH, PrivacyLevel.MAXIMUM]
        
        for level in privacy_levels:
            logger.info(f"Configuring privacy level: {level.value}")
            self.privacy_controller.configure_privacy_level(level)
            
            # Get privacy status
            status = self.privacy_controller.get_privacy_status()
            logger.info(f"Privacy status: {status['anonymity_status']}")
            
            # Perform privacy audit
            audit = self.privacy_controller.perform_privacy_audit()
            logger.info(f"Privacy audit score: {audit.overall_score:.2f}")
            
            if audit.vulnerabilities:
                logger.info(f"Vulnerabilities found: {len(audit.vulnerabilities)}")
                for vuln in audit.vulnerabilities[:3]:  # Show first 3
                    logger.info(f"  - {vuln}")
            
            if audit.recommendations:
                logger.info(f"Recommendations: {audit.recommendations[:2]}")  # Show first 2
            
            await asyncio.sleep(0.5)  # Brief pause between levels
        
        # Get personalized recommendations
        logger.info("Getting personalized privacy recommendations...")
        recommendations = self.privacy_controller.get_privacy_recommendations()
        for i, rec in enumerate(recommendations, 1):
            logger.info(f"{i}. {rec}")
        
        # Show privacy metrics
        metrics = self.privacy_controller.get_privacy_metrics()
        logger.info(f"Privacy metrics: {metrics}")
        
        # Export and import settings
        logger.info("Testing settings export/import...")
        exported_settings = self.privacy_controller.export_privacy_settings()
        logger.info(f"Exported settings: privacy_level={exported_settings['privacy_level']}")
        
        # Import settings back
        success = self.privacy_controller.import_privacy_settings(exported_settings)
        logger.info(f"Settings import: {'Success' if success else 'Failed'}")
    
    async def demo_integration(self):
        """Demonstrate integration between all anonymity components"""
        logger.info("=== Integration Demo ===")
        
        # Configure for maximum anonymity
        logger.info("Configuring maximum anonymity protection...")
        self.privacy_controller.configure_privacy_level(PrivacyLevel.MAXIMUM)
        
        # Create conversation identity
        conv_identity = self.identity_manager.get_identity_for_conversation("demo_conversation")
        logger.info(f"Using conversation identity: {conv_identity.identity_id.hex()[:16]}")
        
        # Send anonymous message with full protection
        logger.info("Sending anonymous message with full protection...")
        message = b"This is a fully anonymous and protected message!"
        
        # Send through traffic analysis resistance
        await self.traffic_resistance.send_message_with_protection(message, urgency="normal")
        
        # Update identity usage
        conv_identity.update_usage()
        
        # Update reputation based on successful message
        self.identity_manager.update_reputation(conv_identity.identity_id, 1.2)
        
        # Perform final audit
        final_audit = self.privacy_controller.perform_privacy_audit()
        logger.info(f"Final privacy audit score: {final_audit.overall_score:.2f}")
        logger.info(f"Final anonymity status: {final_audit.anonymity_level.value}")
        
        # Show comprehensive statistics
        logger.info("=== Final Statistics ===")
        
        onion_stats = self.onion_manager.get_circuit_statistics()
        logger.info(f"Onion routing: {onion_stats['total_circuits_built']} circuits built, "
                   f"{onion_stats['active_circuits']} active")
        
        traffic_stats = self.traffic_resistance.get_traffic_statistics()
        logger.info(f"Traffic analysis resistance: {traffic_stats['total_events']} events, "
                   f"{traffic_stats['protection_efficiency']:.2f} efficiency")
        
        identity_stats = self.identity_manager.get_identity_statistics()
        logger.info(f"Identity management: {identity_stats['total_identities_created']} identities created, "
                   f"{identity_stats['identity_rotations']} rotations")
        
        logger.info(f"Total messages sent during demo: {self.messages_sent}")

async def main():
    """Main demonstration function"""
    print("=== Privatus-chat Week 4 Anonymity Demo ===")
    print("Demonstrating onion routing and anonymous messaging capabilities")
    print()
    
    demo = AnonymityDemo()
    
    try:
        # Initialize components
        await demo.initialize_components()
        await demo.start_components()
        
        # Run demonstrations
        await demo.demo_onion_routing()
        await demo.demo_traffic_analysis_resistance()
        await demo.demo_anonymous_identities()
        await demo.demo_privacy_controls()
        await demo.demo_integration()
        
        print("\n=== Demo Complete ===")
        print("Week 4 anonymity features demonstrated successfully!")
        print("Check 'week4_anonymity_demo.log' for detailed logs.")
        
    except Exception as e:
        logger.error(f"Demo failed with error: {e}")
        print(f"Demo failed: {e}")
        
    finally:
        # Clean shutdown
        await demo.stop_components()

if __name__ == "__main__":
    # Run the demo
    asyncio.run(main()) 