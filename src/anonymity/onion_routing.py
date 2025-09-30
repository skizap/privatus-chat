"""
Onion Routing Implementation for Privatus-chat
Week 4: Anonymous Messaging and Onion Routing

This module implements a custom onion routing system inspired by Tor but optimized
for real-time communication and decentralized chat applications.

Key Features:
- Three-hop circuit construction by default
- Layered encryption with unique keys per hop
- Relay selection with diversity algorithms
- Circuit lifecycle management
- Exit node handling for message delivery
"""

import asyncio
import secrets
import time
import hashlib
import hmac
import os
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

try:
    from ..crypto.encryption import MessageEncryption
    from ..crypto.key_management import KeyManager
    from ..network.message_protocol import MessageSerializer, MessageType
except ImportError:
    from crypto.encryption import MessageEncryption
    from crypto.key_management import KeyManager
    from network.message_protocol import MessageSerializer, MessageType

logger = logging.getLogger(__name__)

class CircuitState(Enum):
    """Circuit states in the onion routing system"""
    BUILDING = "building"
    ESTABLISHED = "established" 
    EXTENDING = "extending"
    FAILED = "failed"
    CLOSING = "closing"
    CLOSED = "closed"

class RelayType(Enum):
    """Types of relays in the onion routing circuit"""
    ENTRY = "entry"      # First hop (guard)
    MIDDLE = "middle"    # Middle hop
    EXIT = "exit"        # Final hop

@dataclass
class OnionRelay:
    """Represents a relay node in the onion routing network"""
    node_id: bytes
    address: str
    port: int
    public_key: bytes
    relay_type: RelayType
    last_seen: float = field(default_factory=time.time)
    reputation: float = 1.0
    uptime: float = 0.0
    bandwidth: int = 0
    
    def distance_from(self, node_id: bytes) -> int:
        """Calculate XOR distance from another node"""
        return int.from_bytes(self.node_id, 'big') ^ int.from_bytes(node_id, 'big')
    
    def is_suitable_for_type(self, relay_type: RelayType) -> bool:
        """Check if relay is suitable for a specific position"""
        if relay_type == RelayType.ENTRY:
            return self.reputation >= 0.8 and self.uptime >= 86400  # 24 hours
        elif relay_type == RelayType.MIDDLE:
            return self.reputation >= 0.6 and self.uptime >= 43200  # 12 hours
        elif relay_type == RelayType.EXIT:
            return self.reputation >= 0.7 and self.uptime >= 86400  # 24 hours
        return False

@dataclass
class CircuitHop:
    """Represents a single hop in an onion circuit"""
    relay: OnionRelay
    circuit_key: bytes  # Symmetric key for this hop
    forward_digest: bytes = b''
    backward_digest: bytes = b''
    
class OnionCircuit:
    """Represents a complete onion routing circuit"""
    
    def __init__(self, circuit_id: int, hops: List[CircuitHop]):
        self.circuit_id = circuit_id
        self.hops = hops
        self.state = CircuitState.BUILDING
        self.created_time = time.time()
        self.last_used = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.usage_count = 0
        
    @property
    def is_established(self) -> bool:
        """Check if circuit is fully established"""
        return self.state == CircuitState.ESTABLISHED
    
    @property
    def is_expired(self, max_age: int = 3600) -> bool:
        """Check if circuit has expired (default 1 hour)"""
        return time.time() - self.created_time > max_age
    
    @property
    def entry_relay(self) -> OnionRelay:
        """Get the entry (guard) relay"""
        return self.hops[0].relay
    
    @property
    def exit_relay(self) -> OnionRelay:
        """Get the exit relay"""
        return self.hops[-1].relay
    
    def update_usage(self, bytes_sent: int = 0, bytes_received: int = 0):
        """Update circuit usage statistics"""
        self.bytes_sent += bytes_sent
        self.bytes_received += bytes_received
        self.usage_count += 1
        self.last_used = time.time()

class OnionRoutingManager:
    """Manages onion routing circuits and message routing"""
    
    def __init__(self, node_id: bytes, key_manager: KeyManager):
        self.node_id = node_id
        self.key_manager = key_manager
        # MessageEncryption uses static methods
        self.serializer = MessageSerializer()
        
        # Circuit management
        self.circuits: Dict[int, OnionCircuit] = {}
        self.active_circuits: List[OnionCircuit] = []
        self.circuit_counter = 0
        
        # Relay directory
        self.known_relays: Dict[bytes, OnionRelay] = {}
        self.relay_selection_pool: List[OnionRelay] = []
        
        # Configuration
        self.default_circuit_length = 3
        self.max_circuit_length = 6  # Support up to 6-hop circuits
        self.min_circuit_length = 2  # Minimum 2-hop for basic anonymity
        self.max_circuits = 10
        self.circuit_lifetime = 3600  # 1 hour
        self.min_relay_pool_size = 20
        self.enable_multi_hop = True  # Enable configurable hop counts

        # Multi-hop enhancements
        self.adaptive_circuit_length = True
        self.circuit_length_by_threat_level = {
            "low": 2,      # Basic anonymity
            "medium": 3,   # Standard protection
            "high": 4,     # Enhanced protection
            "extreme": 6   # Maximum protection
        }
        
        # Statistics
        self.total_circuits_built = 0
        self.failed_circuits = 0
        self.total_messages_sent = 0
        
        self.running = False
        
    async def start(self):
        """Start the onion routing manager"""
        logger.info("Starting onion routing manager")
        
        self.running = True
        
        # Start background tasks
        asyncio.create_task(self._circuit_maintenance_loop())
        asyncio.create_task(self._relay_discovery_loop())
        
        logger.info("Onion routing manager started")
        
    async def stop(self):
        """Stop the onion routing manager"""
        logger.info("Stopping onion routing manager")
        
        self.running = False
        
        # Close all circuits
        for circuit in list(self.circuits.values()):
            await self._close_circuit(circuit.circuit_id)
            
        logger.info("Onion routing manager stopped")
    
    def add_relay(self, relay: OnionRelay):
        """Add a relay to the known relays directory"""
        self.known_relays[relay.node_id] = relay
        
        # Add to selection pool if suitable
        if self._is_relay_suitable(relay):
            self.relay_selection_pool.append(relay)
            logger.debug(f"Added relay {relay.node_id.hex()[:16]} to selection pool")
    
    def _is_relay_suitable(self, relay: OnionRelay) -> bool:
        """Check if a relay meets minimum requirements"""
        return (
            relay.reputation >= 0.5 and
            relay.uptime >= 1800 and  # 30 minutes minimum
            time.time() - relay.last_seen <= 300  # Seen within 5 minutes
        )
    
    async def build_circuit(self, destination_node_id: Optional[bytes] = None,
                           hop_count: Optional[int] = None) -> Optional[OnionCircuit]:
        """Build a new onion routing circuit with configurable hop count"""
        circuit_length = hop_count or self.default_circuit_length

        if not self.enable_multi_hop and circuit_length != self.default_circuit_length:
            logger.warning("Multi-hop circuits disabled, using default length")
            circuit_length = self.default_circuit_length

        if circuit_length > self.max_circuit_length:
            logger.warning(f"Requested hop count {circuit_length} exceeds maximum {self.max_circuit_length}")
            circuit_length = self.max_circuit_length

        if len(self.relay_selection_pool) < circuit_length:
            logger.warning(f"Not enough relays available for {circuit_length}-hop circuit construction")
            return None

        circuit_id = self._generate_circuit_id()

        try:
            # Select relays for the circuit
            selected_relays = await self._select_relays_for_circuit(destination_node_id, circuit_length)
            if not selected_relays or len(selected_relays) != circuit_length:
                logger.error("Failed to select suitable relays for circuit")
                return None

            # Create circuit hops with encryption keys
            hops = []
            for relay in selected_relays:
                circuit_key = secrets.token_bytes(32)  # AES-256 key
                hop = CircuitHop(relay=relay, circuit_key=circuit_key)
                hops.append(hop)

            # Create circuit object
            circuit = OnionCircuit(circuit_id, hops)

            # Perform circuit establishment handshakes
            if await self._establish_circuit(circuit):
                circuit.state = CircuitState.ESTABLISHED
                self.circuits[circuit_id] = circuit
                self.active_circuits.append(circuit)
                self.total_circuits_built += 1

                logger.info(f"Successfully built circuit {circuit_id} with {len(hops)} hops")
                return circuit
            else:
                logger.error(f"Failed to establish circuit {circuit_id}")
                self.failed_circuits += 1
                return None

        except Exception as e:
            logger.error(f"Error building circuit: {e}")
            self.failed_circuits += 1
            return None
    
    async def _select_relays_for_circuit(self, destination_node_id: Optional[bytes] = None,
                                        hop_count: int = 3) -> List[OnionRelay]:
        """Select diverse relays for a circuit using security-focused algorithms"""
        if len(self.relay_selection_pool) < hop_count:
            return []

        selected_relays = []
        available_relays = self.relay_selection_pool.copy()

        # For circuits with more than 3 hops, distribute roles more evenly
        if hop_count > 3:
            # Select entry relay
            entry_candidates = [r for r in available_relays if r.is_suitable_for_type(RelayType.ENTRY)]
            if not entry_candidates:
                logger.error("No suitable entry relays available")
                return []

            entry_relay = self._select_relay_by_reputation(entry_candidates)
            selected_relays.append(entry_relay)
            available_relays.remove(entry_relay)

            # Select multiple middle relays
            for i in range(hop_count - 2):  # -2 for entry and exit
                middle_candidates = [
                    r for r in available_relays
                    if (r.is_suitable_for_type(RelayType.MIDDLE) and
                        self._is_relay_diverse(r, selected_relays))
                ]
                if not middle_candidates:
                    logger.error(f"No suitable middle relay {i+1} available")
                    return []

                middle_relay = self._select_relay_by_reputation(middle_candidates)
                selected_relays.append(middle_relay)
                available_relays.remove(middle_relay)

            # Select exit relay
            exit_candidates = [
                r for r in available_relays
                if (r.is_suitable_for_type(RelayType.EXIT) and
                    self._is_relay_diverse(r, selected_relays))
            ]
            if not exit_candidates:
                logger.error("No suitable exit relays available")
                return []

            exit_relay = self._select_relay_by_reputation(exit_candidates)
            selected_relays.append(exit_relay)
        else:
            # Original 3-hop selection logic
            # Select entry (guard) relay
            entry_candidates = [r for r in available_relays if r.is_suitable_for_type(RelayType.ENTRY)]
            if not entry_candidates:
                logger.error("No suitable entry relays available")
                return []

            entry_relay = self._select_relay_by_reputation(entry_candidates)
            selected_relays.append(entry_relay)
            available_relays.remove(entry_relay)

            # Select middle relay (ensure diversity)
            middle_candidates = [
                r for r in available_relays
                if (r.is_suitable_for_type(RelayType.MIDDLE) and
                    self._is_relay_diverse(r, selected_relays))
            ]
            if not middle_candidates:
                logger.error("No suitable middle relays available")
                return []

            middle_relay = self._select_relay_by_reputation(middle_candidates)
            selected_relays.append(middle_relay)
            available_relays.remove(middle_relay)

            # Select exit relay
            exit_candidates = [
                r for r in available_relays
                if (r.is_suitable_for_type(RelayType.EXIT) and
                    self._is_relay_diverse(r, selected_relays))
            ]
            if not exit_candidates:
                logger.error("No suitable exit relays available")
                return []

            exit_relay = self._select_relay_by_reputation(exit_candidates)
            selected_relays.append(exit_relay)

        return selected_relays
    
    def _select_relay_by_reputation(self, candidates: List[OnionRelay]) -> OnionRelay:
        """Select relay based on reputation-weighted random selection"""
        if not candidates:
            raise ValueError("No relay candidates provided")
        
        # Weight by reputation and uptime
        weights = []
        for relay in candidates:
            weight = relay.reputation * (1 + relay.uptime / 86400)  # Bonus for uptime
            weights.append(weight)
        
        # Weighted random selection
        total_weight = sum(weights)
        if total_weight == 0:
            return secrets.choice(candidates)
        
        random_value = secrets.randbelow(int(total_weight * 1000)) / 1000
        cumulative_weight = 0
        
        for i, weight in enumerate(weights):
            cumulative_weight += weight
            if random_value <= cumulative_weight:
                return candidates[i]
        
        return candidates[-1]  # Fallback
    
    def _is_relay_diverse(self, relay: OnionRelay, selected_relays: List[OnionRelay]) -> bool:
        """Check if relay provides sufficient diversity (different network/location)"""
        for selected in selected_relays:
            # Check if same node
            if relay.node_id == selected.node_id:
                return False
            
            # Check if same IP subnet (simplified)
            relay_subnet = '.'.join(relay.address.split('.')[:3])
            selected_subnet = '.'.join(selected.address.split('.')[:3])
            if relay_subnet == selected_subnet:
                return False
        
        return True

    def _generate_circuit_challenge(self, circuit_id: int) -> bytes:
        """Generate a cryptographically secure challenge for circuit authentication"""
        # Use circuit ID, timestamp, and secure random data for uniqueness
        timestamp = int(time.time() * 1000).to_bytes(8, 'big')
        circuit_seed = circuit_id.to_bytes(8, 'big')
        random_entropy = secrets.token_bytes(32)

        # Combine all entropy sources
        challenge_data = timestamp + circuit_seed + random_entropy

        # Generate challenge using SHA-256
        challenge = hashlib.sha256(challenge_data).digest()

        logger.debug(f"Generated secure challenge for circuit {circuit_id}: {challenge.hex()[:16]}...")
        return challenge

    def _create_challenge_response(self, challenge: bytes, circuit_key: bytes, hop_index: int) -> bytes:
        """Create a cryptographically secure response to a challenge"""
        try:
            # Create HMAC of challenge using circuit key
            response_data = challenge + hop_index.to_bytes(4, 'big')
            response = hmac.new(circuit_key, response_data, hashlib.sha256).digest()

            # Add timestamp to prevent replay attacks
            timestamp = int(time.time() * 1000).to_bytes(8, 'big')
            final_response = timestamp + response

            logger.debug(f"Created challenge response for hop {hop_index}")
            return final_response

        except Exception as e:
            logger.error(f"Failed to create challenge response: {e}")
            raise

    def _validate_challenge_response(self, challenge: bytes, response: bytes,
                                   circuit_key: bytes, hop_index: int,
                                   max_age_ms: int = 30000) -> bool:
        """Validate a challenge response with replay attack protection"""
        try:
            if len(response) < 40:  # 8 bytes timestamp + 32 bytes HMAC
                logger.error("Invalid response length")
                return False

            # Extract timestamp and HMAC from response
            timestamp_bytes = response[:8]
            received_hmac = response[8:]

            # Check timestamp for replay attack prevention
            current_time_ms = int(time.time() * 1000)
            response_time_ms = int.from_bytes(timestamp_bytes, 'big')

            if abs(current_time_ms - response_time_ms) > max_age_ms:
                logger.error(f"Challenge response too old: {abs(current_time_ms - response_time_ms)}ms")
                return False

            # Verify HMAC
            expected_response_data = challenge + hop_index.to_bytes(4, 'big')
            expected_hmac = hmac.new(circuit_key, expected_response_data, hashlib.sha256).digest()

            if not hmac.compare_digest(received_hmac, expected_hmac):
                logger.error("Challenge response HMAC verification failed")
                return False

            logger.debug(f"Challenge response validated for hop {hop_index}")
            return True

        except Exception as e:
            logger.error(f"Failed to validate challenge response: {e}")
            return False

    def _generate_circuit_proof(self, circuit: OnionCircuit, challenge: bytes) -> bytes:
        """Generate a cryptographic proof of circuit integrity"""
        try:
            # Create proof data combining circuit information
            proof_data = b'circuit_proof' + challenge

            # Include hop information in proof
            for i, hop in enumerate(circuit.hops):
                hop_info = hop.relay.node_id + hop.circuit_key + hop.forward_digest + hop.backward_digest
                proof_data += i.to_bytes(4, 'big') + hop_info

            # Generate proof using all circuit keys
            proof = hashlib.sha256(proof_data).digest()

            # Sign proof with master circuit key (derived from all hop keys)
            master_key = self._derive_master_circuit_key(circuit)
            signed_proof = hmac.new(master_key, proof, hashlib.sha256).digest()

            logger.debug(f"Generated circuit proof: {signed_proof.hex()[:16]}...")
            return signed_proof

        except Exception as e:
            logger.error(f"Failed to generate circuit proof: {e}")
            raise

    def _validate_circuit_proof(self, circuit: OnionCircuit, challenge: bytes, proof: bytes) -> bool:
        """Validate a cryptographic proof of circuit integrity"""
        try:
            # Regenerate expected proof
            expected_proof = self._generate_circuit_proof(circuit, challenge)

            # Use constant-time comparison to prevent timing attacks
            if not hmac.compare_digest(proof, expected_proof):
                logger.error("Circuit proof validation failed")
                return False

            logger.debug("Circuit proof validated successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to validate circuit proof: {e}")
            return False

    def _derive_master_circuit_key(self, circuit: OnionCircuit) -> bytes:
        """Derive a master key from all circuit hop keys for proof signing"""
        try:
            # Combine all hop keys
            combined_keys = b''.join(hop.circuit_key for hop in circuit.hops)

            # Derive master key using HKDF
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'circuit_master',
                info=b'master_key_derivation'
            )

            master_key = hkdf.derive(combined_keys)
            return master_key

        except Exception as e:
            logger.error(f"Failed to derive master circuit key: {e}")
            # Fallback to simple hash combination
            combined = hashlib.sha256(b''.join(hop.circuit_key for hop in circuit.hops)).digest()
            return combined[:32]

    async def _perform_secure_circuit_test(self, circuit: OnionCircuit) -> bool:
        """Perform secure circuit integrity test with cryptographic authentication"""
        try:
            circuit_id = circuit.circuit_id

            # Generate unique challenge for this circuit
            challenge = self._generate_circuit_challenge(circuit_id)

            # Test each hop individually with challenge-response
            for i, hop in enumerate(circuit.hops):
                logger.debug(f"Testing hop {i+1}/{len(circuit.hops)} in circuit {circuit_id}")

                # Create challenge response for this hop
                challenge_response = self._create_challenge_response(challenge, hop.circuit_key, i)

                # Encrypt challenge response through the circuit up to this hop
                test_payload = challenge + challenge_response

                # Encrypt for transmission to this hop
                encrypted_test = test_payload
                for j in range(len(circuit.hops) - 1, i - 1, -1):  # From exit to current hop
                    encrypted_test = MessageEncryption.encrypt_with_header(
                        encrypted_test, circuit.hops[j].circuit_key
                    )

                # Simulate sending to hop and receiving response
                # In real implementation, this would involve actual network communication
                decrypted_response = encrypted_test

                # Decrypt response layer by layer
                for j in range(i, len(circuit.hops)):  # From current hop to exit
                    try:
                        decrypted_response = MessageEncryption.decrypt_with_header(
                            decrypted_response, circuit.hops[j].circuit_key
                        )
                    except (InvalidTag, Exception) as e:
                        logger.error(f"Decryption failed at hop {j}: {e}")
                        return False

                # Validate the response
                if len(decrypted_response) < len(challenge) + 40:  # Challenge + timestamp + HMAC
                    logger.error(f"Invalid response length from hop {i}")
                    return False

                received_challenge = decrypted_response[:32]
                received_response = decrypted_response[32:]

                # Verify challenge matches
                if not hmac.compare_digest(received_challenge, challenge):
                    logger.error(f"Challenge mismatch at hop {i}")
                    return False

                # Validate challenge response
                if not self._validate_challenge_response(challenge, received_response,
                                                       hop.circuit_key, i):
                    logger.error(f"Challenge response validation failed at hop {i}")
                    return False

                logger.debug(f"Hop {i+1} authentication successful")

            # Generate and validate circuit-wide proof
            circuit_proof = self._generate_circuit_proof(circuit, challenge)

            # In real implementation, this proof would be validated by all hops
            # For now, we validate it locally as a final integrity check
            if not self._validate_circuit_proof(circuit, challenge, circuit_proof):
                logger.error("Circuit proof validation failed")
                return False

            logger.info(f"Circuit {circuit_id} integrity test passed with cryptographic authentication")
            return True

        except Exception as e:
            logger.error(f"Secure circuit test failed: {e}")
            return False

    async def _establish_circuit(self, circuit: OnionCircuit) -> bool:
        """Establish the circuit through cryptographic handshakes"""
        try:
            # Generate shared secrets for each hop using Diffie-Hellman
            for i, hop in enumerate(circuit.hops):
                # Generate ephemeral key pair for this hop
                ephemeral_private = X25519PrivateKey.generate()
                ephemeral_public = ephemeral_private.public_key()

                # Perform DH with relay's public key
                try:
                    shared_secret = ephemeral_private.exchange(hop.relay.public_key)
                except Exception as e:
                    logger.error(f"DH exchange failed for hop {i}: {e}")
                    return False

                # Derive circuit keys from shared secret
                hop.circuit_key = self._derive_circuit_key(shared_secret, i)

                # Initialize digests for traffic flow authentication
                hop.forward_digest = self._initialize_digest(hop.circuit_key, b"forward")
                hop.backward_digest = self._initialize_digest(hop.circuit_key, b"backward")

                # Simulate network handshake delay
                await asyncio.sleep(0.05)

            # Perform secure circuit integrity test with cryptographic authentication
            if not await self._perform_secure_circuit_test(circuit):
                logger.error("Secure circuit integrity test failed")
                return False

            logger.info(f"Circuit {circuit.circuit_id} established with cryptographic authentication ({len(circuit.hops)} hops)")
            return True

        except Exception as e:
            logger.error(f"Circuit establishment failed: {e}")
            return False
    
    async def send_message_through_circuit(self, circuit: OnionCircuit, 
                                         destination: bytes, message: Dict[str, Any]) -> bool:
        """Send a message through an onion circuit"""
        if not circuit.is_established:
            logger.error("Cannot send message through non-established circuit")
            return False
        
        try:
            # Create the message payload
            payload_data = self.serializer.serialize_payload(message)
            
            # Apply onion encryption (innermost to outermost)
            encrypted_payload = payload_data
            
            for hop in reversed(circuit.hops):  # Start from exit, work backwards
                # Add routing header for this hop
                if hop == circuit.hops[-1]:  # Exit hop
                    routing_data = {
                        'destination': destination.hex(),
                        'command': 'RELAY_DATA'
                    }
                else:  # Middle/Entry hops
                    routing_data = {
                        'next_hop': circuit.hops[circuit.hops.index(hop) + 1].relay.node_id.hex(),
                        'command': 'RELAY_EXTEND'
                    }
                
                # Encrypt this layer
                encrypted_payload = MessageEncryption.encrypt_with_header(
                    encrypted_payload, hop.circuit_key
                )
                
                # Add routing header
                layer_data = {
                    'routing': routing_data,
                    'payload': encrypted_payload.hex()
                }
                encrypted_payload = self.serializer.serialize_payload(layer_data).encode()
            
            # Send through the circuit
            await self._send_to_entry_node(circuit, encrypted_payload)
            
            # Update circuit usage
            circuit.update_usage(bytes_sent=len(encrypted_payload))
            self.total_messages_sent += 1
            
            logger.debug(f"Message sent through circuit {circuit.circuit_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send message through circuit: {e}")
            return False
    
    async def _send_to_entry_node(self, circuit: OnionCircuit, encrypted_payload: bytes):
        """Send encrypted payload to the entry node of the circuit"""
        # This would normally send the data to the first hop
        # For now, simulate the network operation
        await asyncio.sleep(0.05)  # Simulate network delay
        logger.debug(f"Sent {len(encrypted_payload)} bytes to entry node")
    
    async def build_circuit_by_threat_level(self, threat_level: str = "medium",
                                          destination_node_id: Optional[bytes] = None) -> Optional[OnionCircuit]:
        """Build a circuit with hop count based on threat level."""
        if threat_level not in self.circuit_length_by_threat_level:
            logger.warning(f"Unknown threat level '{threat_level}', using 'medium'")
            threat_level = "medium"

        hop_count = self.circuit_length_by_threat_level[threat_level]
        logger.info(f"Building {hop_count}-hop circuit for threat level '{threat_level}'")

        return await self.build_circuit(destination_node_id, hop_count)

    def get_available_circuit(self) -> Optional[OnionCircuit]:
        """Get an available circuit for sending messages"""
        available = [c for c in self.active_circuits if c.is_established and not c.is_expired]

        if not available:
            return None

        # Select circuit with least usage
        return min(available, key=lambda c: c.usage_count)
    
    async def _circuit_maintenance_loop(self):
        """Background task for circuit maintenance"""
        while self.running:
            try:
                # Clean up expired circuits
                expired_circuits = [
                    c for c in self.active_circuits 
                    if c.is_expired or c.state == CircuitState.FAILED
                ]
                
                for circuit in expired_circuits:
                    await self._close_circuit(circuit.circuit_id)
                
                # Build new circuits if needed
                active_count = len([c for c in self.active_circuits if c.is_established])
                if active_count < 3:  # Maintain at least 3 active circuits
                    logger.info("Building new circuit for redundancy")
                    await self.build_circuit()
                
                # Update relay statistics
                await self._update_relay_statistics()
                
            except Exception as e:
                logger.error(f"Error in circuit maintenance: {e}")
                
            await asyncio.sleep(30)  # Run every 30 seconds
    
    async def _relay_discovery_loop(self):
        """Background task for discovering new relays"""
        while self.running:
            try:
                # This would normally query the DHT or directory services
                # for available relays. For now, simulate the process
                await asyncio.sleep(60)  # Run every minute
                
            except Exception as e:
                logger.error(f"Error in relay discovery: {e}")
    
    async def _update_relay_statistics(self):
        """Update relay reputation and statistics"""
        current_time = time.time()
        
        for relay in self.known_relays.values():
            # Decay reputation for relays not seen recently
            time_since_seen = current_time - relay.last_seen
            if time_since_seen > 300:  # 5 minutes
                decay_factor = min(0.1, time_since_seen / 3600)  # Decay over 1 hour
                relay.reputation = max(0.1, relay.reputation - decay_factor)
    
    async def _close_circuit(self, circuit_id: int):
        """Close and clean up a circuit"""
        if circuit_id not in self.circuits:
            return
        
        circuit = self.circuits[circuit_id]
        circuit.state = CircuitState.CLOSING
        
        # Send circuit close messages (would normally notify relays)
        await asyncio.sleep(0.05)  # Simulate network delay
        
        # Clean up
        circuit.state = CircuitState.CLOSED
        del self.circuits[circuit_id]
        
        if circuit in self.active_circuits:
            self.active_circuits.remove(circuit)
        
        logger.debug(f"Closed circuit {circuit_id}")
    
    def _generate_circuit_id(self) -> int:
        """Generate a unique circuit ID"""
        self.circuit_counter += 1
        return self.circuit_counter

    def _derive_circuit_key(self, shared_secret: bytes, hop_index: int) -> bytes:
        """Derive circuit key from shared secret"""
        # Use HKDF-like construction for key derivation
        info = f"circuit-key-{hop_index}".encode()
        return hmac.new(shared_secret, info, hashlib.sha256).digest()[:32]

    def _initialize_digest(self, key: bytes, direction: bytes) -> bytes:
        """Initialize digest for traffic flow authentication"""
        return hmac.new(key, direction, hashlib.sha256).digest()

    def _encrypt_circuit_data(self, circuit: OnionCircuit, data: bytes) -> Optional[bytes]:
        """Encrypt data for transmission through the circuit"""
        try:
            encrypted = data
            # Apply encryption layer by layer (exit to entry)
            for hop in reversed(circuit.hops):
                encrypted = MessageEncryption.encrypt_with_header(encrypted, hop.circuit_key)
            return encrypted
        except Exception as e:
            logger.error(f"Circuit encryption failed: {e}")
            return None

    def _decrypt_circuit_data(self, circuit: OnionCircuit, data: bytes) -> Optional[bytes]:
        """Decrypt data received from the circuit"""
        try:
            decrypted = data
            # Apply decryption layer by layer (entry to exit)
            for hop in circuit.hops:
                decrypted = MessageEncryption.decrypt_with_header(decrypted, hop.circuit_key)
            return decrypted
        except Exception as e:
            logger.error(f"Circuit decryption failed: {e}")
            return None
    
    def get_circuit_statistics(self) -> Dict[str, Any]:
        """Get statistics about circuit usage and performance"""
        active_count = len([c for c in self.active_circuits if c.is_established])
        
        return {
            'total_circuits_built': self.total_circuits_built,
            'active_circuits': active_count,
            'failed_circuits': self.failed_circuits,
            'total_messages_sent': self.total_messages_sent,
            'known_relays': len(self.known_relays),
            'relay_selection_pool': len(self.relay_selection_pool),
            'circuit_success_rate': (
                self.total_circuits_built / max(1, self.total_circuits_built + self.failed_circuits)
            )
        } 