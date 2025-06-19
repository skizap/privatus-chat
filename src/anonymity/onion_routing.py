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
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

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
        self.max_circuits = 10
        self.circuit_lifetime = 3600  # 1 hour
        self.min_relay_pool_size = 20
        
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
    
    async def build_circuit(self, destination_node_id: Optional[bytes] = None) -> Optional[OnionCircuit]:
        """Build a new onion routing circuit"""
        if len(self.relay_selection_pool) < self.default_circuit_length:
            logger.warning("Not enough relays available for circuit construction")
            return None
            
        circuit_id = self._generate_circuit_id()
        
        try:
            # Select relays for the circuit
            selected_relays = await self._select_relays_for_circuit(destination_node_id)
            if not selected_relays:
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
    
    async def _select_relays_for_circuit(self, destination_node_id: Optional[bytes] = None) -> List[OnionRelay]:
        """Select diverse relays for a circuit using security-focused algorithms"""
        if len(self.relay_selection_pool) < self.default_circuit_length:
            return []
        
        selected_relays = []
        available_relays = self.relay_selection_pool.copy()
        
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
    
    async def _establish_circuit(self, circuit: OnionCircuit) -> bool:
        """Establish the circuit through cryptographic handshakes"""
        try:
            # This would normally involve:
            # 1. Creating encrypted handshake messages for each hop
            # 2. Sending CREATE/EXTEND messages through the circuit
            # 3. Receiving CREATED/EXTENDED responses
            # 4. Establishing shared secrets for each hop
            
            # For now, simulate the handshake process
            await asyncio.sleep(0.1)  # Simulate network delay
            
            # Initialize circuit keys and state
            for hop in circuit.hops:
                hop.forward_digest = secrets.token_bytes(32)
                hop.backward_digest = secrets.token_bytes(32)
            
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