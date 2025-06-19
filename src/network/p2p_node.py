"""
P2P Node Implementation for Privatus-chat
Week 3: Networking Infrastructure

This module implements the main P2P node that coordinates all networking
components including DHT, connection management, NAT traversal, and peer discovery.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Callable, Any
from .kademlia_dht import KademliaDHT
from .connection_manager import ConnectionManager, PeerInfo
from .nat_traversal import NATTraversal
from .message_protocol import MessageProtocol, P2PMessage
from .peer_discovery import PeerDiscovery

class P2PNode:
    """Main P2P node implementation"""
    
    def __init__(self, node_id: bytes = None, bind_address: str = "0.0.0.0", 
                 bind_port: int = 0):
        # Generate node ID if not provided
        if node_id is None:
            import hashlib
            import random
            node_id = hashlib.sha1(str(random.random()).encode()).digest()
        
        self.node_id = node_id
        self.bind_address = bind_address
        self.bind_port = bind_port
        
        # Initialize components
        self.dht = KademliaDHT(node_id, bind_address, bind_port + 1000)
        self.connection_manager = ConnectionManager()
        self.nat_traversal = NATTraversal()
        self.message_protocol = MessageProtocol(node_id)
        self.peer_discovery = PeerDiscovery(node_id, self.dht)
        
        # Node state
        self.running = False
        self.server = None
        
        # Callbacks
        self.on_message_received: Optional[Callable[[bytes, Dict], None]] = None
        self.on_peer_connected: Optional[Callable[[bytes], None]] = None
        self.on_peer_disconnected: Optional[Callable[[bytes], None]] = None
        
        # Setup component callbacks
        self._setup_callbacks()
        
        self.logger = logging.getLogger(__name__)
    
    def _setup_callbacks(self):
        """Setup callbacks between components"""
        # Connection manager callbacks
        self.connection_manager.on_message_received = self._handle_received_message
        self.connection_manager.on_connection_established = self._handle_connection_established
        self.connection_manager.on_connection_lost = self._handle_connection_lost
        
        # Message protocol callbacks
        self.message_protocol.on_chat_message = self._handle_chat_message
        self.message_protocol.on_peer_connected = self._handle_peer_handshake
        self.message_protocol.on_peer_disconnected = self._handle_peer_disconnect
        
        # Peer discovery callbacks
        self.peer_discovery.on_peer_discovered = self._handle_peer_discovered
    
    async def start(self, bootstrap_nodes: List[tuple] = None):
        """Start the P2P node"""
        if self.running:
            return
        
        self.logger.info(f"Starting P2P node {self.node_id.hex()}")
        
        try:
            # Start DHT
            await self.dht.start(bootstrap_nodes)
            
            # Discover NAT type
            nat_type = await self.nat_traversal.discover_nat_type()
            self.logger.info(f"NAT type: {nat_type}")
            
            # Start connection manager
            await self.connection_manager.start()
            
            # Start TCP server for incoming connections
            self.server = await asyncio.start_server(
                self._handle_incoming_connection,
                self.bind_address,
                self.bind_port
            )
            
            # Get actual bind port
            self.bind_port = self.server.sockets[0].getsockname()[1]
            
            # Start peer discovery
            await self.peer_discovery.start(bootstrap_nodes)
            
            self.running = True
            self.logger.info(f"P2P node started on {self.bind_address}:{self.bind_port}")
            
        except Exception as e:
            self.logger.error(f"Failed to start P2P node: {e}")
            await self.stop()
            raise
    
    async def stop(self):
        """Stop the P2P node"""
        if not self.running:
            return
        
        self.logger.info("Stopping P2P node")
        self.running = False
        
        # Stop components
        await self.peer_discovery.stop()
        await self.connection_manager.stop()
        await self.dht.stop()
        
        # Stop server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        self.logger.info("P2P node stopped")
    
    async def send_message(self, peer_id: bytes, message_type: str, payload: Dict[str, Any]) -> bool:
        """Send a message to a peer"""
        try:
            # Create message
            if message_type == "chat":
                message = self.message_protocol.serializer.create_chat_message(
                    self.node_id, peer_id, payload.get('content', '')
                )
            else:
                from .message_protocol import MessageHeader, P2PMessage
                header = MessageHeader(
                    message_type=message_type,
                    message_id=self.message_protocol.serializer._generate_message_id(),
                    sender_id=self.node_id,
                    recipient_id=peer_id
                )
                message = P2PMessage(header=header, payload=payload)
            
            # Serialize message
            serialized = self.message_protocol.serializer.serialize(message)
            
            # Send through connection manager
            return await self.connection_manager.send_to_peer(peer_id, serialized)
            
        except Exception as e:
            self.logger.error(f"Failed to send message to {peer_id.hex()}: {e}")
            return False
    
    async def connect_to_peer(self, address: str, port: int) -> bool:
        """Connect to a specific peer"""
        try:
            # Create peer info
            peer_info = PeerInfo(
                peer_id=b"",  # Will be set during handshake
                address=address,
                port=port
            )
            
            # Attempt connection
            success = await self.connection_manager.connect_to_peer(peer_info)
            
            if success:
                self.logger.info(f"Connected to peer at {address}:{port}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to connect to {address}:{port}: {e}")
            return False
    
    def get_connected_peers(self) -> List[bytes]:
        """Get list of connected peer IDs"""
        return self.connection_manager.get_connected_peers()
    
    def get_discovered_peers(self) -> List:
        """Get list of discovered peers"""
        return self.peer_discovery.get_discovered_peers()
    
    def get_node_info(self) -> Dict[str, Any]:
        """Get node information"""
        return {
            'node_id': self.node_id.hex(),
            'address': self.bind_address,
            'port': self.bind_port,
            'nat_type': self.nat_traversal.nat_type,
            'public_address': (
                f"{self.nat_traversal.public_address.public_ip}:"
                f"{self.nat_traversal.public_address.public_port}"
                if self.nat_traversal.public_address else None
            ),
            'connected_peers': len(self.get_connected_peers()),
            'discovered_peers': len(self.get_discovered_peers()),
            'running': self.running
        }
    
    async def _handle_incoming_connection(self, reader, writer):
        """Handle incoming TCP connection"""
        peer_addr = writer.get_extra_info('peername')
        self.logger.info(f"Incoming connection from {peer_addr}")
        
        try:
            # Wait for handshake
            # This would be implemented with proper handshake protocol
            # For now, we'll create a temporary peer info
            import hashlib
            temp_peer_id = hashlib.sha1(f"{peer_addr[0]}:{peer_addr[1]}".encode()).digest()
            
            peer_info = PeerInfo(
                peer_id=temp_peer_id,
                address=peer_addr[0],
                port=peer_addr[1]
            )
            
            # Add to connection manager
            from .connection_manager import Connection, ConnectionState
            connection = Connection(
                peer_info=peer_info,
                reader=reader,
                writer=writer,
                state=ConnectionState.CONNECTED
            )
            
            self.connection_manager.connections[temp_peer_id] = connection
            
            # Start handling this connection
            await self.connection_manager._handle_connection(connection)
            
        except Exception as e:
            self.logger.error(f"Error handling incoming connection: {e}")
            writer.close()
            await writer.wait_closed()
    
    async def _handle_received_message(self, peer_id: bytes, data: bytes):
        """Handle received message from connection manager"""
        try:
            # Deserialize message
            message = self.message_protocol.serializer.deserialize(data)
            
            # Handle through protocol
            response = await self.message_protocol.handle_message(message, peer_id)
            
            # Send response if needed
            if response:
                response_data = self.message_protocol.serializer.serialize(response)
                await self.connection_manager.send_to_peer(peer_id, response_data)
                
        except Exception as e:
            self.logger.error(f"Error handling message from {peer_id.hex()}: {e}")
    
    def _handle_connection_established(self, connection):
        """Handle new connection established"""
        self.logger.info(f"Connection established with {connection.peer_info.peer_id.hex()}")
        
        if self.on_peer_connected:
            self.on_peer_connected(connection.peer_info.peer_id)
    
    def _handle_connection_lost(self, peer_id: bytes):
        """Handle connection lost"""
        self.logger.info(f"Connection lost with {peer_id.hex()}")
        
        if self.on_peer_disconnected:
            self.on_peer_disconnected(peer_id)
    
    def _handle_chat_message(self, peer_id: bytes, payload: Dict[str, Any]):
        """Handle chat message"""
        if self.on_message_received:
            self.on_message_received(peer_id, payload)
    
    def _handle_peer_handshake(self, peer_id: bytes, payload: Dict[str, Any]):
        """Handle peer handshake completion"""
        self.logger.info(f"Handshake completed with {peer_id.hex()}")
    
    def _handle_peer_disconnect(self, peer_id: bytes, reason: str):
        """Handle peer disconnect notification"""
        self.logger.info(f"Peer {peer_id.hex()} disconnected: {reason}")
    
    def _handle_peer_discovered(self, discovered_peer):
        """Handle newly discovered peer"""
        self.logger.info(f"Discovered peer {discovered_peer.peer_id.hex()} from {discovered_peer.source}")
        
        # Optionally auto-connect to discovered peers
        # This would be configurable based on user preferences 