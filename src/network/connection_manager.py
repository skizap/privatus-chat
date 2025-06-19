"""
Connection Manager for Privatus-chat
Week 3: Networking Infrastructure

This module manages multiple peer-to-peer connections, including connection
establishment, maintenance, and cleanup.
"""

import asyncio
import time
import logging
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass
from enum import Enum

@dataclass
class PeerInfo:
    """Information about a peer"""
    peer_id: bytes
    address: str
    port: int
    node_id: bytes = None
    last_seen: float = 0.0
    connection_attempts: int = 0
    is_trusted: bool = False
    
    def __post_init__(self):
        if self.last_seen == 0.0:
            self.last_seen = time.time()
        if self.node_id is None:
            self.node_id = self.peer_id

class ConnectionState(Enum):
    """Connection states"""
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"
    FAILED = "failed"

@dataclass
class Connection:
    """Represents a connection to a peer"""
    peer_info: PeerInfo
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    state: ConnectionState = ConnectionState.CONNECTED
    created_at: float = 0.0
    last_activity: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    
    def __post_init__(self):
        if self.created_at == 0.0:
            self.created_at = time.time()
        if self.last_activity == 0.0:
            self.last_activity = time.time()
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = time.time()
    
    def is_alive(self) -> bool:
        """Check if connection is alive"""
        return (self.state == ConnectionState.CONNECTED and
                not self.writer.is_closing())

class ConnectionManager:
    """Manages multiple peer-to-peer connections"""
    
    def __init__(self, max_connections: int = 50, 
                 connection_timeout: float = 30.0,
                 keepalive_interval: float = 60.0):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.keepalive_interval = keepalive_interval
        
        # Active connections
        self.connections: Dict[bytes, Connection] = {}
        
        # Known peers
        self.peers: Dict[bytes, PeerInfo] = {}
        
        # Connection callbacks
        self.on_connection_established: Optional[Callable[[Connection], None]] = None
        self.on_connection_lost: Optional[Callable[[bytes], None]] = None
        self.on_message_received: Optional[Callable[[bytes, bytes], None]] = None
        
        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.keepalive_task: Optional[asyncio.Task] = None
        
        # Connection limits and throttling
        self.connection_attempts: Dict[str, List[float]] = {}
        self.max_attempts_per_hour = 30
        
        self.logger = logging.getLogger(__name__)
        
        # Running state
        self.running = False
    
    async def start(self):
        """Start the connection manager"""
        if self.running:
            return
        
        self.running = True
        
        # Start background tasks
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        
        self.logger.info("Connection manager started")
    
    async def stop(self):
        """Stop the connection manager"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel background tasks
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        if self.keepalive_task:
            self.keepalive_task.cancel()
            try:
                await self.keepalive_task
            except asyncio.CancelledError:
                pass
        
        # Close all connections
        await self._close_all_connections()
        
        self.logger.info("Connection manager stopped")
    
    async def connect_to_peer(self, peer_info: PeerInfo) -> bool:
        """Connect to a peer"""
        if peer_info.peer_id in self.connections:
            # Already connected
            return True
        
        if len(self.connections) >= self.max_connections:
            self.logger.warning(f"Maximum connections reached ({self.max_connections})")
            return False
        
        # Check connection throttling
        if not self._can_attempt_connection(peer_info.address):
            self.logger.warning(f"Connection attempts throttled for {peer_info.address}")
            return False
        
        try:
            self.logger.info(f"Connecting to peer {peer_info.address}:{peer_info.port}")
            
            # Record connection attempt
            self._record_connection_attempt(peer_info.address)
            peer_info.connection_attempts += 1
            
            # Attempt connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(peer_info.address, peer_info.port),
                timeout=self.connection_timeout
            )
            
            # Create connection object
            connection = Connection(
                peer_info=peer_info,
                reader=reader,
                writer=writer,
                state=ConnectionState.CONNECTED
            )
            
            # Store connection and peer info
            self.connections[peer_info.peer_id] = connection
            self.peers[peer_info.peer_id] = peer_info
            
            # Start message handling for this connection
            asyncio.create_task(self._handle_connection(connection))
            
            # Notify callback
            if self.on_connection_established:
                self.on_connection_established(connection)
            
            self.logger.info(f"Connected to peer {peer_info.address}:{peer_info.port}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to connect to {peer_info.address}:{peer_info.port}: {e}")
            return False
    
    async def disconnect_peer(self, peer_id: bytes):
        """Disconnect from a peer"""
        if peer_id not in self.connections:
            return
        
        connection = self.connections[peer_id]
        
        try:
            if connection.writer and not connection.writer.is_closing():
                connection.writer.close()
                await connection.writer.wait_closed()
        except Exception as e:
            self.logger.error(f"Error closing connection to peer {peer_id.hex()}: {e}")
        
        # Remove from connections
        del self.connections[peer_id]
        
        # Notify callback
        if self.on_connection_lost:
            self.on_connection_lost(peer_id)
        
        self.logger.info(f"Disconnected from peer {peer_id.hex()}")
    
    async def send_to_peer(self, peer_id: bytes, data: bytes) -> bool:
        """Send data to a specific peer"""
        if peer_id not in self.connections:
            self.logger.warning(f"No connection to peer {peer_id.hex()}")
            return False
        
        connection = self.connections[peer_id]
        
        if not connection.is_alive():
            self.logger.warning(f"Connection to peer {peer_id.hex()} is not alive")
            await self.disconnect_peer(peer_id)
            return False
        
        try:
            # Send data with length prefix
            message_length = len(data)
            length_prefix = message_length.to_bytes(4, 'big')
            
            connection.writer.write(length_prefix + data)
            await connection.writer.drain()
            
            # Update statistics
            connection.bytes_sent += len(data) + 4
            connection.update_activity()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to send data to peer {peer_id.hex()}: {e}")
            await self.disconnect_peer(peer_id)
            return False
    
    async def broadcast_to_peers(self, data: bytes, exclude: Set[bytes] = None) -> int:
        """Broadcast data to all connected peers"""
        if exclude is None:
            exclude = set()
        
        sent_count = 0
        
        for peer_id in list(self.connections.keys()):
            if peer_id not in exclude:
                if await self.send_to_peer(peer_id, data):
                    sent_count += 1
        
        return sent_count
    
    def get_connected_peers(self) -> List[bytes]:
        """Get list of connected peer IDs"""
        return list(self.connections.keys())
    
    def get_connection_info(self, peer_id: bytes) -> Optional[Connection]:
        """Get connection information for a peer"""
        return self.connections.get(peer_id)
    
    def get_peer_info(self, peer_id: bytes) -> Optional[PeerInfo]:
        """Get peer information"""
        return self.peers.get(peer_id)
    
    def add_known_peer(self, peer_info: PeerInfo):
        """Add a peer to the known peers list"""
        self.peers[peer_info.peer_id] = peer_info
    
    def remove_peer(self, peer_id: bytes):
        """Remove a peer from known peers"""
        self.peers.pop(peer_id, None)
    
    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            'active_connections': len(self.connections),
            'max_connections': self.max_connections,
            'known_peers': len(self.peers),
            'total_bytes_sent': sum(conn.bytes_sent for conn in self.connections.values()),
            'total_bytes_received': sum(conn.bytes_received for conn in self.connections.values())
        }
    
    async def _handle_connection(self, connection: Connection):
        """Handle incoming messages from a connection"""
        try:
            while self.running and connection.is_alive():
                try:
                    # Read message length
                    length_data = await asyncio.wait_for(
                        connection.reader.readexactly(4), 
                        timeout=self.connection_timeout
                    )
                    
                    message_length = int.from_bytes(length_data, 'big')
                    
                    # Validate message length
                    if message_length <= 0 or message_length > 1024 * 1024:  # 1MB max
                        self.logger.warning(f"Invalid message length: {message_length}")
                        break
                    
                    # Read message data
                    message_data = await asyncio.wait_for(
                        connection.reader.readexactly(message_length),
                        timeout=self.connection_timeout
                    )
                    
                    # Update statistics
                    connection.bytes_received += len(message_data) + 4
                    connection.update_activity()
                    
                    # Notify callback
                    if self.on_message_received:
                        self.on_message_received(connection.peer_info.peer_id, message_data)
                    
                except asyncio.TimeoutError:
                    self.logger.warning(f"Timeout reading from peer {connection.peer_info.peer_id.hex()}")
                    break
                except asyncio.IncompleteReadError:
                    self.logger.info(f"Peer {connection.peer_info.peer_id.hex()} disconnected")
                    break
                    
        except Exception as e:
            self.logger.error(f"Error handling connection: {e}")
        finally:
            # Clean up connection
            await self.disconnect_peer(connection.peer_info.peer_id)
    
    async def _cleanup_loop(self):
        """Background task to clean up stale connections"""
        while self.running:
            try:
                current_time = time.time()
                stale_connections = []
                
                for peer_id, connection in self.connections.items():
                    # Check if connection is stale
                    if (current_time - connection.last_activity > self.connection_timeout * 2 or
                        not connection.is_alive()):
                        stale_connections.append(peer_id)
                
                # Clean up stale connections
                for peer_id in stale_connections:
                    self.logger.info(f"Cleaning up stale connection to {peer_id.hex()}")
                    await self.disconnect_peer(peer_id)
                
                # Clean up old connection attempt records
                cutoff_time = current_time - 3600  # 1 hour
                for address in list(self.connection_attempts.keys()):
                    self.connection_attempts[address] = [
                        t for t in self.connection_attempts[address] 
                        if t > cutoff_time
                    ]
                    if not self.connection_attempts[address]:
                        del self.connection_attempts[address]
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                await asyncio.sleep(30)
    
    async def _keepalive_loop(self):
        """Background task to send keepalive messages"""
        while self.running:
            try:
                # Send keepalive to all connections
                keepalive_data = b"KEEPALIVE"
                
                for peer_id in list(self.connections.keys()):
                    connection = self.connections.get(peer_id)
                    if connection and connection.is_alive():
                        # Only send keepalive if no recent activity
                        if time.time() - connection.last_activity > self.keepalive_interval / 2:
                            await self.send_to_peer(peer_id, keepalive_data)
                
                await asyncio.sleep(self.keepalive_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in keepalive loop: {e}")
                await asyncio.sleep(self.keepalive_interval)
    
    async def _close_all_connections(self):
        """Close all active connections"""
        for peer_id in list(self.connections.keys()):
            await self.disconnect_peer(peer_id)
    
    def _can_attempt_connection(self, address: str) -> bool:
        """Check if we can attempt a connection to an address"""
        current_time = time.time()
        cutoff_time = current_time - 3600  # 1 hour
        
        # Clean up old attempts
        if address in self.connection_attempts:
            self.connection_attempts[address] = [
                t for t in self.connection_attempts[address] 
                if t > cutoff_time
            ]
        
        # Check if under limit
        attempts = self.connection_attempts.get(address, [])
        return len(attempts) < self.max_attempts_per_hour
    
    def _record_connection_attempt(self, address: str):
        """Record a connection attempt"""
        current_time = time.time()
        
        if address not in self.connection_attempts:
            self.connection_attempts[address] = []
        
        self.connection_attempts[address].append(current_time) 