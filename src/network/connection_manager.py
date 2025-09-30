"""
Connection Manager for Privatus-chat
Week 3: Networking Infrastructure

This module manages multiple peer-to-peer connections, including connection
establishment, maintenance, and cleanup.
"""

import asyncio
import time
import logging
import ipaddress
from typing import Dict, List, Optional, Set, Callable, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
import threading

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

class ConnectionFailureType(Enum):
    """Types of connection failures"""
    TIMEOUT = "timeout"
    REFUSED = "refused"
    NETWORK_ERROR = "network_error"
    AUTHENTICATION_FAILED = "authentication_failed"
    RATE_LIMITED = "rate_limited"
    OTHER = "other"

class SecurityLevel(Enum):
    """Security levels for rate limiting"""
    LOW = "low"           # Permissive: 100 attempts/minute, short backoff
    MEDIUM = "medium"     # Balanced: 50 attempts/minute, moderate backoff
    HIGH = "high"         # Strict: 20 attempts/minute, long backoff
    PARANOID = "paranoid" # Maximum security: 5 attempts/minute, very long backoff

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

@dataclass
class ConnectionPoolEntry:
    """Entry in the connection pool"""
    connection: Connection
    last_used: float
    in_use: bool = False

@dataclass
class RateLimitConfig:
    """Configuration for connection rate limiting"""
    security_level: SecurityLevel = SecurityLevel.MEDIUM

    # Base rate limits per minute
    max_attempts_per_minute: Dict[SecurityLevel, int] = field(default_factory=lambda: {
        SecurityLevel.LOW: 100,
        SecurityLevel.MEDIUM: 50,
        SecurityLevel.HIGH: 20,
        SecurityLevel.PARANOID: 5
    })

    # Exponential backoff multipliers
    backoff_multipliers: Dict[SecurityLevel, float] = field(default_factory=lambda: {
        SecurityLevel.LOW: 1.5,
        SecurityLevel.MEDIUM: 2.0,
        SecurityLevel.HIGH: 3.0,
        SecurityLevel.PARANOID: 5.0
    })

    # Maximum backoff time in seconds
    max_backoff_seconds: Dict[SecurityLevel, int] = field(default_factory=lambda: {
        SecurityLevel.LOW: 60,
        SecurityLevel.MEDIUM: 300,
        SecurityLevel.HIGH: 900,
        SecurityLevel.PARANOID: 3600
    })

    # Time windows for rate limiting
    rate_limit_window_seconds: int = 60
    cleanup_interval_seconds: int = 300  # 5 minutes

    # Burst allowance (allow short bursts above the rate limit)
    burst_allowance: Dict[SecurityLevel, int] = field(default_factory=lambda: {
        SecurityLevel.LOW: 10,
        SecurityLevel.MEDIUM: 5,
        SecurityLevel.HIGH: 2,
        SecurityLevel.PARANOID: 0
    })

    def get_max_attempts_per_minute(self) -> int:
        """Get max attempts per minute for current security level"""
        return self.max_attempts_per_minute[self.security_level]

    def get_backoff_multiplier(self) -> float:
        """Get backoff multiplier for current security level"""
        return self.backoff_multipliers[self.security_level]

    def get_max_backoff(self) -> int:
        """Get maximum backoff time for current security level"""
        return self.max_backoff_seconds[self.security_level]

    def get_burst_allowance(self) -> int:
        """Get burst allowance for current security level"""
        return self.burst_allowance[self.security_level]

@dataclass
class ConnectionAttempt:
    """Tracks a single connection attempt"""
    timestamp: float
    failure_type: ConnectionFailureType = ConnectionFailureType.OTHER
    backoff_until: float = 0.0
    consecutive_failures: int = 0

@dataclass
class IPRateLimitData:
    """Rate limiting data for a specific IP address"""
    attempts: deque = field(default_factory=deque)
    backoff_until: float = 0.0
    consecutive_failures: int = 0
    last_failure_type: Optional[ConnectionFailureType] = None
    total_failures: int = 0
    lock: threading.RLock = field(default_factory=threading.RLock)

class RateLimiter:
    """Comprehensive rate limiter for connection attempts"""

    def __init__(self, config: RateLimitConfig):
        self.config = config
        self.ip_data: Dict[str, IPRateLimitData] = {}
        self.cleanup_task: Optional[asyncio.Task] = None
        self.running = False
        self.logger = logging.getLogger(f"{__name__}.RateLimiter")
        self._lock = asyncio.Lock()

    async def start(self):
        """Start the rate limiter"""
        if self.running:
            return

        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.logger.info(f"Rate limiter started with security level: {self.config.security_level.value}")

    async def stop(self):
        """Stop the rate limiter"""
        if not self.running:
            return

        self.running = False

        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass

        self.logger.info("Rate limiter stopped")

    def _normalize_ip(self, address: str) -> str:
        """Normalize IP address to standard format"""
        try:
            # Handle IPv4-mapped IPv6 addresses
            if address.startswith('::ffff:'):
                address = address[7:]

            ip = ipaddress.ip_address(address)
            return str(ip)
        except ValueError:
            # If it's not a valid IP, return as-is but log warning
            self.logger.warning(f"Invalid IP address format: {address}")
            return address

    def _get_ip_data(self, ip: str) -> IPRateLimitData:
        """Get or create rate limit data for an IP"""
        normalized_ip = self._normalize_ip(ip)

        if normalized_ip not in self.ip_data:
            self.ip_data[normalized_ip] = IPRateLimitData()

        return self.ip_data[normalized_ip]

    def _calculate_backoff(self, consecutive_failures: int) -> float:
        """Calculate exponential backoff time"""
        if consecutive_failures <= 0:
            return 0.0

        # Base backoff: 2^failures seconds
        backoff = 2.0 ** consecutive_failures

        # Apply security level multiplier
        backoff *= self.config.get_backoff_multiplier()

        # Cap at maximum backoff time
        max_backoff = self.config.get_max_backoff()
        return min(backoff, max_backoff)

    def _clean_old_attempts(self, ip_data: IPRateLimitData, current_time: float):
        """Clean old attempts from the rate limit window"""
        window_start = current_time - self.config.rate_limit_window_seconds

        # Remove attempts outside the window
        while ip_data.attempts and ip_data.attempts[0].timestamp < window_start:
            ip_data.attempts.popleft()

    async def can_attempt_connection(self, address: str) -> Tuple[bool, float]:
        """
        Check if a connection attempt is allowed
        Returns: (allowed: bool, wait_time: float)
        """
        async with self._lock:
            current_time = time.time()
            ip_data = self._get_ip_data(address)

            with ip_data.lock:
                # Clean old attempts
                self._clean_old_attempts(ip_data, current_time)

                # Check if currently in backoff period
                if current_time < ip_data.backoff_until:
                    wait_time = ip_data.backoff_until - current_time
                    self.logger.debug(f"IP {address} in backoff period, wait {wait_time:.1f}s")
                    return False, wait_time

                # Check rate limit
                max_attempts = self.config.get_max_attempts_per_minute()
                burst_allowance = self.config.get_burst_allowance()

                # Allow burst above base rate limit
                effective_limit = max_attempts + burst_allowance

                if len(ip_data.attempts) >= effective_limit:
                    # Rate limit exceeded
                    self.logger.warning(f"Rate limit exceeded for IP {address}: {len(ip_data.attempts)} attempts in window")
                    return False, self.config.rate_limit_window_seconds

                return True, 0.0

    async def record_connection_attempt(self, address: str, success: bool = True,
                                      failure_type: ConnectionFailureType = ConnectionFailureType.OTHER):
        """
        Record a connection attempt
        """
        async with self._lock:
            current_time = time.time()
            ip_data = self._get_ip_data(address)

            with ip_data.lock:
                attempt = ConnectionAttempt(
                    timestamp=current_time,
                    failure_type=failure_type
                )

                # Add to attempts deque
                ip_data.attempts.append(attempt)

                if success:
                    # Reset failure tracking on success
                    ip_data.consecutive_failures = 0
                    ip_data.backoff_until = 0.0
                    ip_data.last_failure_type = None
                    self.logger.debug(f"Successful connection from IP {address}")
                else:
                    # Handle failure
                    ip_data.consecutive_failures += 1
                    ip_data.total_failures += 1
                    ip_data.last_failure_type = failure_type

                    # Calculate and set backoff
                    backoff_duration = self._calculate_backoff(ip_data.consecutive_failures)
                    ip_data.backoff_until = current_time + backoff_duration

                    self.logger.warning(
                        f"Connection failed from IP {address}: {failure_type.value}, "
                        f"consecutive failures: {ip_data.consecutive_failures}, "
                        f"backoff: {backoff_duration:.1f}s"
                    )

    async def get_ip_stats(self, address: str) -> Dict[str, Any]:
        """Get rate limiting statistics for an IP"""
        async with self._lock:
            current_time = time.time()
            ip_data = self._get_ip_data(address)

            with ip_data.lock:
                self._clean_old_attempts(ip_data, current_time)

                return {
                    'attempts_in_window': len(ip_data.attempts),
                    'consecutive_failures': ip_data.consecutive_failures,
                    'total_failures': ip_data.total_failures,
                    'backoff_until': max(0.0, ip_data.backoff_until - current_time),
                    'last_failure_type': ip_data.last_failure_type.value if ip_data.last_failure_type else None,
                    'rate_limit_window_seconds': self.config.rate_limit_window_seconds,
                    'max_attempts_per_minute': self.config.get_max_attempts_per_minute()
                }

    async def _cleanup_loop(self):
        """Clean up old rate limit data"""
        while self.running:
            try:
                await asyncio.sleep(self.config.cleanup_interval_seconds)
                current_time = time.time()
                cutoff_time = current_time - self.config.rate_limit_window_seconds * 2

                # Clean up old IP data
                to_remove = []
                for ip, ip_data in self.ip_data.items():
                    with ip_data.lock:
                        # Remove old attempts
                        self._clean_old_attempts(ip_data, cutoff_time)

                        # If no recent activity and no backoff, mark for removal
                        if (not ip_data.attempts and
                            ip_data.backoff_until < current_time and
                            ip_data.consecutive_failures == 0):
                            to_remove.append(ip)

                # Remove old entries
                for ip in to_remove:
                    del self.ip_data[ip]

                if to_remove:
                    self.logger.debug(f"Cleaned up rate limit data for {len(to_remove)} IPs")

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in rate limiter cleanup: {e}")

class ConnectionManager:
    """Manages multiple peer-to-peer connections with pooling"""

    def __init__(self, max_connections: int = 50,
                 connection_timeout: float = 30.0,
                 keepalive_interval: float = 60.0,
                 pool_size: int = 20,
                 security_level: SecurityLevel = SecurityLevel.MEDIUM,
                 rate_limit_config: Optional[RateLimitConfig] = None):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.keepalive_interval = keepalive_interval
        self.pool_size = pool_size

        # Active connections
        self.connections: Dict[bytes, Connection] = {}

        # Connection pool for reuse
        self.connection_pool: Dict[bytes, ConnectionPoolEntry] = {}
        self.pool_lock = asyncio.Lock()

        # Known peers
        self.peers: Dict[bytes, PeerInfo] = {}

        # Connection callbacks
        self.on_connection_established: Optional[Callable[[Connection], None]] = None
        self.on_connection_lost: Optional[Callable[[bytes], None]] = None
        self.on_message_received: Optional[Callable[[bytes, bytes], None]] = None

        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.keepalive_task: Optional[asyncio.Task] = None
        self.pool_maintenance_task: Optional[asyncio.Task] = None

        # Enhanced rate limiting system
        self.rate_limiter: RateLimiter = None
        self.rate_limit_config = rate_limit_config or RateLimitConfig(security_level=security_level)

        # Legacy connection attempts tracking (for backward compatibility)
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

        # Initialize rate limiter
        self.rate_limiter = RateLimiter(self.rate_limit_config)
        await self.rate_limiter.start()

        # Start background tasks
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        self.pool_maintenance_task = asyncio.create_task(self._maintain_connection_pool())

        self.logger.info(f"Connection manager started with security level: {self.rate_limit_config.security_level.value}")
    
    async def stop(self):
        """Stop the connection manager"""
        if not self.running:
            return

        self.running = False

        # Stop rate limiter
        if self.rate_limiter:
            await self.rate_limiter.stop()

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

        if self.pool_maintenance_task:
            self.pool_maintenance_task.cancel()
            try:
                await self.pool_maintenance_task
            except asyncio.CancelledError:
                pass

        # Close all connections and clear pool
        await self._close_all_connections()
        async with self.pool_lock:
            self.connection_pool.clear()

        self.logger.info("Connection manager stopped")
    
    async def connect_to_peer(self, peer_info: PeerInfo) -> bool:
        """Connect to a peer with comprehensive rate limiting and security"""
        if peer_info.peer_id in self.connections:
            # Already connected
            self.logger.debug(f"Already connected to peer {peer_info.peer_id.hex()}")
            return True

        # Try to get connection from pool first
        pooled_connection = await self._get_pooled_connection(peer_info.peer_id)
        if pooled_connection:
            self.connections[peer_info.peer_id] = pooled_connection
            self.peers[peer_info.peer_id] = peer_info
            pooled_connection.update_activity()

            # Record successful connection for rate limiting
            if self.rate_limiter:
                await self.rate_limiter.record_connection_attempt(peer_info.address, success=True)

            self.logger.debug(f"Reused pooled connection to peer {peer_info.address}:{peer_info.port}")
            return True

        if len(self.connections) >= self.max_connections:
            self.logger.warning(f"Maximum connections reached ({self.max_connections})")
            return False

        # Enhanced rate limiting check
        if self.rate_limiter:
            can_connect, wait_time = await self.rate_limiter.can_attempt_connection(peer_info.address)

            if not can_connect:
                self.logger.warning(
                    f"Connection rate limited for {peer_info.address}: "
                    f"wait {wait_time:.1f}s or backoff period"
                )

                # Record rate limited attempt
                await self.rate_limiter.record_connection_attempt(
                    peer_info.address,
                    success=False,
                    failure_type=ConnectionFailureType.RATE_LIMITED
                )
                return False

        # Legacy rate limiting (fallback)
        if not self._can_attempt_connection(peer_info.address):
            self.logger.warning(f"Legacy rate limit exceeded for {peer_info.address}")
            return False

        try:
            self.logger.info(f"Attempting connection to peer {peer_info.address}:{peer_info.port}")

            # Record connection attempt for legacy tracking
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
                try:
                    self.on_connection_established(connection)
                except Exception as e:
                    self.logger.error(f"Error in connection established callback: {e}")

            # Record successful connection
            if self.rate_limiter:
                await self.rate_limiter.record_connection_attempt(peer_info.address, success=True)

            self.logger.info(f"Successfully connected to peer {peer_info.address}:{peer_info.port}")
            return True

        except asyncio.TimeoutError:
            self.logger.warning(f"Connection timeout to {peer_info.address}:{peer_info.port}")

            # Record timeout failure
            if self.rate_limiter:
                await self.rate_limiter.record_connection_attempt(
                    peer_info.address,
                    success=False,
                    failure_type=ConnectionFailureType.TIMEOUT
                )
            return False

        except ConnectionRefusedError:
            self.logger.warning(f"Connection refused by {peer_info.address}:{peer_info.port}")

            # Record connection refused failure
            if self.rate_limiter:
                await self.rate_limiter.record_connection_attempt(
                    peer_info.address,
                    success=False,
                    failure_type=ConnectionFailureType.REFUSED
                )
            return False

        except OSError as e:
            self.logger.warning(f"Network error connecting to {peer_info.address}:{peer_info.port}: {e}")

            # Record network error failure
            if self.rate_limiter:
                await self.rate_limiter.record_connection_attempt(
                    peer_info.address,
                    success=False,
                    failure_type=ConnectionFailureType.NETWORK_ERROR
                )
            return False

        except Exception as e:
            self.logger.error(f"Unexpected error connecting to {peer_info.address}:{peer_info.port}: {e}")

            # Record other failure type
            if self.rate_limiter:
                await self.rate_limiter.record_connection_attempt(
                    peer_info.address,
                    success=False,
                    failure_type=ConnectionFailureType.OTHER
                )
            return False
    
    async def disconnect_peer(self, peer_id: bytes):
        """Disconnect from a peer"""
        if peer_id not in self.connections:
            return

        connection = self.connections[peer_id]

        try:
            # Mark connection as closing
            connection.state = ConnectionState.CLOSING

            # Close writer
            if connection.writer and not connection.writer.is_closing():
                connection.writer.close()
                await connection.writer.wait_closed()

            # Close reader if it has a close method
            if hasattr(connection.reader, 'close'):
                connection.reader.close()

        except Exception as e:
            self.logger.error(f"Error closing connection to peer {peer_id.hex()}: {e}")
        finally:
            # Always remove from connections, even if cleanup failed
            if peer_id in self.connections:
                del self.connections[peer_id]

            # Notify callback
            if self.on_connection_lost:
                try:
                    self.on_connection_lost(peer_id)
                except Exception as e:
                    self.logger.error(f"Error in connection lost callback: {e}")

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

    def get_rate_limit_stats(self, address: Optional[str] = None) -> Dict[str, Any]:
        """Get rate limiting statistics"""
        if not self.rate_limiter:
            return {'error': 'Rate limiter not initialized'}

        if address:
            return self.rate_limiter.get_ip_stats(address)
        else:
            # Return general rate limiter stats
            return {
                'security_level': self.rate_limiter.config.security_level.value,
                'max_attempts_per_minute': self.rate_limiter.config.get_max_attempts_per_minute(),
                'rate_limit_window_seconds': self.rate_limiter.config.rate_limit_window_seconds,
                'tracked_ips': len(self.rate_limiter.ip_data)
            }

    def set_security_level(self, security_level: SecurityLevel):
        """Change the security level for rate limiting"""
        if not self.running:
            self.logger.warning("Cannot change security level while not running")
            return

        old_level = self.rate_limiter.config.security_level
        self.rate_limiter.config.security_level = security_level

        self.logger.info(f"Security level changed from {old_level.value} to {security_level.value}")

    def get_security_level(self) -> SecurityLevel:
        """Get current security level"""
        if self.rate_limiter:
            return self.rate_limiter.config.security_level
        return SecurityLevel.MEDIUM
    
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
            # Ensure connection is properly cleaned up
            peer_id = connection.peer_info.peer_id
            if peer_id in self.connections:
                await self.disconnect_peer(peer_id)
            else:
                # Connection was already removed, just ensure cleanup
                try:
                    if connection.writer and not connection.writer.is_closing():
                        connection.writer.close()
                        await connection.writer.wait_closed()
                except Exception:
                    pass  # Ignore cleanup errors in finally block
    
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

    async def _get_pooled_connection(self, peer_id: bytes) -> Optional[Connection]:
        """Get a connection from the pool"""
        async with self.pool_lock:
            if peer_id in self.connection_pool:
                entry = self.connection_pool[peer_id]
                if not entry.in_use and entry.connection.is_alive():
                    entry.in_use = True
                    entry.last_used = time.time()
                    return entry.connection
                else:
                    # Remove stale connection
                    del self.connection_pool[peer_id]
        return None

    async def return_connection_to_pool(self, peer_id: bytes):
        """Return a connection to the pool for reuse"""
        if peer_id not in self.connections:
            return

        connection = self.connections[peer_id]

        # Only pool if connection is healthy and we have space
        if (len(self.connection_pool) < self.pool_size and
            connection.is_alive() and
            connection.state == ConnectionState.CONNECTED):

            async with self.pool_lock:
                self.connection_pool[peer_id] = ConnectionPoolEntry(
                    connection=connection,
                    last_used=time.time(),
                    in_use=False
                )

            # Remove from active connections (but keep in peers)
            del self.connections[peer_id]
        else:
            # Close connection if not pooling
            await self.disconnect_peer(peer_id)

    async def _maintain_connection_pool(self):
        """Maintain the connection pool by cleaning up stale connections"""
        while self.running:
            try:
                current_time = time.time()
                async with self.pool_lock:
                    stale_peers = []
                    for peer_id, entry in self.connection_pool.items():
                        # Remove connections older than 5 minutes or not alive
                        if (current_time - entry.last_used > 300 or
                            not entry.connection.is_alive()):
                            stale_peers.append(peer_id)

                    for peer_id in stale_peers:
                        entry = self.connection_pool[peer_id]
                        if not entry.in_use:
                            await self.disconnect_peer(peer_id)
                        del self.connection_pool[peer_id]

                await asyncio.sleep(60)  # Check every minute

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Error in pool maintenance: {e}")
                await asyncio.sleep(60)