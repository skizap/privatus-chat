"""
Network Performance Optimizer

Implements comprehensive network performance optimizations including:
- Connection pooling and reuse
- Message batching and compression
- Adaptive bandwidth utilization
- Network congestion handling
"""

import asyncio
import time
import logging
import zlib
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import heapq

logger = logging.getLogger(__name__)


class ConnectionState(Enum):
    """Connection states for pool management"""
    IDLE = "idle"
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass
class PooledConnection:
    """Represents a pooled network connection"""
    connection_id: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    peer_id: bytes
    created_at: float
    last_used: float
    state: ConnectionState = ConnectionState.IDLE
    bytes_sent: int = 0
    bytes_received: int = 0
    message_count: int = 0
    
    def is_alive(self) -> bool:
        """Check if connection is still alive"""
        return not self.writer.is_closing() and self.state != ConnectionState.CLOSED
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_used = time.time()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get connection statistics"""
        return {
            'connection_id': self.connection_id,
            'peer_id': self.peer_id.hex(),
            'age': time.time() - self.created_at,
            'idle_time': time.time() - self.last_used,
            'bytes_sent': self.bytes_sent,
            'bytes_received': self.bytes_received,
            'message_count': self.message_count,
            'state': self.state.value
        }


class ConnectionPool:
    """Advanced connection pool with load balancing and health monitoring"""
    
    def __init__(self, max_connections: int = 1000, 
                 connection_timeout: float = 30.0,
                 idle_timeout: float = 300.0,
                 health_check_interval: float = 60.0):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.idle_timeout = idle_timeout
        self.health_check_interval = health_check_interval
        
        # Connection storage
        self.connections: Dict[str, PooledConnection] = {}
        self.peer_connections: Dict[bytes, Set[str]] = defaultdict(set)
        self.idle_connections: Set[str] = set()
        
        # Connection statistics
        self.total_connections_created = 0
        self.total_connections_reused = 0
        self.total_connections_closed = 0
        
        # Background tasks
        self.cleanup_task: Optional[asyncio.Task] = None
        self.health_check_task: Optional[asyncio.Task] = None
        
        self.running = False
        
    async def start(self):
        """Start the connection pool"""
        if self.running:
            return
        
        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        self.health_check_task = asyncio.create_task(self._health_check_loop())
        
        logger.info(f"Connection pool started (max_connections: {self.max_connections})")
    
    async def stop(self):
        """Stop the connection pool and close all connections"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel background tasks
        if self.cleanup_task:
            self.cleanup_task.cancel()
        if self.health_check_task:
            self.health_check_task.cancel()
        
        # Close all connections
        for connection in list(self.connections.values()):
            await self._close_connection(connection)
        
        logger.info("Connection pool stopped")
    
    async def get_connection(self, peer_id: bytes) -> Optional[PooledConnection]:
        """Get a connection to the specified peer (reuse or create new)"""
        # Try to reuse existing idle connection
        peer_connection_ids = self.peer_connections.get(peer_id, set())
        
        for conn_id in peer_connection_ids:
            if conn_id in self.idle_connections:
                connection = self.connections[conn_id]
                if connection.is_alive():
                    # Reuse connection
                    connection.state = ConnectionState.ACTIVE
                    connection.update_activity()
                    self.idle_connections.discard(conn_id)
                    self.total_connections_reused += 1
                    
                    logger.debug(f"Reused connection {conn_id} for peer {peer_id.hex()}")
                    return connection
        
        # Create new connection if we haven't reached the limit
        if len(self.connections) >= self.max_connections:
            # Try to close some idle connections
            await self._cleanup_idle_connections()
            
            if len(self.connections) >= self.max_connections:
                logger.warning("Connection pool is full, cannot create new connection")
                return None
        
        # This would normally establish a new connection
        # For now, we'll simulate connection creation
        connection_id = f"conn_{time.time()}_{len(self.connections)}"
        
        # In a real implementation, this would connect to the peer
        # For now, we'll create a mock connection
        reader = None  # Would be actual StreamReader
        writer = None  # Would be actual StreamWriter
        
        connection = PooledConnection(
            connection_id=connection_id,
            reader=reader,
            writer=writer,
            peer_id=peer_id,
            created_at=time.time(),
            last_used=time.time(),
            state=ConnectionState.ACTIVE
        )
        
        # Add to pool
        self.connections[connection_id] = connection
        self.peer_connections[peer_id].add(connection_id)
        self.total_connections_created += 1
        
        logger.debug(f"Created new connection {connection_id} for peer {peer_id.hex()}")
        return connection
    
    async def return_connection(self, connection: PooledConnection):
        """Return a connection to the pool (mark as idle)"""
        if connection.connection_id not in self.connections:
            return
        
        if connection.is_alive():
            connection.state = ConnectionState.IDLE
            connection.update_activity()
            self.idle_connections.add(connection.connection_id)
            
            logger.debug(f"Returned connection {connection.connection_id} to pool")
        else:
            await self._close_connection(connection)
    
    async def _close_connection(self, connection: PooledConnection):
        """Close and remove a connection from the pool"""
        connection_id = connection.connection_id
        
        if connection_id not in self.connections:
            return
        
        connection.state = ConnectionState.CLOSING
        
        # Close the actual connection
        if connection.writer and not connection.writer.is_closing():
            connection.writer.close()
            try:
                await connection.writer.wait_closed()
            except Exception as e:
                logger.warning(f"Error closing connection {connection_id}: {e}")
        
        # Remove from pool
        del self.connections[connection_id]
        self.peer_connections[connection.peer_id].discard(connection_id)
        self.idle_connections.discard(connection_id)
        
        connection.state = ConnectionState.CLOSED
        self.total_connections_closed += 1
        
        logger.debug(f"Closed connection {connection_id}")
    
    async def _cleanup_loop(self):
        """Background task to clean up stale connections"""
        while self.running:
            try:
                await self._cleanup_idle_connections()
                await asyncio.sleep(self.idle_timeout / 2)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in connection cleanup: {e}")
                await asyncio.sleep(10)
    
    async def _cleanup_idle_connections(self):
        """Clean up idle connections that have timed out"""
        current_time = time.time()
        stale_connections = []
        
        for conn_id in list(self.idle_connections):
            connection = self.connections.get(conn_id)
            if not connection:
                self.idle_connections.discard(conn_id)
                continue
            
            # Check if connection is stale
            if (current_time - connection.last_used > self.idle_timeout or
                not connection.is_alive()):
                stale_connections.append(connection)
        
        # Close stale connections
        for connection in stale_connections:
            await self._close_connection(connection)
    
    async def _health_check_loop(self):
        """Background task to perform health checks on connections"""
        while self.running:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check: {e}")
                await asyncio.sleep(30)
    
    async def _perform_health_checks(self):
        """Perform health checks on all connections"""
        unhealthy_connections = []
        
        for connection in self.connections.values():
            if not connection.is_alive():
                unhealthy_connections.append(connection)
        
        # Close unhealthy connections
        for connection in unhealthy_connections:
            await self._close_connection(connection)
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics"""
        idle_count = len(self.idle_connections)
        active_count = len(self.connections) - idle_count
        
        return {
            'total_connections': len(self.connections),
            'active_connections': active_count,
            'idle_connections': idle_count,
            'max_connections': self.max_connections,
            'utilization': len(self.connections) / self.max_connections,
            'total_created': self.total_connections_created,
            'total_reused': self.total_connections_reused,
            'total_closed': self.total_connections_closed,
            'reuse_rate': (self.total_connections_reused / max(1, self.total_connections_created + self.total_connections_reused))
        }


@dataclass
class BatchedMessage:
    """Represents a message waiting to be batched"""
    peer_id: bytes
    data: bytes
    timestamp: float
    priority: int = 0
    
    def __lt__(self, other):
        return self.priority > other.priority  # Higher priority first


class MessageBatcher:
    """Batches messages for efficient network transmission"""
    
    def __init__(self, batch_size: int = 100, 
                 batch_timeout: float = 0.1,
                 compression_threshold: int = 1024,
                 max_batch_size: int = 64 * 1024):  # 64KB max
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        self.compression_threshold = compression_threshold
        self.max_batch_size = max_batch_size
        
        # Message queues per peer
        self.message_queues: Dict[bytes, List[BatchedMessage]] = defaultdict(list)
        self.batch_timers: Dict[bytes, asyncio.Task] = {}
        
        # Statistics
        self.total_messages_batched = 0
        self.total_batches_sent = 0
        self.total_bytes_saved = 0
        
        self.running = False
        
    async def start(self):
        """Start the message batcher"""
        self.running = True
        logger.info("Message batcher started")
    
    async def stop(self):
        """Stop the message batcher and flush all queues"""
        self.running = False
        
        # Cancel all batch timers
        for timer in self.batch_timers.values():
            timer.cancel()
        self.batch_timers.clear()
        
        # Flush all queues
        for peer_id in list(self.message_queues.keys()):
            await self._flush_queue(peer_id)
        
        logger.info("Message batcher stopped")
    
    async def queue_message(self, peer_id: bytes, data: bytes, priority: int = 0):
        """Queue a message for batching"""
        if not self.running:
            return
        
        message = BatchedMessage(
            peer_id=peer_id,
            data=data,
            timestamp=time.time(),
            priority=priority
        )
        
        # Add to queue
        heapq.heappush(self.message_queues[peer_id], message)
        
        # Check if we should flush immediately
        if len(self.message_queues[peer_id]) >= self.batch_size:
            await self._flush_queue(peer_id)
        else:
            # Set timer for timeout-based flushing
            if peer_id not in self.batch_timers:
                self.batch_timers[peer_id] = asyncio.create_task(
                    self._batch_timeout(peer_id)
                )
    
    async def _batch_timeout(self, peer_id: bytes):
        """Handle batch timeout for a peer"""
        try:
            await asyncio.sleep(self.batch_timeout)
            await self._flush_queue(peer_id)
        except asyncio.CancelledError:
            pass
    
    async def _flush_queue(self, peer_id: bytes):
        """Flush the message queue for a peer"""
        if peer_id not in self.message_queues:
            return
        
        queue = self.message_queues[peer_id]
        if not queue:
            return
        
        # Cancel timer
        if peer_id in self.batch_timers:
            self.batch_timers[peer_id].cancel()
            del self.batch_timers[peer_id]
        
        # Create batch
        batch_messages = []
        batch_size = 0
        
        while queue and batch_size < self.max_batch_size:
            message = heapq.heappop(queue)
            batch_messages.append(message)
            batch_size += len(message.data)
        
        if batch_messages:
            await self._send_batch(peer_id, batch_messages)
    
    async def _send_batch(self, peer_id: bytes, messages: List[BatchedMessage]):
        """Send a batch of messages"""
        if not messages:
            return
        
        # Prepare batch data
        batch_data = self._create_batch_payload(messages)
        
        # Compress if beneficial
        if len(batch_data) > self.compression_threshold:
            compressed_data = zlib.compress(batch_data)
            if len(compressed_data) < len(batch_data):
                batch_data = b'\x01' + compressed_data  # Compression marker
                self.total_bytes_saved += len(batch_data) - len(compressed_data)
            else:
                batch_data = b'\x00' + batch_data  # No compression marker
        else:
            batch_data = b'\x00' + batch_data
        
        # Send batch (would integrate with connection pool)
        # For now, we'll just log the batch
        logger.debug(f"Sending batch to {peer_id.hex()}: {len(messages)} messages, {len(batch_data)} bytes")
        
        # Update statistics
        self.total_messages_batched += len(messages)
        self.total_batches_sent += 1
    
    def _create_batch_payload(self, messages: List[BatchedMessage]) -> bytes:
        """Create batch payload from messages"""
        payload = bytearray()
        
        # Add message count
        payload.extend(len(messages).to_bytes(4, 'big'))
        
        # Add each message with length prefix
        for message in messages:
            payload.extend(len(message.data).to_bytes(4, 'big'))
            payload.extend(message.data)
        
        return bytes(payload)
    
    def get_batch_stats(self) -> Dict[str, Any]:
        """Get batching statistics"""
        queued_messages = sum(len(queue) for queue in self.message_queues.values())
        
        return {
            'queued_messages': queued_messages,
            'active_queues': len(self.message_queues),
            'total_messages_batched': self.total_messages_batched,
            'total_batches_sent': self.total_batches_sent,
            'total_bytes_saved': self.total_bytes_saved,
            'average_batch_size': (self.total_messages_batched / max(1, self.total_batches_sent))
        }


class BandwidthManager:
    """Manages bandwidth allocation and throttling"""
    
    def __init__(self, max_bandwidth: int = 10 * 1024 * 1024,  # 10MB/s
                 window_size: float = 1.0,
                 burst_allowance: float = 1.5):
        self.max_bandwidth = max_bandwidth
        self.window_size = window_size
        self.burst_allowance = burst_allowance
        
        # Bandwidth tracking
        self.bandwidth_history: deque = deque(maxlen=100)
        self.current_usage = 0
        self.last_update = time.time()
        
        # Per-peer bandwidth tracking
        self.peer_bandwidth: Dict[bytes, deque] = defaultdict(lambda: deque(maxlen=10))
        
        # Throttling
        self.throttled_peers: Set[bytes] = set()
        
    def record_transfer(self, peer_id: bytes, bytes_transferred: int):
        """Record a data transfer"""
        current_time = time.time()
        
        # Update global bandwidth tracking
        self.bandwidth_history.append((current_time, bytes_transferred))
        
        # Update per-peer tracking
        self.peer_bandwidth[peer_id].append((current_time, bytes_transferred))
        
        # Update current usage
        self._update_current_usage()
    
    def _update_current_usage(self):
        """Update current bandwidth usage"""
        current_time = time.time()
        cutoff_time = current_time - self.window_size
        
        # Calculate usage in the current window
        total_bytes = 0
        for timestamp, bytes_transferred in self.bandwidth_history:
            if timestamp > cutoff_time:
                total_bytes += bytes_transferred
        
        self.current_usage = total_bytes / self.window_size
        self.last_update = current_time
    
    def can_send(self, peer_id: bytes, data_size: int) -> bool:
        """Check if we can send data without exceeding bandwidth limits"""
        self._update_current_usage()
        
        # Check global bandwidth limit
        if self.current_usage + data_size > self.max_bandwidth * self.burst_allowance:
            return False
        
        # Check if peer is throttled
        if peer_id in self.throttled_peers:
            # Check if throttling should be lifted
            if self._should_unthrottle_peer(peer_id):
                self.throttled_peers.discard(peer_id)
            else:
                return False
        
        return True
    
    def _should_unthrottle_peer(self, peer_id: bytes) -> bool:
        """Check if a peer should be unthrottled"""
        current_time = time.time()
        cutoff_time = current_time - self.window_size
        
        # Calculate peer's recent usage
        peer_usage = 0
        for timestamp, bytes_transferred in self.peer_bandwidth[peer_id]:
            if timestamp > cutoff_time:
                peer_usage += bytes_transferred
        
        # Unthrottle if usage is reasonable
        peer_limit = self.max_bandwidth * 0.1  # 10% of total bandwidth per peer
        return peer_usage < peer_limit
    
    async def throttle_if_needed(self, peer_id: bytes, data_size: int):
        """Apply throttling if bandwidth limits are exceeded"""
        if not self.can_send(peer_id, data_size):
            # Calculate delay needed
            delay = self._calculate_throttle_delay(data_size)
            if delay > 0:
                await asyncio.sleep(delay)
    
    def _calculate_throttle_delay(self, data_size: int) -> float:
        """Calculate delay needed for throttling"""
        if self.current_usage <= self.max_bandwidth:
            return 0.0
        
        # Calculate how long to wait
        excess_bandwidth = self.current_usage - self.max_bandwidth
        delay = (excess_bandwidth + data_size) / self.max_bandwidth
        
        return min(delay, 1.0)  # Cap at 1 second
    
    def get_bandwidth_stats(self) -> Dict[str, Any]:
        """Get bandwidth statistics"""
        self._update_current_usage()
        
        return {
            'current_usage': self.current_usage,
            'max_bandwidth': self.max_bandwidth,
            'utilization': self.current_usage / self.max_bandwidth,
            'throttled_peers': len(self.throttled_peers),
            'total_peers': len(self.peer_bandwidth)
        }


class CongestionController:
    """Handles network congestion detection and mitigation"""
    
    def __init__(self, congestion_threshold: float = 0.8,
                 recovery_threshold: float = 0.6,
                 backoff_factor: float = 2.0,
                 max_backoff: float = 30.0):
        self.congestion_threshold = congestion_threshold
        self.recovery_threshold = recovery_threshold
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        
        # Congestion state
        self.is_congested = False
        self.congestion_level = 0.0
        self.current_backoff = 0.0
        
        # Metrics
        self.rtt_samples: deque = deque(maxlen=100)
        self.packet_loss_samples: deque = deque(maxlen=50)
        
    def record_rtt(self, rtt: float):
        """Record a round-trip time measurement"""
        self.rtt_samples.append((time.time(), rtt))
        self._update_congestion_level()
    
    def record_packet_loss(self, loss_rate: float):
        """Record packet loss rate"""
        self.packet_loss_samples.append((time.time(), loss_rate))
        self._update_congestion_level()
    
    def _update_congestion_level(self):
        """Update congestion level based on metrics"""
        if not self.rtt_samples:
            return
        
        # Calculate recent RTT statistics
        recent_rtts = [rtt for _, rtt in self.rtt_samples[-20:]]
        if not recent_rtts:
            return
        
        avg_rtt = sum(recent_rtts) / len(recent_rtts)
        baseline_rtt = min(recent_rtts) if recent_rtts else avg_rtt
        
        # Calculate RTT-based congestion indicator
        rtt_congestion = max(0, (avg_rtt - baseline_rtt) / baseline_rtt) if baseline_rtt > 0 else 0
        
        # Calculate packet loss-based congestion indicator
        loss_congestion = 0.0
        if self.packet_loss_samples:
            recent_losses = [loss for _, loss in self.packet_loss_samples[-10:]]
            loss_congestion = sum(recent_losses) / len(recent_losses)
        
        # Combine indicators
        self.congestion_level = min(1.0, max(rtt_congestion, loss_congestion))
        
        # Update congestion state
        if not self.is_congested and self.congestion_level > self.congestion_threshold:
            self._enter_congestion_state()
        elif self.is_congested and self.congestion_level < self.recovery_threshold:
            self._exit_congestion_state()
    
    def _enter_congestion_state(self):
        """Enter congestion state and apply backoff"""
        self.is_congested = True
        self.current_backoff = min(self.max_backoff, 
                                 max(0.1, self.current_backoff * self.backoff_factor))
        
        logger.warning(f"Network congestion detected (level: {self.congestion_level:.2f}), "
                      f"applying backoff: {self.current_backoff:.2f}s")
    
    def _exit_congestion_state(self):
        """Exit congestion state"""
        self.is_congested = False
        self.current_backoff = 0.0
        
        logger.info(f"Network congestion cleared (level: {self.congestion_level:.2f})")
    
    async def apply_congestion_control(self):
        """Apply congestion control delay if needed"""
        if self.is_congested and self.current_backoff > 0:
            await asyncio.sleep(self.current_backoff)
    
    def get_congestion_stats(self) -> Dict[str, Any]:
        """Get congestion control statistics"""
        avg_rtt = 0.0
        if self.rtt_samples:
            recent_rtts = [rtt for _, rtt in self.rtt_samples[-20:]]
            avg_rtt = sum(recent_rtts) / len(recent_rtts) if recent_rtts else 0.0
        
        avg_loss = 0.0
        if self.packet_loss_samples:
            recent_losses = [loss for _, loss in self.packet_loss_samples[-10:]]
            avg_loss = sum(recent_losses) / len(recent_losses) if recent_losses else 0.0
        
        return {
            'is_congested': self.is_congested,
            'congestion_level': self.congestion_level,
            'current_backoff': self.current_backoff,
            'average_rtt': avg_rtt,
            'average_packet_loss': avg_loss,
            'rtt_samples': len(self.rtt_samples),
            'loss_samples': len(self.packet_loss_samples)
        }


class NetworkOptimizer:
    """Main network performance optimizer"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}
        
        # Initialize components
        self.connection_pool = ConnectionPool(
            max_connections=config.get('max_connections', 1000),
            connection_timeout=config.get('connection_timeout', 30.0)
        )
        
        self.message_batcher = MessageBatcher(
            batch_size=config.get('batch_size', 100),
            batch_timeout=config.get('batch_timeout', 0.1)
        )
        
        self.bandwidth_manager = BandwidthManager(
            max_bandwidth=config.get('bandwidth_limit', 10 * 1024 * 1024)
        )
        
        self.congestion_controller = CongestionController(
            congestion_threshold=config.get('congestion_threshold', 0.8)
        )
        
        self.running = False
    
    async def start(self):
        """Start the network optimizer"""
        if self.running:
            return
        
        self.running = True
        
        await self.connection_pool.start()
        await self.message_batcher.start()
        
        logger.info("Network optimizer started")
    
    async def stop(self):
        """Stop the network optimizer"""
        if not self.running:
            return
        
        self.running = False
        
        await self.connection_pool.stop()
        await self.message_batcher.stop()
        
        logger.info("Network optimizer stopped")
    
    async def send_message(self, peer_id: bytes, data: bytes, priority: int = 0) -> bool:
        """Send a message with optimization"""
        if not self.running:
            return False
        
        # Check bandwidth limits
        if not self.bandwidth_manager.can_send(peer_id, len(data)):
            await self.bandwidth_manager.throttle_if_needed(peer_id, len(data))
        
        # Apply congestion control
        await self.congestion_controller.apply_congestion_control()
        
        # Queue for batching
        await self.message_batcher.queue_message(peer_id, data, priority)
        
        # Record bandwidth usage
        self.bandwidth_manager.record_transfer(peer_id, len(data))
        
        return True
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics"""
        return {
            'connection_pool': self.connection_pool.get_pool_stats(),
            'message_batcher': self.message_batcher.get_batch_stats(),
            'bandwidth_manager': self.bandwidth_manager.get_bandwidth_stats(),
            'congestion_controller': self.congestion_controller.get_congestion_stats()
        } 