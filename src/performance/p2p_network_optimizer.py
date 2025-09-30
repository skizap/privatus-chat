"""
P2P Network Performance Optimizer

Specialized optimizations for peer-to-peer networking including:
- DHT performance optimization
- Peer discovery acceleration
- Message routing optimization
- Connection management for large networks
"""

import asyncio
import time
import logging
import hashlib
import threading
from typing import Dict, List, Optional, Any, Set, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import heapq
import math

logger = logging.getLogger(__name__)


class PeerState(Enum):
    """Peer connection states"""
    CONNECTING = "connecting"
    CONNECTED = "connected"
    DISCONNECTING = "disconnecting"
    DISCONNECTED = "disconnected"
    UNREACHABLE = "unreachable"


@dataclass
class P2PPeer:
    """Represents a P2P network peer"""
    peer_id: bytes
    address: str
    port: int
    node_id: bytes
    state: PeerState = PeerState.DISCONNECTED
    last_seen: float = field(default_factory=time.time)
    response_time: float = 0.0
    connection_quality: float = 1.0
    messages_sent: int = 0
    messages_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    capabilities: Set[str] = field(default_factory=set)

    def update_response_time(self, response_time: float):
        """Update response time with exponential moving average"""
        self.response_time = (self.response_time * 0.8) + (response_time * 0.2)
        self.last_seen = time.time()

    def update_connection_quality(self, success: bool):
        """Update connection quality based on success/failure"""
        if success:
            self.connection_quality = min(1.0, self.connection_quality + 0.01)
        else:
            self.connection_quality = max(0.0, self.connection_quality - 0.05)

    def get_peer_score(self) -> float:
        """Calculate peer score for selection"""
        # Combine response time, quality, and activity
        time_score = 1.0 / (1.0 + self.response_time)
        quality_score = self.connection_quality
        activity_score = min(1.0, (self.messages_sent + self.messages_received) / 100)

        return time_score * quality_score * activity_score


class DHTOptimizer:
    """Optimizes Distributed Hash Table operations"""

    def __init__(self, k: int = 20, alpha: int = 3):
        self.k = k  # Maximum nodes per bucket
        self.alpha = alpha  # Concurrency parameter

        # DHT state
        self.routing_table: Dict[bytes, List[P2PPeer]] = defaultdict(list)
        self.node_id = None  # Our node ID

        # Performance tracking
        self.lookup_cache: Dict[bytes, Tuple[List[P2PPeer], float]] = {}
        self.cache_ttl = 300.0  # 5 minutes

        # Statistics
        self.lookups_performed = 0
        self.cache_hits = 0
        self.average_hops = 0.0

        # Thread safety
        self._lock = threading.RLock()

    def set_node_id(self, node_id: bytes):
        """Set our node ID"""
        self.node_id = node_id

    def update_routing_table(self, peers: List[P2PPeer]):
        """Update routing table with new peer information"""
        with self._lock:
            for peer in peers:
                peer_id = peer.peer_id

                # Add to appropriate bucket
                if peer_id not in [p.peer_id for p in self.routing_table[peer_id[:1]]]:
                    self.routing_table[peer_id[:1]].append(peer)

                    # Keep only k closest nodes per bucket
                    self.routing_table[peer_id[:1]].sort(
                        key=lambda p: self._calculate_distance(peer_id, p.peer_id)
                    )
                    self.routing_table[peer_id[:1]] = self.routing_table[peer_id[:1]][:self.k]

    def find_closest_nodes(self, target_id: bytes, count: int = self.k) -> List[P2PPeer]:
        """Find k closest nodes to target ID"""
        with self._lock:
            # Check cache first
            cache_key = target_id
            current_time = time.time()

            if cache_key in self.lookup_cache:
                cached_nodes, cache_time = self.lookup_cache[cache_key]
                if current_time - cache_time < self.cache_ttl:
                    self.cache_hits += 1
                    return cached_nodes[:count]

            # Find closest nodes across all buckets
            all_nodes = []
            for bucket in self.routing_table.values():
                all_nodes.extend(bucket)

            # Sort by distance to target
            all_nodes.sort(key=lambda p: self._calculate_distance(target_id, p.peer_id))

            # Cache result
            self.lookup_cache[cache_key] = (all_nodes[:count], current_time)
            self.lookups_performed += 1

            return all_nodes[:count]

    def _calculate_distance(self, id1: bytes, id2: bytes) -> int:
        """Calculate XOR distance between two node IDs"""
        return int.from_bytes(id1, 'big') ^ int.from_bytes(id2, 'big')

    def get_dht_stats(self) -> Dict[str, Any]:
        """Get DHT performance statistics"""
        with self._lock:
            total_nodes = sum(len(peers) for peers in self.routing_table.values())

            return {
                'total_nodes': total_nodes,
                'buckets': len(self.routing_table),
                'lookups_performed': self.lookups_performed,
                'cache_hits': self.cache_hits,
                'cache_size': len(self.lookup_cache),
                'cache_hit_rate': self.cache_hits / max(1, self.lookups_performed)
            }


class PeerDiscoveryOptimizer:
    """Optimizes peer discovery process"""

    def __init__(self, max_concurrent_discoveries: int = 10,
                 discovery_timeout: float = 5.0):
        self.max_concurrent_discoveries = max_concurrent_discoveries
        self.discovery_timeout = discovery_timeout

        # Discovery state
        self.discovery_queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self.active_discoveries: Set[str] = set()
        self.discovered_peers: Dict[bytes, P2PPeer] = {}

        # Discovery strategies
        self.strategies = ['bootstrap', 'random_walk', 'neighborhood']

        # Statistics
        self.discoveries_attempted = 0
        self.discoveries_successful = 0
        self.average_discovery_time = 0.0

        # Thread safety
        self._lock = threading.RLock()

    async def start(self):
        """Start the peer discovery optimizer"""
        # Start discovery workers
        self.discovery_workers = []
        for i in range(self.max_concurrent_discoveries):
            worker = asyncio.create_task(self._discovery_worker(i))
            self.discovery_workers.append(worker)

        logger.info(f"Peer discovery optimizer started with {self.max_concurrent_discoveries} workers")

    async def stop(self):
        """Stop the peer discovery optimizer"""
        # Cancel discovery workers
        for worker in self.discovery_workers:
            worker.cancel()

        # Wait for workers to finish
        await asyncio.gather(*self.discovery_workers, return_exceptions=True)

        logger.info("Peer discovery optimizer stopped")

    async def discover_peers(self, target_count: int = 20) -> List[P2PPeer]:
        """Discover peers up to target count"""
        with self._lock:
            # Check if we already have enough peers
            available_peers = [p for p in self.discovered_peers.values()
                             if p.state == PeerState.CONNECTED]
            if len(available_peers) >= target_count:
                return available_peers[:target_count]

        # Queue discovery tasks
        discovery_tasks = []

        # Use different strategies
        for strategy in self.strategies:
            task = self._queue_discovery(strategy, target_count // len(self.strategies))
            discovery_tasks.append(task)

        # Wait for discoveries to complete
        results = await asyncio.gather(*discovery_tasks, return_exceptions=True)

        # Collect discovered peers
        new_peers = []
        for result in results:
            if isinstance(result, list):
                new_peers.extend(result)

        # Update discovered peers
        with self._lock:
            for peer in new_peers:
                self.discovered_peers[peer.peer_id] = peer

        return new_peers

    async def _queue_discovery(self, strategy: str, count: int) -> List[P2PPeer]:
        """Queue a discovery task"""
        # This would implement actual discovery logic
        # For now, return empty list
        return []

    async def _discovery_worker(self, worker_id: int):
        """Discovery worker loop"""
        logger.debug(f"Discovery worker {worker_id} started")

        while True:
            try:
                # Get discovery task from queue
                priority, strategy, count = await self.discovery_queue.get()

                start_time = time.time()
                self.discoveries_attempted += 1

                # Perform discovery
                peers = await self._perform_discovery(strategy, count)

                discovery_time = time.time() - start_time

                # Update statistics
                if peers:
                    self.discoveries_successful += 1
                    self.average_discovery_time = (
                        (self.average_discovery_time * 0.9) +
                        (discovery_time * 0.1)
                    )

                # Mark task as done
                self.discovery_queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Discovery worker {worker_id} error: {e}")

        logger.debug(f"Discovery worker {worker_id} stopped")

    async def _perform_discovery(self, strategy: str, count: int) -> List[P2PPeer]:
        """Perform peer discovery using specified strategy"""
        # This would implement actual discovery strategies
        # For now, return empty list
        return []

    def get_discovery_stats(self) -> Dict[str, Any]:
        """Get discovery statistics"""
        with self._lock:
            success_rate = self.discoveries_successful / max(1, self.discoveries_attempted)

            return {
                'discoveries_attempted': self.discoveries_attempted,
                'discoveries_successful': self.discoveries_successful,
                'success_rate': success_rate,
                'average_discovery_time': self.average_discovery_time,
                'discovered_peers': len(self.discovered_peers),
                'active_discoveries': len(self.active_discoveries)
            }


class MessageRoutingOptimizer:
    """Optimizes message routing in P2P network"""

    def __init__(self, max_routes: int = 1000, route_ttl: float = 3600.0):
        self.max_routes = max_routes
        self.route_ttl = route_ttl

        # Routing table
        self.routes: Dict[bytes, Dict[str, Any]] = {}
        self.route_access_times: Dict[bytes, float] = {}

        # Message routing statistics
        self.messages_routed = 0
        self.routes_created = 0
        self.routes_expired = 0

        # Thread safety
        self._lock = threading.RLock()

    def add_route(self, destination: bytes, next_hop: bytes, distance: int = 1):
        """Add a route to the routing table"""
        with self._lock:
            current_time = time.time()

            self.routes[destination] = {
                'next_hop': next_hop,
                'distance': distance,
                'created_at': current_time,
                'last_accessed': current_time
            }
            self.route_access_times[destination] = current_time
            self.routes_created += 1

            # Cleanup old routes if needed
            if len(self.routes) > self.max_routes:
                self._cleanup_expired_routes()

    def get_next_hop(self, destination: bytes) -> Optional[bytes]:
        """Get next hop for destination"""
        with self._lock:
            if destination not in self.routes:
                return None

            route = self.routes[destination]
            current_time = time.time()

            # Check if route expired
            if current_time - route['created_at'] > self.route_ttl:
                del self.routes[destination]
                del self.route_access_times[destination]
                self.routes_expired += 1
                return None

            # Update access time
            route['last_accessed'] = current_time
            self.route_access_times[destination] = current_time
            self.messages_routed += 1

            return route['next_hop']

    def _cleanup_expired_routes(self):
        """Clean up expired routes"""
        current_time = time.time()
        expired_routes = []

        for destination, route in self.routes.items():
            if current_time - route['created_at'] > self.route_ttl:
                expired_routes.append(destination)

        for destination in expired_routes:
            del self.routes[destination]
            del self.route_access_times[destination]
            self.routes_expired += len(expired_routes)

    def get_routing_stats(self) -> Dict[str, Any]:
        """Get routing statistics"""
        with self._lock:
            return {
                'total_routes': len(self.routes),
                'messages_routed': self.messages_routed,
                'routes_created': self.routes_created,
                'routes_expired': self.routes_expired,
                'route_utilization': self.messages_routed / max(1, self.routes_created)
            }


class ConnectionPoolOptimizer:
    """Optimizes connection pool for P2P networking"""

    def __init__(self, max_connections: int = 1000,
                 connection_timeout: float = 30.0,
                 keepalive_interval: float = 60.0):
        self.max_connections = max_connections
        self.connection_timeout = connection_timeout
        self.keepalive_interval = keepalive_interval

        # Connection management
        self.connections: Dict[bytes, P2PPeer] = {}
        self.connection_quality_scores: Dict[bytes, float] = {}

        # Connection statistics
        self.total_connections_created = 0
        self.total_connections_closed = 0
        self.average_connection_lifetime = 0.0

        # Background tasks
        self.keepalive_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None

        # Thread safety
        self._lock = threading.RLock()

    async def start(self):
        """Start the connection pool optimizer"""
        self.keepalive_task = asyncio.create_task(self._keepalive_loop())
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("Connection pool optimizer started")

    async def stop(self):
        """Stop the connection pool optimizer"""
        # Cancel background tasks
        if self.keepalive_task:
            self.keepalive_task.cancel()
        if self.cleanup_task:
            self.cleanup_task.cancel()

        # Close all connections
        await self._close_all_connections()

        logger.info("Connection pool optimizer stopped")

    def add_peer_connection(self, peer: P2PPeer) -> bool:
        """Add a peer connection"""
        with self._lock:
            if len(self.connections) >= self.max_connections:
                # Remove lowest quality connection
                self._remove_lowest_quality_connection()

            if len(self.connections) < self.max_connections:
                self.connections[peer.peer_id] = peer
                self.connection_quality_scores[peer.peer_id] = peer.get_peer_score()
                self.total_connections_created += 1
                return True

            return False

    def remove_peer_connection(self, peer_id: bytes):
        """Remove a peer connection"""
        with self._lock:
            if peer_id in self.connections:
                del self.connections[peer_id]
                del self.connection_quality_scores[peer_id]
                self.total_connections_closed += 1

    def get_best_peer_for_message(self, message_size: int = 0) -> Optional[P2PPeer]:
        """Get best peer for sending a message"""
        with self._lock:
            if not self.connections:
                return None

            # Score peers based on quality and message size
            scored_peers = []
            for peer_id, peer in self.connections.items():
                if peer.state == PeerState.CONNECTED:
                    # Adjust score based on message size and peer capacity
                    quality_score = self.connection_quality_scores[peer_id]
                    capacity_score = self._calculate_capacity_score(peer, message_size)
                    total_score = quality_score * capacity_score

                    scored_peers.append((total_score, peer))

            if not scored_peers:
                return None

            # Return highest scoring peer
            scored_peers.sort(reverse=True)
            return scored_peers[0][1]

    def _calculate_capacity_score(self, peer: P2PPeer, message_size: int) -> float:
        """Calculate capacity score for a peer"""
        # Base capacity on response time and connection quality
        base_capacity = 1.0 / (1.0 + peer.response_time)

        # Adjust for message size (smaller messages get higher capacity)
        if message_size > 0:
            size_factor = min(1.0, 1024 / message_size)  # Favor smaller messages
            return base_capacity * size_factor

        return base_capacity

    def _remove_lowest_quality_connection(self):
        """Remove the lowest quality connection"""
        if not self.connection_quality_scores:
            return

        lowest_quality_peer = min(
            self.connection_quality_scores.items(),
            key=lambda x: x[1]
        )

        self.remove_peer_connection(lowest_quality_peer[0])

    async def _keepalive_loop(self):
        """Send keepalive messages to maintain connections"""
        while True:
            try:
                await self._send_keepalives()
                await asyncio.sleep(self.keepalive_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Keepalive loop error: {e}")
                await asyncio.sleep(10)

    async def _send_keepalives(self):
        """Send keepalive messages to all connected peers"""
        with self._lock:
            connected_peers = [p for p in self.connections.values()
                             if p.state == PeerState.CONNECTED]

        for peer in connected_peers:
            try:
                # Send keepalive (would implement actual keepalive logic)
                await self._send_keepalive_to_peer(peer)
            except Exception as e:
                logger.warning(f"Keepalive failed for peer {peer.peer_id.hex()[:8]}: {e}")
                peer.state = PeerState.UNREACHABLE

    async def _send_keepalive_to_peer(self, peer: P2PPeer):
        """Send keepalive to specific peer"""
        # This would implement actual keepalive sending
        # For now, just update the last seen time
        peer.last_seen = time.time()

    async def _cleanup_loop(self):
        """Clean up stale connections"""
        while True:
            try:
                await self._cleanup_stale_connections()
                await asyncio.sleep(300)  # Check every 5 minutes
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")
                await asyncio.sleep(60)

    async def _cleanup_stale_connections(self):
        """Clean up connections that haven't been seen recently"""
        current_time = time.time()
        stale_threshold = 600.0  # 10 minutes

        with self._lock:
            stale_peers = [
                peer_id for peer_id, peer in self.connections.items()
                if current_time - peer.last_seen > stale_threshold
            ]

        for peer_id in stale_peers:
            self.remove_peer_connection(peer_id)
            logger.debug(f"Removed stale connection: {peer_id.hex()[:8]}")

    async def _close_all_connections(self):
        """Close all connections"""
        with self._lock:
            peer_ids = list(self.connections.keys())

        for peer_id in peer_ids:
            self.remove_peer_connection(peer_id)

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics"""
        with self._lock:
            connected_count = sum(1 for p in self.connections.values()
                                if p.state == PeerState.CONNECTED)

            return {
                'total_connections': len(self.connections),
                'connected_peers': connected_count,
                'max_connections': self.max_connections,
                'utilization': len(self.connections) / self.max_connections,
                'total_created': self.total_connections_created,
                'total_closed': self.total_connections_closed,
                'average_quality': sum(self.connection_quality_scores.values()) / max(1, len(self.connection_quality_scores))
            }


class P2PNetworkOptimizer:
    """Main P2P network performance optimizer"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}

        # Initialize components
        self.dht_optimizer = DHTOptimizer(
            k=config.get('dht_k', 20),
            alpha=config.get('dht_alpha', 3)
        )

        self.peer_discovery = PeerDiscoveryOptimizer(
            max_concurrent_discoveries=config.get('max_discovery_workers', 10),
            discovery_timeout=config.get('discovery_timeout', 5.0)
        )

        self.message_routing = MessageRoutingOptimizer(
            max_routes=config.get('max_routes', 1000),
            route_ttl=config.get('route_ttl', 3600.0)
        )

        self.connection_pool = ConnectionPoolOptimizer(
            max_connections=config.get('max_connections', 1000),
            connection_timeout=config.get('connection_timeout', 30.0),
            keepalive_interval=config.get('keepalive_interval', 60.0)
        )

        # Configuration
        self.auto_peer_discovery = config.get('auto_peer_discovery', True)
        self.discovery_interval = config.get('discovery_interval', 300.0)  # 5 minutes

        # State
        self.running = False
        self.discovery_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the P2P network optimizer"""
        if self.running:
            return

        self.running = True

        # Start components
        await self.peer_discovery.start()
        await self.connection_pool.start()

        # Start auto-discovery if enabled
        if self.auto_peer_discovery:
            self.discovery_task = asyncio.create_task(self._auto_discovery_loop())

        logger.info("P2P network optimizer started")

    async def stop(self):
        """Stop the P2P network optimizer"""
        if not self.running:
            return

        self.running = False

        # Stop auto-discovery
        if self.discovery_task:
            self.discovery_task.cancel()

        # Stop components
        await self.connection_pool.stop()
        await self.peer_discovery.stop()

        logger.info("P2P network optimizer stopped")

    async def _auto_discovery_loop(self):
        """Automatic peer discovery loop"""
        while self.running:
            try:
                # Discover new peers
                await self.peer_discovery.discover_peers(target_count=10)

                # Wait for next discovery
                await asyncio.sleep(self.discovery_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Auto-discovery error: {e}")
                await asyncio.sleep(60)

    def add_peer(self, peer: P2PPeer):
        """Add a peer to the network"""
        self.dht_optimizer.update_routing_table([peer])
        self.connection_pool.add_peer_connection(peer)

    def remove_peer(self, peer_id: bytes):
        """Remove a peer from the network"""
        self.dht_optimizer.update_routing_table([])  # Would need to implement removal
        self.connection_pool.remove_peer_connection(peer_id)

    def find_peers_for_message(self, message_data: bytes, count: int = 3) -> List[P2PPeer]:
        """Find best peers for sending a message"""
        # Use DHT to find closest nodes
        target_id = hashlib.sha256(message_data).digest()
        closest_peers = self.dht_optimizer.find_closest_nodes(target_id, count * 2)

        # Filter to connected peers and return best ones
        connected_peers = [p for p in closest_peers if p.state == PeerState.CONNECTED]

        # If we don't have enough connected peers, use connection pool
        if len(connected_peers) < count:
            for _ in range(count - len(connected_peers)):
                best_peer = self.connection_pool.get_best_peer_for_message(len(message_data))
                if best_peer and best_peer not in connected_peers:
                    connected_peers.append(best_peer)

        return connected_peers[:count]

    def update_peer_stats(self, peer_id: bytes, response_time: float, success: bool):
        """Update peer statistics"""
        # Update in DHT optimizer
        # Update in connection pool

        # Update routing if needed
        pass

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive P2P optimization statistics"""
        return {
            'dht_optimizer': self.dht_optimizer.get_dht_stats(),
            'peer_discovery': self.peer_discovery.get_discovery_stats(),
            'message_routing': self.message_routing.get_routing_stats(),
            'connection_pool': self.connection_pool.get_connection_stats(),
            'configuration': {
                'auto_peer_discovery': self.auto_peer_discovery,
                'discovery_interval': self.discovery_interval
            }
        }