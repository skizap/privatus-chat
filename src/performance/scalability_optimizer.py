"""
Scalability Performance Optimizer

Implements comprehensive scalability optimizations for Privatus-chat including:
- Large network support with efficient peer discovery
- Load balancing for popular relays
- Distributed hash table optimization
- High-volume messaging performance
- Database performance tuning
- Caching layer implementation
"""

import asyncio
import time
import logging
import random
import hashlib
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import heapq
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


class LoadBalanceStrategy(Enum):
    """Load balancing strategies"""
    ROUND_ROBIN = "round_robin"
    WEIGHTED_ROUND_ROBIN = "weighted_round_robin"
    LEAST_CONNECTIONS = "least_connections"
    LEAST_RESPONSE_TIME = "least_response_time"
    CONSISTENT_HASH = "consistent_hash"


@dataclass
class PeerNode:
    """Represents a peer node in the network"""
    peer_id: bytes
    address: str
    port: int
    load: float = 0.0
    response_time: float = 0.0
    connection_count: int = 0
    last_seen: float = field(default_factory=time.time)
    reliability_score: float = 1.0
    capabilities: Set[str] = field(default_factory=set)
    
    def update_stats(self, response_time: float, success: bool):
        """Update node statistics"""
        self.response_time = (self.response_time * 0.9) + (response_time * 0.1)
        if success:
            self.reliability_score = min(1.0, self.reliability_score + 0.01)
        else:
            self.reliability_score = max(0.0, self.reliability_score - 0.05)
        self.last_seen = time.time()
    
    def get_score(self) -> float:
        """Calculate overall node score for selection"""
        # Combine reliability, response time, and load
        time_score = 1.0 / (1.0 + self.response_time)
        load_score = 1.0 / (1.0 + self.load)
        
        return self.reliability_score * time_score * load_score


class LoadBalancer:
    """Advanced load balancer for peer selection"""
    
    def __init__(self, strategy: LoadBalanceStrategy = LoadBalanceStrategy.WEIGHTED_ROUND_ROBIN):
        self.strategy = strategy
        
        # Node management
        self.nodes: Dict[bytes, PeerNode] = {}
        self.active_nodes: Set[bytes] = set()
        self.unhealthy_nodes: Set[bytes] = set()
        
        # Round-robin state
        self.round_robin_index = 0
        
        # Consistent hashing
        self.hash_ring: List[Tuple[int, bytes]] = []
        self.ring_dirty = True
        
        # Statistics
        self.total_requests = 0
        self.successful_requests = 0
        self.failed_requests = 0
        
        # Thread safety
        self._lock = threading.RLock()
    
    def add_node(self, node: PeerNode):
        """Add a node to the load balancer"""
        with self._lock:
            self.nodes[node.peer_id] = node
            self.active_nodes.add(node.peer_id)
            self.ring_dirty = True
            
            logger.debug(f"Added node {node.peer_id.hex()[:8]} to load balancer")
    
    def remove_node(self, peer_id: bytes):
        """Remove a node from the load balancer"""
        with self._lock:
            if peer_id in self.nodes:
                del self.nodes[peer_id]
                self.active_nodes.discard(peer_id)
                self.unhealthy_nodes.discard(peer_id)
                self.ring_dirty = True
                
                logger.debug(f"Removed node {peer_id.hex()[:8]} from load balancer")
    
    def mark_unhealthy(self, peer_id: bytes):
        """Mark a node as unhealthy"""
        with self._lock:
            if peer_id in self.active_nodes:
                self.active_nodes.discard(peer_id)
                self.unhealthy_nodes.add(peer_id)
                self.ring_dirty = True
                
                logger.warning(f"Marked node {peer_id.hex()[:8]} as unhealthy")
    
    def mark_healthy(self, peer_id: bytes):
        """Mark a node as healthy"""
        with self._lock:
            if peer_id in self.unhealthy_nodes:
                self.unhealthy_nodes.discard(peer_id)
                self.active_nodes.add(peer_id)
                self.ring_dirty = True
                
                logger.info(f"Marked node {peer_id.hex()[:8]} as healthy")
    
    def select_node(self, key: Optional[bytes] = None) -> Optional[PeerNode]:
        """Select a node based on the load balancing strategy"""
        with self._lock:
            if not self.active_nodes:
                return None
            
            self.total_requests += 1
            
            if self.strategy == LoadBalanceStrategy.ROUND_ROBIN:
                return self._round_robin_select()
            elif self.strategy == LoadBalanceStrategy.WEIGHTED_ROUND_ROBIN:
                return self._weighted_round_robin_select()
            elif self.strategy == LoadBalanceStrategy.LEAST_CONNECTIONS:
                return self._least_connections_select()
            elif self.strategy == LoadBalanceStrategy.LEAST_RESPONSE_TIME:
                return self._least_response_time_select()
            elif self.strategy == LoadBalanceStrategy.CONSISTENT_HASH:
                return self._consistent_hash_select(key)
            else:
                return self._round_robin_select()
    
    def _round_robin_select(self) -> Optional[PeerNode]:
        """Round-robin node selection"""
        active_list = list(self.active_nodes)
        if not active_list:
            return None
        
        selected_id = active_list[self.round_robin_index % len(active_list)]
        self.round_robin_index += 1
        
        return self.nodes[selected_id]
    
    def _weighted_round_robin_select(self) -> Optional[PeerNode]:
        """Weighted round-robin based on node scores"""
        candidates = [(self.nodes[peer_id].get_score(), peer_id) 
                     for peer_id in self.active_nodes]
        
        if not candidates:
            return None
        
        # Sort by score (highest first)
        candidates.sort(reverse=True)
        
        # Weighted selection
        total_weight = sum(score for score, _ in candidates)
        if total_weight == 0:
            return self._round_robin_select()
        
        rand_val = random.uniform(0, total_weight)
        current_weight = 0
        
        for score, peer_id in candidates:
            current_weight += score
            if rand_val <= current_weight:
                return self.nodes[peer_id]
        
        # Fallback
        return self.nodes[candidates[0][1]]
    
    def _least_connections_select(self) -> Optional[PeerNode]:
        """Select node with least connections"""
        if not self.active_nodes:
            return None
        
        min_connections = float('inf')
        selected_node = None
        
        for peer_id in self.active_nodes:
            node = self.nodes[peer_id]
            if node.connection_count < min_connections:
                min_connections = node.connection_count
                selected_node = node
        
        return selected_node
    
    def _least_response_time_select(self) -> Optional[PeerNode]:
        """Select node with least response time"""
        if not self.active_nodes:
            return None
        
        min_response_time = float('inf')
        selected_node = None
        
        for peer_id in self.active_nodes:
            node = self.nodes[peer_id]
            if node.response_time < min_response_time:
                min_response_time = node.response_time
                selected_node = node
        
        return selected_node
    
    def _consistent_hash_select(self, key: Optional[bytes]) -> Optional[PeerNode]:
        """Consistent hash-based selection"""
        if key is None:
            return self._round_robin_select()
        
        if self.ring_dirty:
            self._rebuild_hash_ring()
        
        if not self.hash_ring:
            return None
        
        # Hash the key
        key_hash = int(hashlib.sha256(key).hexdigest(), 16)
        
        # Find the first node with hash >= key_hash
        for ring_hash, peer_id in self.hash_ring:
            if ring_hash >= key_hash:
                return self.nodes[peer_id]
        
        # Wrap around to first node
        return self.nodes[self.hash_ring[0][1]]
    
    def _rebuild_hash_ring(self):
        """Rebuild the consistent hash ring"""
        self.hash_ring.clear()
        
        for peer_id in self.active_nodes:
            # Create multiple virtual nodes for better distribution
            for i in range(100):  # 100 virtual nodes per physical node
                virtual_key = peer_id + str(i).encode()
                hash_val = int(hashlib.sha256(virtual_key).hexdigest(), 16)
                self.hash_ring.append((hash_val, peer_id))
        
        # Sort by hash value
        self.hash_ring.sort()
        self.ring_dirty = False
    
    def update_node_stats(self, peer_id: bytes, response_time: float, success: bool):
        """Update node statistics"""
        with self._lock:
            if peer_id in self.nodes:
                self.nodes[peer_id].update_stats(response_time, success)
                
                if success:
                    self.successful_requests += 1
                else:
                    self.failed_requests += 1
    
    def get_load_balancer_stats(self) -> Dict[str, Any]:
        """Get load balancer statistics"""
        with self._lock:
            success_rate = self.successful_requests / max(1, self.total_requests)
            
            return {
                'strategy': self.strategy.value,
                'total_nodes': len(self.nodes),
                'active_nodes': len(self.active_nodes),
                'unhealthy_nodes': len(self.unhealthy_nodes),
                'total_requests': self.total_requests,
                'successful_requests': self.successful_requests,
                'failed_requests': self.failed_requests,
                'success_rate': success_rate,
                'hash_ring_size': len(self.hash_ring)
            }


class CachingLayer:
    """High-performance caching layer with TTL and LRU eviction"""
    
    def __init__(self, cache_size: int = 50 * 1024 * 1024,  # 50MB
                 default_ttl: int = 3600,  # 1 hour
                 cleanup_interval: int = 300):  # 5 minutes
        self.cache_size = cache_size
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        
        # Cache storage
        self.cache: Dict[str, Any] = {}
        self.cache_metadata: Dict[str, Dict[str, Any]] = {}
        self.access_order: deque = deque()
        
        # Size tracking
        self.current_size = 0
        
        # Statistics
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_evictions = 0
        self.cache_expirations = 0
        
        # Background cleanup
        self.cleanup_task: Optional[asyncio.Task] = None
        
        # Thread safety
        self._lock = threading.RLock()
        
        self.running = False
    
    async def start(self):
        """Start the caching layer"""
        if self.running:
            return
        
        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("Caching layer started")
    
    async def stop(self):
        """Stop the caching layer"""
        if not self.running:
            return
        
        self.running = False
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
        
        logger.info("Caching layer stopped")
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self._lock:
            current_time = time.time()
            
            if key not in self.cache:
                self.cache_misses += 1
                return None
            
            metadata = self.cache_metadata[key]
            
            # Check if expired
            if current_time > metadata['expires_at']:
                self._remove_key(key)
                self.cache_misses += 1
                self.cache_expirations += 1
                return None
            
            # Update access order
            self.access_order.remove(key)
            self.access_order.append(key)
            
            # Update access stats
            metadata['access_count'] += 1
            metadata['last_accessed'] = current_time
            
            self.cache_hits += 1
            return self.cache[key]
    
    def put(self, key: str, value: Any, ttl: Optional[int] = None) -> bool:
        """Put value in cache"""
        with self._lock:
            if ttl is None:
                ttl = self.default_ttl
            
            current_time = time.time()
            value_size = self._estimate_size(value)
            
            # Check if we need to evict items
            while (self.current_size + value_size > self.cache_size and 
                   self.cache):
                self._evict_lru()
            
            # Remove existing key if present
            if key in self.cache:
                self._remove_key(key)
            
            # Add new item
            self.cache[key] = value
            self.cache_metadata[key] = {
                'size': value_size,
                'created_at': current_time,
                'expires_at': current_time + ttl,
                'access_count': 0,
                'last_accessed': current_time
            }
            self.access_order.append(key)
            self.current_size += value_size
            
            return True
    
    def delete(self, key: str) -> bool:
        """Delete key from cache"""
        with self._lock:
            if key in self.cache:
                self._remove_key(key)
                return True
            return False
    
    def _remove_key(self, key: str):
        """Remove a key from cache"""
        if key in self.cache:
            metadata = self.cache_metadata[key]
            self.current_size -= metadata['size']
            
            del self.cache[key]
            del self.cache_metadata[key]
            
            if key in self.access_order:
                self.access_order.remove(key)
    
    def _evict_lru(self):
        """Evict least recently used item"""
        if self.access_order:
            lru_key = self.access_order.popleft()
            self._remove_key(lru_key)
            self.cache_evictions += 1
    
    def _estimate_size(self, value: Any) -> int:
        """Estimate size of value in bytes"""
        try:
            import sys
            return sys.getsizeof(value)
        except:
            # Fallback estimation
            if isinstance(value, (str, bytes)):
                return len(value)
            elif isinstance(value, (list, tuple)):
                return sum(self._estimate_size(item) for item in value)
            elif isinstance(value, dict):
                return sum(self._estimate_size(k) + self._estimate_size(v) 
                          for k, v in value.items())
            else:
                return 64  # Default estimate
    
    async def _cleanup_loop(self):
        """Background cleanup of expired items"""
        while self.running:
            try:
                await self._cleanup_expired()
                await asyncio.sleep(self.cleanup_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cache cleanup error: {e}")
                await asyncio.sleep(60)
    
    async def _cleanup_expired(self):
        """Clean up expired cache items"""
        with self._lock:
            current_time = time.time()
            expired_keys = []
            
            for key, metadata in self.cache_metadata.items():
                if current_time > metadata['expires_at']:
                    expired_keys.append(key)
            
            for key in expired_keys:
                self._remove_key(key)
                self.cache_expirations += 1
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            hit_rate = self.cache_hits / max(1, self.cache_hits + self.cache_misses)
            
            return {
                'cache_size': len(self.cache),
                'current_size_bytes': self.current_size,
                'max_size_bytes': self.cache_size,
                'utilization': self.current_size / self.cache_size,
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'hit_rate': hit_rate,
                'cache_evictions': self.cache_evictions,
                'cache_expirations': self.cache_expirations
            }


class DatabaseOptimizer:
    """Database performance optimizer"""
    
    def __init__(self, db_path: str, pool_size: int = 20):
        self.db_path = db_path
        self.pool_size = pool_size
        
        # Connection pool
        self.connection_pool: deque = deque()
        self.active_connections: Set[sqlite3.Connection] = set()
        
        # Thread pool for database operations
        self.thread_pool = ThreadPoolExecutor(max_workers=pool_size)
        
        # Query cache
        self.query_cache: Dict[str, Any] = {}
        self.prepared_statements: Dict[str, str] = {}
        
        # Statistics
        self.query_count = 0
        self.cache_hits = 0
        self.connection_reuses = 0
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize connection pool
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize database connection pool"""
        try:
            for _ in range(min(5, self.pool_size)):
                conn = self._create_connection()
                if conn:
                    self.connection_pool.append(conn)
            
            logger.info(f"Database connection pool initialized with {len(self.connection_pool)} connections")
        except Exception as e:
            logger.error(f"Failed to initialize database pool: {e}")
    
    def _create_connection(self) -> Optional[sqlite3.Connection]:
        """Create optimized database connection"""
        try:
            conn = sqlite3.connect(
                self.db_path,
                check_same_thread=False,
                timeout=30.0
            )
            
            # Optimize SQLite settings
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA cache_size=10000")
            conn.execute("PRAGMA temp_store=MEMORY")
            conn.execute("PRAGMA mmap_size=268435456")  # 256MB
            
            return conn
        except Exception as e:
            logger.error(f"Failed to create database connection: {e}")
            return None
    
    def get_connection(self) -> Optional[sqlite3.Connection]:
        """Get connection from pool"""
        with self._lock:
            if self.connection_pool:
                conn = self.connection_pool.popleft()
                self.active_connections.add(conn)
                self.connection_reuses += 1
                return conn
            elif len(self.active_connections) < self.pool_size:
                conn = self._create_connection()
                if conn:
                    self.active_connections.add(conn)
                return conn
            else:
                logger.warning("Database connection pool exhausted")
                return None
    
    def return_connection(self, conn: sqlite3.Connection):
        """Return connection to pool"""
        with self._lock:
            if conn in self.active_connections:
                self.active_connections.remove(conn)
                self.connection_pool.append(conn)
    
    async def execute_query(self, query: str, params: Tuple = (), 
                          cache_result: bool = False) -> Optional[List[Any]]:
        """Execute database query with optimization"""
        self.query_count += 1
        
        # Check query cache
        if cache_result:
            cache_key = hashlib.sha256((query + str(params)).encode()).hexdigest()
            if cache_key in self.query_cache:
                self.cache_hits += 1
                return self.query_cache[cache_key]
        
        # Execute query in thread pool
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            self.thread_pool,
            self._execute_query_sync,
            query,
            params
        )
        
        # Cache result if requested
        if cache_result and result is not None:
            cache_key = hashlib.sha256((query + str(params)).encode()).hexdigest()
            self.query_cache[cache_key] = result
        
        return result
    
    def _execute_query_sync(self, query: str, params: Tuple) -> Optional[List[Any]]:
        """Execute query synchronously"""
        conn = self.get_connection()
        if not conn:
            return None
        
        try:
            cursor = conn.cursor()
            cursor.execute(query, params)
            
            if query.strip().upper().startswith('SELECT'):
                result = cursor.fetchall()
            else:
                conn.commit()
                result = []
            
            return result
        except Exception as e:
            logger.error(f"Database query failed: {e}")
            conn.rollback()
            return None
        finally:
            self.return_connection(conn)
    
    def clear_query_cache(self):
        """Clear the query cache"""
        with self._lock:
            self.query_cache.clear()
    
    def get_db_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self._lock:
            cache_hit_rate = self.cache_hits / max(1, self.query_count)
            
            return {
                'connection_pool_size': len(self.connection_pool),
                'active_connections': len(self.active_connections),
                'max_connections': self.pool_size,
                'query_count': self.query_count,
                'cache_hits': self.cache_hits,
                'cache_hit_rate': cache_hit_rate,
                'connection_reuses': self.connection_reuses,
                'query_cache_size': len(self.query_cache)
            }


class ScalabilityOptimizer:
    """Main scalability performance optimizer"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}
        
        # Initialize components
        strategy = LoadBalanceStrategy(config.get('load_balance_strategy', 'weighted_round_robin'))
        self.load_balancer = LoadBalancer(strategy)
        
        self.caching_layer = CachingLayer(
            cache_size=config.get('cache_size', 50 * 1024 * 1024),
            default_ttl=config.get('cache_ttl', 3600)
        )
        
        db_path = config.get('db_path', ':memory:')
        self.database_optimizer = DatabaseOptimizer(
            db_path=db_path,
            pool_size=config.get('db_pool_size', 20)
        )
        
        # Scalability settings
        self.max_peers = config.get('max_peers', 10000)
        self.message_queue_size = config.get('message_queue_size', 100000)
        
        # Message batching for high volume
        self.message_batches: Dict[bytes, List[Any]] = defaultdict(list)
        self.batch_timers: Dict[bytes, asyncio.Task] = {}
        
        self.running = False
    
    async def start(self):
        """Start the scalability optimizer"""
        if self.running:
            return
        
        self.running = True
        
        await self.caching_layer.start()
        
        logger.info("Scalability optimizer started")
    
    async def stop(self):
        """Stop the scalability optimizer"""
        if not self.running:
            return
        
        self.running = False
        
        await self.caching_layer.stop()
        
        # Cancel batch timers
        for timer in self.batch_timers.values():
            timer.cancel()
        
        logger.info("Scalability optimizer stopped")
    
    def add_peer(self, peer_node: PeerNode):
        """Add a peer to the load balancer"""
        self.load_balancer.add_node(peer_node)
    
    def remove_peer(self, peer_id: bytes):
        """Remove a peer from the load balancer"""
        self.load_balancer.remove_node(peer_id)
    
    def select_peer(self, key: Optional[bytes] = None) -> Optional[PeerNode]:
        """Select optimal peer for communication"""
        return self.load_balancer.select_node(key)
    
    async def cache_data(self, key: str, data: Any, ttl: Optional[int] = None) -> bool:
        """Cache data for performance"""
        return self.caching_layer.put(key, data, ttl)
    
    async def get_cached_data(self, key: str) -> Optional[Any]:
        """Get cached data"""
        return self.caching_layer.get(key)
    
    async def execute_db_query(self, query: str, params: Tuple = (), 
                             cache_result: bool = False) -> Optional[List[Any]]:
        """Execute optimized database query"""
        return await self.database_optimizer.execute_query(query, params, cache_result)
    
    async def batch_message(self, peer_id: bytes, message: Any):
        """Add message to batch for high-volume processing"""
        self.message_batches[peer_id].append(message)
        
        # Start batch timer if not exists
        if peer_id not in self.batch_timers:
            self.batch_timers[peer_id] = asyncio.create_task(
                self._flush_message_batch(peer_id)
            )
    
    async def _flush_message_batch(self, peer_id: bytes):
        """Flush message batch after timeout"""
        try:
            await asyncio.sleep(0.1)  # 100ms batch timeout
            
            if peer_id in self.message_batches:
                batch = self.message_batches[peer_id]
                if batch:
                    # Process batch
                    await self._process_message_batch(peer_id, batch)
                    
                    # Clear batch
                    self.message_batches[peer_id].clear()
            
            # Remove timer
            if peer_id in self.batch_timers:
                del self.batch_timers[peer_id]
                
        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"Error flushing message batch: {e}")
    
    async def _process_message_batch(self, peer_id: bytes, messages: List[Any]):
        """Process a batch of messages"""
        # This would integrate with the actual message processing system
        logger.debug(f"Processing batch of {len(messages)} messages for peer {peer_id.hex()[:8]}")
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive scalability optimization statistics"""
        return {
            'load_balancer': self.load_balancer.get_load_balancer_stats(),
            'caching_layer': self.caching_layer.get_cache_stats(),
            'database_optimizer': self.database_optimizer.get_db_stats(),
            'max_peers': self.max_peers,
            'active_batches': len(self.message_batches),
            'pending_messages': sum(len(batch) for batch in self.message_batches.values())
        } 