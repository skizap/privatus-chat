"""
Comprehensive Caching Strategies

Implements multiple caching strategies for frequently accessed data including:
- Multi-level caching (L1, L2, L3)
- Cache warming and preloading
- Intelligent cache invalidation
- Distributed caching support
- Cache analytics and optimization
"""

import asyncio
import time
import logging
import hashlib
import threading
from typing import Dict, List, Optional, Any, Set, Tuple, Union, Callable
from collections import defaultdict, OrderedDict
from dataclasses import dataclass, field
from enum import Enum
import weakref
import json

logger = logging.getLogger(__name__)


class CacheLevel(Enum):
    """Cache levels for multi-level caching"""
    L1 = "l1"  # Fastest, smallest (CPU cache)
    L2 = "l2"  # Medium speed/size (memory cache)
    L3 = "l3"  # Slowest, largest (disk/distributed cache)


class CacheStrategy(Enum):
    """Caching strategies"""
    LRU = "lru"                    # Least Recently Used
    LFU = "lfu"                    # Least Frequently Used
    TTL = "ttl"                    # Time To Live
    ADAPTIVE = "adaptive"          # Adaptive based on access patterns
    WRITE_THROUGH = "write_through"  # Write to all levels
    WRITE_BACK = "write_back"      # Write to one level, propagate later


@dataclass
class CacheEntry:
    """Represents a cache entry"""
    key: str
    value: Any
    created_at: float
    accessed_at: float
    access_count: int
    size: int
    ttl: float
    level: CacheLevel
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if entry is expired"""
        return time.time() > self.created_at + self.ttl

    def update_access(self):
        """Update access statistics"""
        self.accessed_at = time.time()
        self.access_count += 1

    def get_age(self) -> float:
        """Get age of entry"""
        return time.time() - self.created_at

    def get_idle_time(self) -> float:
        """Get idle time of entry"""
        return time.time() - self.accessed_at


class MultiLevelCache:
    """Multi-level cache with different strategies per level"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}

        # Cache levels
        self.l1_cache = self._create_cache_level(CacheLevel.L1, config.get('l1_config', {}))
        self.l2_cache = self._create_cache_level(CacheLevel.L2, config.get('l2_config', {}))
        self.l3_cache = self._create_cache_level(CacheLevel.L3, config.get('l3_config', {}))

        # Cache levels mapping
        self.cache_levels = {
            CacheLevel.L1: self.l1_cache,
            CacheLevel.L2: self.l2_cache,
            CacheLevel.L3: self.l3_cache
        }

        # Strategy configuration
        self.strategy = CacheStrategy(config.get('strategy', 'ADAPTIVE'))
        self.write_strategy = CacheStrategy(config.get('write_strategy', 'WRITE_BACK'))

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0
        self.level_hits = {level: 0 for level in CacheLevel}

        # Thread safety
        self._lock = threading.RLock()

    def _create_cache_level(self, level: CacheLevel, config: Dict[str, Any]) -> 'CacheLevel':
        """Create a cache level with appropriate strategy"""
        if level == CacheLevel.L1:
            return L1Cache(
                max_size=config.get('max_size', 1000),
                strategy=CacheStrategy(config.get('strategy', 'LRU'))
            )
        elif level == CacheLevel.L2:
            return L2Cache(
                max_size=config.get('max_size', 10000),
                strategy=CacheStrategy(config.get('strategy', 'LFU'))
            )
        else:  # L3
            return L3Cache(
                max_size=config.get('max_size', 100000),
                strategy=CacheStrategy(config.get('strategy', 'TTL'))
            )

    def get(self, key: str) -> Optional[Any]:
        """Get value from multi-level cache"""
        with self._lock:
            # Try L1 first (fastest)
            value = self.l1_cache.get(key)
            if value is not None:
                self.hits += 1
                self.level_hits[CacheLevel.L1] += 1
                # Promote to L1 if found in lower levels
                if self.l1_cache.strategy == CacheStrategy.LRU:
                    self.l1_cache._promote_entry(key)
                return value

            # Try L2
            value = self.l2_cache.get(key)
            if value is not None:
                self.hits += 1
                self.level_hits[CacheLevel.L2] += 1
                # Promote to L1
                self.l1_cache.put(key, value)
                return value

            # Try L3 (slowest)
            value = self.l3_cache.get(key)
            if value is not None:
                self.hits += 1
                self.level_hits[CacheLevel.L3] += 1
                # Promote to L2 and L1
                self.l2_cache.put(key, value)
                self.l1_cache.put(key, value)
                return value

            self.misses += 1
            return None

    def put(self, key: str, value: Any, ttl: float = 3600.0) -> bool:
        """Put value in multi-level cache"""
        with self._lock:
            # Write to L1 first
            success = self.l1_cache.put(key, value, ttl)

            if success:
                # Write to other levels based on strategy
                if self.write_strategy == CacheStrategy.WRITE_THROUGH:
                    self.l2_cache.put(key, value, ttl)
                    self.l3_cache.put(key, value, ttl)
                elif self.write_strategy == CacheStrategy.WRITE_BACK:
                    # Only write to L1, let eviction policy handle promotion
                    pass

            return success

    def delete(self, key: str) -> bool:
        """Delete from all cache levels"""
        with self._lock:
            success = False
            for cache in self.cache_levels.values():
                if cache.delete(key):
                    success = True
            return success

    def clear(self):
        """Clear all cache levels"""
        with self._lock:
            for cache in self.cache_levels.values():
                cache.clear()

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics"""
        with self._lock:
            total_hits = sum(self.level_hits.values())
            total_requests = total_hits + self.misses
            hit_rate = total_hits / max(1, total_requests)

            return {
                'total_hits': total_hits,
                'total_misses': self.misses,
                'hit_rate': hit_rate,
                'evictions': self.evictions,
                'level_hits': self.level_hits.copy(),
                'levels': {
                    'l1': self.l1_cache.get_cache_stats(),
                    'l2': self.l2_cache.get_cache_stats(),
                    'l3': self.l3_cache.get_cache_stats()
                },
                'strategy': self.strategy.value,
                'write_strategy': self.write_strategy.value
            }


class L1Cache:
    """Level 1 cache - fastest, smallest"""

    def __init__(self, max_size: int = 1000, strategy: CacheStrategy = CacheStrategy.LRU):
        self.max_size = max_size
        self.strategy = strategy

        # Cache storage
        self.cache: Dict[str, CacheEntry] = {}
        self.access_order: deque = deque()  # For LRU

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

        # Thread safety
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        """Get value from L1 cache"""
        with self._lock:
            if key not in self.cache:
                self.misses += 1
                return None

            entry = self.cache[key]

            if entry.is_expired():
                self._remove_entry(key)
                self.misses += 1
                return None

            entry.update_access()

            if self.strategy == CacheStrategy.LRU:
                # Update LRU order
                self.access_order.remove(key)
                self.access_order.append(key)

            self.hits += 1
            return entry.value

    def put(self, key: str, value: Any, ttl: float = 3600.0) -> bool:
        """Put value in L1 cache"""
        with self._lock:
            value_size = self._estimate_size(value)

            # Check if we need to evict
            if (key not in self.cache and
                len(self.cache) >= self.max_size):
                self._evict_entry()

            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)

            # Add new entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                accessed_at=time.time(),
                access_count=0,
                size=value_size,
                ttl=ttl,
                level=CacheLevel.L1
            )

            self.cache[key] = entry

            if self.strategy == CacheStrategy.LRU:
                self.access_order.append(key)

            return True

    def delete(self, key: str) -> bool:
        """Delete entry from L1 cache"""
        with self._lock:
            if key in self.cache:
                self._remove_entry(key)
                return True
            return False

    def clear(self):
        """Clear L1 cache"""
        with self._lock:
            self.cache.clear()
            self.access_order.clear()

    def _remove_entry(self, key: str):
        """Remove entry from cache"""
        if key in self.cache:
            del self.cache[key]
            if key in self.access_order:
                self.access_order.remove(key)

    def _evict_entry(self):
        """Evict entry based on strategy"""
        if self.strategy == CacheStrategy.LRU:
            if self.access_order:
                lru_key = self.access_order.popleft()
                self._remove_entry(lru_key)
                self.evictions += 1
        else:
            # Default to LRU
            if self.access_order:
                lru_key = self.access_order.popleft()
                self._remove_entry(lru_key)
                self.evictions += 1

    def _promote_entry(self, key: str):
        """Promote entry (for LRU)"""
        if self.strategy == CacheStrategy.LRU and key in self.access_order:
            self.access_order.remove(key)
            self.access_order.append(key)

    def _estimate_size(self, value: Any) -> int:
        """Estimate size of value"""
        try:
            import sys
            return sys.getsizeof(value)
        except:
            return 64

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get L1 cache statistics"""
        with self._lock:
            hit_rate = self.hits / max(1, self.hits + self.misses)

            return {
                'level': 'L1',
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'evictions': self.evictions,
                'strategy': self.strategy.value
            }


class L2Cache:
    """Level 2 cache - medium speed/size"""

    def __init__(self, max_size: int = 10000, strategy: CacheStrategy = CacheStrategy.LFU):
        self.max_size = max_size
        self.strategy = strategy

        # Cache storage
        self.cache: Dict[str, CacheEntry] = {}
        self.frequency: Dict[str, int] = {}  # For LFU

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

        # Thread safety
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        """Get value from L2 cache"""
        with self._lock:
            if key not in self.cache:
                self.misses += 1
                return None

            entry = self.cache[key]

            if entry.is_expired():
                self._remove_entry(key)
                self.misses += 1
                return None

            entry.update_access()

            if self.strategy == CacheStrategy.LFU:
                self.frequency[key] = self.frequency.get(key, 0) + 1

            self.hits += 1
            return entry.value

    def put(self, key: str, value: Any, ttl: float = 3600.0) -> bool:
        """Put value in L2 cache"""
        with self._lock:
            value_size = self._estimate_size(value)

            # Check if we need to evict
            if (key not in self.cache and
                len(self.cache) >= self.max_size):
                self._evict_entry()

            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)

            # Add new entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                accessed_at=time.time(),
                access_count=0,
                size=value_size,
                ttl=ttl,
                level=CacheLevel.L2
            )

            self.cache[key] = entry
            self.frequency[key] = 1

            return True

    def delete(self, key: str) -> bool:
        """Delete entry from L2 cache"""
        with self._lock:
            if key in self.cache:
                self._remove_entry(key)
                return True
            return False

    def clear(self):
        """Clear L2 cache"""
        with self._lock:
            self.cache.clear()
            self.frequency.clear()

    def _remove_entry(self, key: str):
        """Remove entry from cache"""
        if key in self.cache:
            del self.cache[key]
            if key in self.frequency:
                del self.frequency[key]

    def _evict_entry(self):
        """Evict entry based on strategy"""
        if self.strategy == CacheStrategy.LFU:
            if self.frequency:
                # Find least frequently used
                lfu_key = min(self.frequency.items(), key=lambda x: x[1])
                self._remove_entry(lfu_key[0])
                self.evictions += 1
        else:
            # Default eviction
            if self.cache:
                oldest_key = min(self.cache.items(), key=lambda x: x[1].accessed_at)
                self._remove_entry(oldest_key[0])
                self.evictions += 1

    def _estimate_size(self, value: Any) -> int:
        """Estimate size of value"""
        try:
            import sys
            return sys.getsizeof(value)
        except:
            return 64

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get L2 cache statistics"""
        with self._lock:
            hit_rate = self.hits / max(1, self.hits + self.misses)

            return {
                'level': 'L2',
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'evictions': self.evictions,
                'strategy': self.strategy.value
            }


class L3Cache:
    """Level 3 cache - slowest, largest (disk/distributed)"""

    def __init__(self, max_size: int = 100000, strategy: CacheStrategy = CacheStrategy.TTL):
        self.max_size = max_size
        self.strategy = strategy

        # Cache storage (simulated as memory for this implementation)
        self.cache: Dict[str, CacheEntry] = {}
        self.expiry_times: Dict[str, float] = {}

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

        # Thread safety
        self._lock = threading.RLock()

    def get(self, key: str) -> Optional[Any]:
        """Get value from L3 cache"""
        with self._lock:
            if key not in self.cache:
                self.misses += 1
                return None

            entry = self.cache[key]

            if entry.is_expired():
                self._remove_entry(key)
                self.misses += 1
                return None

            entry.update_access()
            self.hits += 1
            return entry.value

    def put(self, key: str, value: Any, ttl: float = 3600.0) -> bool:
        """Put value in L3 cache"""
        with self._lock:
            value_size = self._estimate_size(value)

            # Check if we need to evict
            if (key not in self.cache and
                len(self.cache) >= self.max_size):
                self._evict_entry()

            # Remove existing entry if present
            if key in self.cache:
                self._remove_entry(key)

            # Add new entry
            entry = CacheEntry(
                key=key,
                value=value,
                created_at=time.time(),
                accessed_at=time.time(),
                access_count=0,
                size=value_size,
                ttl=ttl,
                level=CacheLevel.L3
            )

            self.cache[key] = entry
            self.expiry_times[key] = time.time() + ttl

            return True

    def delete(self, key: str) -> bool:
        """Delete entry from L3 cache"""
        with self._lock:
            if key in self.cache:
                self._remove_entry(key)
                return True
            return False

    def clear(self):
        """Clear L3 cache"""
        with self._lock:
            self.cache.clear()
            self.expiry_times.clear()

    def _remove_entry(self, key: str):
        """Remove entry from cache"""
        if key in self.cache:
            del self.cache[key]
            if key in self.expiry_times:
                del self.expiry_times[key]

    def _evict_entry(self):
        """Evict entry based on strategy"""
        if self.strategy == CacheStrategy.TTL:
            if self.expiry_times:
                # Find entry with earliest expiry
                earliest_key = min(self.expiry_times.items(), key=lambda x: x[1])
                self._remove_entry(earliest_key[0])
                self.evictions += 1
        else:
            # Default eviction
            if self.cache:
                oldest_key = min(self.cache.items(), key=lambda x: x[1].accessed_at)
                self._remove_entry(oldest_key[0])
                self.evictions += 1

    def _estimate_size(self, value: Any) -> int:
        """Estimate size of value"""
        try:
            import sys
            return sys.getsizeof(value)
        except:
            return 64

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get L3 cache statistics"""
        with self._lock:
            hit_rate = self.hits / max(1, self.hits + self.misses)

            return {
                'level': 'L3',
                'size': len(self.cache),
                'max_size': self.max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'evictions': self.evictions,
                'strategy': self.strategy.value
            }


class CacheWarmingService:
    """Service for warming cache with frequently accessed data"""

    def __init__(self, cache: MultiLevelCache):
        self.cache = cache
        self.warmup_data: Dict[str, Any] = {}
        self.warmup_ttl: Dict[str, float] = {}

        # Warming state
        self.warming_in_progress = False
        self.warmup_task: Optional[asyncio.Task] = None

        # Statistics
        self.warmup_count = 0
        self.warmup_failures = 0

        # Thread safety
        self._lock = threading.RLock()

    def add_warmup_data(self, key: str, data_func: Callable, ttl: float = 3600.0):
        """Add data to be warmed up"""
        with self._lock:
            self.warmup_data[key] = data_func
            self.warmup_ttl[key] = ttl

    def remove_warmup_data(self, key: str):
        """Remove warmup data"""
        with self._lock:
            if key in self.warmup_data:
                del self.warmup_data[key]
            if key in self.warmup_ttl:
                del self.warmup_ttl[key]

    async def warmup_cache(self) -> Dict[str, Any]:
        """Warm up cache with registered data"""
        if self.warming_in_progress:
            return {'status': 'already_warming'}

        self.warming_in_progress = True
        warmup_results = {
            'total_items': len(self.warmup_data),
            'successful_warmups': 0,
            'failed_warmups': 0,
            'errors': []
        }

        try:
            # Warm up each data item
            for key, data_func in self.warmup_data.items():
                try:
                    # Get data
                    if asyncio.iscoroutinefunction(data_func):
                        data = await data_func()
                    else:
                        # Run in thread pool for blocking operations
                        loop = asyncio.get_event_loop()
                        data = await loop.run_in_executor(None, data_func)

                    # Cache the data
                    ttl = self.warmup_ttl.get(key, 3600.0)
                    if self.cache.put(key, data, ttl):
                        warmup_results['successful_warmups'] += 1
                        self.warmup_count += 1
                    else:
                        warmup_results['failed_warmups'] += 1
                        warmup_results['errors'].append(f"Failed to cache {key}")

                except Exception as e:
                    warmup_results['failed_warmups'] += 1
                    warmup_results['errors'].append(f"Error warming up {key}: {e}")
                    self.warmup_failures += 1

        finally:
            self.warming_in_progress = False

        return warmup_results

    def get_warmup_stats(self) -> Dict[str, Any]:
        """Get warmup statistics"""
        with self._lock:
            return {
                'warmup_count': self.warmup_count,
                'warmup_failures': self.warmup_failures,
                'registered_items': len(self.warmup_data),
                'warming_in_progress': self.warming_in_progress
            }


class CacheInvalidationManager:
    """Manages cache invalidation with different strategies"""

    def __init__(self, cache: MultiLevelCache):
        self.cache = cache

        # Invalidation patterns
        self.invalidation_patterns: Dict[str, Set[str]] = defaultdict(set)
        self.reverse_dependencies: Dict[str, Set[str]] = defaultdict(set)

        # Invalidation strategies
        self.invalidation_strategy = 'immediate'  # immediate, delayed, scheduled

        # Statistics
        self.invalidations_performed = 0
        self.invalidation_hits = 0

        # Thread safety
        self._lock = threading.RLock()

    def add_invalidation_dependency(self, key: str, depends_on: str):
        """Add invalidation dependency (key depends on depends_on)"""
        with self._lock:
            self.invalidation_patterns[depends_on].add(key)
            self.reverse_dependencies[key].add(depends_on)

    def remove_invalidation_dependency(self, key: str, depends_on: str):
        """Remove invalidation dependency"""
        with self._lock:
            if depends_on in self.invalidation_patterns:
                self.invalidation_patterns[depends_on].discard(key)
            if key in self.reverse_dependencies:
                self.reverse_dependencies[key].discard(depends_on)

    def invalidate_key(self, key: str) -> int:
        """Invalidate a key and all dependent keys"""
        with self._lock:
            invalidated_count = 0

            # Invalidate the key itself
            if self.cache.delete(key):
                invalidated_count += 1
                self.invalidations_performed += 1

            # Invalidate dependent keys
            dependent_keys = self.invalidation_patterns.get(key, set())
            for dependent_key in dependent_keys:
                if self.cache.delete(dependent_key):
                    invalidated_count += 1
                    self.invalidations_performed += 1

            if invalidated_count > 0:
                self.invalidation_hits += 1

            return invalidated_count

    def invalidate_pattern(self, pattern: str) -> int:
        """Invalidate all keys matching a pattern"""
        with self._lock:
            invalidated_count = 0
            keys_to_invalidate = []

            # Find matching keys
            for key in self.cache.cache.cache.keys():
                if pattern in key:
                    keys_to_invalidate.append(key)

            # Invalidate matching keys
            for key in keys_to_invalidate:
                if self.cache.delete(key):
                    invalidated_count += 1
                    self.invalidations_performed += 1

            return invalidated_count

    def get_invalidation_stats(self) -> Dict[str, Any]:
        """Get invalidation statistics"""
        with self._lock:
            return {
                'invalidations_performed': self.invalidations_performed,
                'invalidation_hits': self.invalidation_hits,
                'patterns_count': len(self.invalidation_patterns),
                'dependencies_count': sum(len(deps) for deps in self.reverse_dependencies.values())
            }


class DistributedCacheCoordinator:
    """Coordinates caching across multiple nodes"""

    def __init__(self, node_id: str, cache: MultiLevelCache):
        self.node_id = node_id
        self.cache = cache

        # Distributed state
        self.cluster_nodes: Set[str] = set()
        self.node_data: Dict[str, Dict[str, Any]] = {}

        # Consistency management
        self.consistency_mode = 'eventual'  # eventual, strong, weak

        # Statistics
        self.remote_cache_requests = 0
        self.remote_cache_responses = 0

        # Thread safety
        self._lock = threading.RLock()

    def add_cluster_node(self, node_id: str, node_info: Dict[str, Any]):
        """Add a node to the cluster"""
        with self._lock:
            self.cluster_nodes.add(node_id)
            self.node_data[node_id] = node_info

    def remove_cluster_node(self, node_id: str):
        """Remove a node from the cluster"""
        with self._lock:
            self.cluster_nodes.discard(node_id)
            if node_id in self.node_data:
                del self.node_data[node_id]

    async def get_from_cluster(self, key: str) -> Optional[Any]:
        """Get value from cluster (if not in local cache)"""
        # Check local cache first
        value = self.cache.get(key)
        if value is not None:
            return value

        # Try to get from other nodes
        for node_id in self.cluster_nodes:
            if node_id != self.node_id:
                try:
                    value = await self._get_from_node(node_id, key)
                    if value is not None:
                        # Cache locally
                        self.cache.put(key, value)
                        self.remote_cache_responses += 1
                        return value
                except Exception as e:
                    logger.warning(f"Failed to get {key} from node {node_id}: {e}")

        self.remote_cache_requests += 1
        return None

    async def _get_from_node(self, node_id: str, key: str) -> Optional[Any]:
        """Get value from specific node (would implement actual network call)"""
        # This would implement actual network communication
        # For now, return None
        return None

    def get_cluster_stats(self) -> Dict[str, Any]:
        """Get cluster cache statistics"""
        with self._lock:
            return {
                'node_id': self.node_id,
                'cluster_size': len(self.cluster_nodes),
                'consistency_mode': self.consistency_mode,
                'remote_requests': self.remote_cache_requests,
                'remote_responses': self.remote_cache_responses,
                'cluster_nodes': list(self.cluster_nodes)
            }


class ComprehensiveCachingStrategy:
    """Main comprehensive caching strategy manager"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}

        # Initialize multi-level cache
        self.multi_level_cache = MultiLevelCache(config.get('cache_config', {}))

        # Initialize supporting services
        self.cache_warming = CacheWarmingService(self.multi_level_cache)
        self.invalidation_manager = CacheInvalidationManager(self.multi_level_cache)

        # Distributed caching (optional)
        node_id = config.get('node_id', 'node_1')
        self.distributed_cache = DistributedCacheCoordinator(node_id, self.multi_level_cache)

        # Configuration
        self.enable_cache_warming = config.get('enable_cache_warming', True)
        self.enable_distributed_cache = config.get('enable_distributed_cache', False)

        # State
        self.running = False

    async def start(self):
        """Start the comprehensive caching strategy"""
        if self.running:
            return

        self.running = True

        # Start cache warming if enabled
        if self.enable_cache_warming:
            await self.cache_warming.warmup_cache()

        logger.info("Comprehensive caching strategy started")

    async def stop(self):
        """Stop the comprehensive caching strategy"""
        if not self.running:
            return

        self.running = False
        logger.info("Comprehensive caching strategy stopped")

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        return self.multi_level_cache.get(key)

    def put(self, key: str, value: Any, ttl: float = 3600.0) -> bool:
        """Put value in cache"""
        return self.multi_level_cache.put(key, value, ttl)

    def delete(self, key: str) -> bool:
        """Delete value from cache"""
        return self.multi_level_cache.delete(key)

    def add_cache_dependency(self, key: str, depends_on: str):
        """Add cache invalidation dependency"""
        self.invalidation_manager.add_invalidation_dependency(key, depends_on)

    def invalidate_key(self, key: str) -> int:
        """Invalidate key and dependencies"""
        return self.invalidation_manager.invalidate_key(key)

    def add_warmup_data(self, key: str, data_func: Callable, ttl: float = 3600.0):
        """Add data for cache warming"""
        self.cache_warming.add_warmup_data(key, data_func, ttl)

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive caching statistics"""
        return {
            'multi_level_cache': self.multi_level_cache.get_cache_stats(),
            'cache_warming': self.cache_warming.get_warmup_stats(),
            'invalidation_manager': self.invalidation_manager.get_invalidation_stats(),
            'distributed_cache': self.distributed_cache.get_cluster_stats() if self.enable_distributed_cache else None,
            'configuration': {
                'enable_cache_warming': self.enable_cache_warming,
                'enable_distributed_cache': self.enable_distributed_cache
            }
        }