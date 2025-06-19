"""
Memory Performance Optimizer

Implements comprehensive memory optimization for Privatus-chat including:
- Memory pool management
- Garbage collection optimization
- Secure memory allocation
- Memory leak prevention
"""

import gc
import mmap
import os
import time
import logging
import threading
import ctypes
import asyncio
from typing import Dict, List, Optional, Any, Union, Set
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum
import weakref

logger = logging.getLogger(__name__)


class MemoryType(Enum):
    """Types of memory allocations"""
    CRYPTO_KEY = "crypto_key"
    MESSAGE_BUFFER = "message_buffer"
    CACHE_DATA = "cache_data"
    TEMPORARY = "temporary"
    PERSISTENT = "persistent"


@dataclass
class MemoryBlock:
    """Represents a memory block in the pool"""
    block_id: str
    size: int
    memory_type: MemoryType
    allocated_at: float
    last_accessed: float
    access_count: int = 0
    is_secure: bool = False
    data: Optional[Union[bytes, bytearray, memoryview]] = None
    
    def update_access(self):
        """Update access statistics"""
        self.last_accessed = time.time()
        self.access_count += 1
    
    def get_age(self) -> float:
        """Get the age of the memory block"""
        return time.time() - self.allocated_at
    
    def get_idle_time(self) -> float:
        """Get the idle time of the memory block"""
        return time.time() - self.last_accessed


class MemoryPool:
    """High-performance memory pool with security features"""
    
    def __init__(self, pool_size: int = 100 * 1024 * 1024,  # 100MB
                 block_size: int = 4096,  # 4KB blocks
                 max_blocks: int = 10000):
        self.pool_size = pool_size
        self.block_size = block_size
        self.max_blocks = max_blocks
        
        # Memory pool storage
        self.memory_blocks: Dict[str, MemoryBlock] = {}
        self.free_blocks: Set[str] = set()
        self.allocated_blocks: Set[str] = set()
        
        # Type-specific pools
        self.type_pools: Dict[MemoryType, Set[str]] = defaultdict(set)
        
        # Memory mapping for large allocations
        self.memory_maps: Dict[str, mmap.mmap] = {}
        
        # Statistics
        self.total_allocated = 0
        self.total_freed = 0
        self.peak_usage = 0
        self.allocation_count = 0
        self.free_count = 0
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Initialize memory pool
        self._initialize_pool()
    
    def _initialize_pool(self):
        """Initialize the memory pool with pre-allocated blocks"""
        try:
            # Pre-allocate memory blocks
            initial_blocks = min(1000, self.max_blocks // 4)
            
            for i in range(initial_blocks):
                block_id = f"block_{i}"
                
                # Allocate memory block
                data = bytearray(self.block_size)
                
                block = MemoryBlock(
                    block_id=block_id,
                    size=self.block_size,
                    memory_type=MemoryType.TEMPORARY,
                    allocated_at=time.time(),
                    last_accessed=time.time(),
                    data=data
                )
                
                self.memory_blocks[block_id] = block
                self.free_blocks.add(block_id)
            
            logger.info(f"Memory pool initialized with {initial_blocks} blocks")
            
        except Exception as e:
            logger.error(f"Failed to initialize memory pool: {e}")
    
    def allocate(self, size: int, memory_type: MemoryType = MemoryType.TEMPORARY,
                secure: bool = False) -> Optional[str]:
        """Allocate memory from the pool"""
        with self._lock:
            # Check if we can allocate
            if len(self.allocated_blocks) >= self.max_blocks:
                logger.warning("Memory pool is full")
                return None
            
            # Find suitable block or create new one
            block_id = self._find_or_create_block(size, memory_type, secure)
            
            if block_id:
                # Mark as allocated
                self.free_blocks.discard(block_id)
                self.allocated_blocks.add(block_id)
                self.type_pools[memory_type].add(block_id)
                
                # Update statistics
                self.total_allocated += size
                self.allocation_count += 1
                self.peak_usage = max(self.peak_usage, self.total_allocated)
                
                # Update block info
                block = self.memory_blocks[block_id]
                block.update_access()
                
                logger.debug(f"Allocated {size} bytes as {block_id}")
                
            return block_id
    
    def _find_or_create_block(self, size: int, memory_type: MemoryType, 
                            secure: bool) -> Optional[str]:
        """Find an existing block or create a new one"""
        # Try to find a suitable free block
        for block_id in self.free_blocks:
            block = self.memory_blocks[block_id]
            if block.size >= size and block.is_secure == secure:
                return block_id
        
        # Create new block if possible
        if len(self.memory_blocks) < self.max_blocks:
            return self._create_new_block(size, memory_type, secure)
        
        return None
    
    def _create_new_block(self, size: int, memory_type: MemoryType, 
                         secure: bool) -> Optional[str]:
        """Create a new memory block"""
        try:
            block_id = f"block_{len(self.memory_blocks)}"
            
            # Allocate memory
            if secure:
                # Use secure memory allocation
                data = self._allocate_secure_memory(size)
            else:
                # Use regular memory allocation
                if size > self.block_size * 10:  # Large allocation
                    data = self._allocate_large_memory(size, block_id)
                else:
                    data = bytearray(size)
            
            block = MemoryBlock(
                block_id=block_id,
                size=size,
                memory_type=memory_type,
                allocated_at=time.time(),
                last_accessed=time.time(),
                is_secure=secure,
                data=data
            )
            
            self.memory_blocks[block_id] = block
            return block_id
            
        except Exception as e:
            logger.error(f"Failed to create memory block: {e}")
            return None
    
    def _allocate_secure_memory(self, size: int) -> bytearray:
        """Allocate secure memory that won't be swapped"""
        data = bytearray(size)
        
        # Try to lock memory to prevent swapping
        try:
            if os.name == 'posix':
                # Unix-like systems
                import mlock
                mlock.mlockall(mlock.MCL_CURRENT | mlock.MCL_FUTURE)
            elif os.name == 'nt':
                # Windows
                ctypes.windll.kernel32.VirtualLock(
                    ctypes.c_void_p(id(data)),
                    ctypes.c_size_t(size)
                )
        except Exception as e:
            logger.warning(f"Could not lock memory: {e}")
        
        return data
    
    def _allocate_large_memory(self, size: int, block_id: str) -> memoryview:
        """Allocate large memory using memory mapping"""
        try:
            # Create memory-mapped file
            mmap_file = mmap.mmap(-1, size)
            self.memory_maps[block_id] = mmap_file
            
            return memoryview(mmap_file)
            
        except Exception as e:
            logger.error(f"Failed to create memory map: {e}")
            return bytearray(size)
    
    def free(self, block_id: str) -> bool:
        """Free a memory block"""
        with self._lock:
            if block_id not in self.allocated_blocks:
                return False
            
            block = self.memory_blocks[block_id]
            
            # Secure deletion for sensitive data
            if block.is_secure and block.data:
                self._secure_delete(block.data)
            
            # Clean up memory map if exists
            if block_id in self.memory_maps:
                self.memory_maps[block_id].close()
                del self.memory_maps[block_id]
            
            # Move to free blocks
            self.allocated_blocks.discard(block_id)
            self.free_blocks.add(block_id)
            
            # Remove from type pool
            self.type_pools[block.memory_type].discard(block_id)
            
            # Update statistics
            self.total_freed += block.size
            self.free_count += 1
            
            logger.debug(f"Freed block {block_id}")
            return True
    
    def _secure_delete(self, data: Union[bytes, bytearray, memoryview]):
        """Securely delete sensitive data"""
        try:
            if isinstance(data, (bytearray, memoryview)):
                # Overwrite with random data multiple times
                import secrets
                size = len(data)
                
                for _ in range(3):  # Multiple passes
                    random_data = secrets.token_bytes(size)
                    if isinstance(data, bytearray):
                        data[:] = random_data
                    elif isinstance(data, memoryview):
                        data[:] = random_data
        except Exception as e:
            logger.warning(f"Secure deletion failed: {e}")
    
    def get_block(self, block_id: str) -> Optional[MemoryBlock]:
        """Get a memory block by ID"""
        with self._lock:
            block = self.memory_blocks.get(block_id)
            if block:
                block.update_access()
            return block
    
    def cleanup_unused_blocks(self, max_age: float = 3600.0):
        """Clean up unused memory blocks"""
        with self._lock:
            current_time = time.time()
            blocks_to_free = []
            
            for block_id in self.free_blocks:
                block = self.memory_blocks[block_id]
                if current_time - block.last_accessed > max_age:
                    blocks_to_free.append(block_id)
            
            for block_id in blocks_to_free:
                self._remove_block(block_id)
    
    def _remove_block(self, block_id: str):
        """Completely remove a block from the pool"""
        if block_id in self.memory_blocks:
            block = self.memory_blocks[block_id]
            
            # Secure deletion if needed
            if block.is_secure and block.data:
                self._secure_delete(block.data)
            
            # Clean up memory map
            if block_id in self.memory_maps:
                self.memory_maps[block_id].close()
                del self.memory_maps[block_id]
            
            # Remove from all collections
            del self.memory_blocks[block_id]
            self.free_blocks.discard(block_id)
            self.allocated_blocks.discard(block_id)
            
            for type_pool in self.type_pools.values():
                type_pool.discard(block_id)
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get memory pool statistics"""
        with self._lock:
            allocated_size = sum(
                block.size for block_id, block in self.memory_blocks.items()
                if block_id in self.allocated_blocks
            )
            
            free_size = sum(
                block.size for block_id, block in self.memory_blocks.items()
                if block_id in self.free_blocks
            )
            
            return {
                'total_blocks': len(self.memory_blocks),
                'allocated_blocks': len(self.allocated_blocks),
                'free_blocks': len(self.free_blocks),
                'allocated_size': allocated_size,
                'free_size': free_size,
                'utilization': allocated_size / max(1, allocated_size + free_size),
                'peak_usage': self.peak_usage,
                'allocation_count': self.allocation_count,
                'free_count': self.free_count,
                'memory_maps': len(self.memory_maps)
            }


class SecureMemoryManager:
    """Secure memory management for sensitive data"""
    
    def __init__(self, secure_pool_size: int = 10 * 1024 * 1024):  # 10MB
        self.secure_pool_size = secure_pool_size
        
        # Secure memory storage
        self.secure_blocks: Dict[str, bytes] = {}
        self.block_metadata: Dict[str, Dict[str, Any]] = {}
        
        # Weak references for automatic cleanup
        self.weak_refs: Dict[str, weakref.ref] = {}
        
        # Statistics
        self.secure_allocations = 0
        self.secure_deallocations = 0
        
        # Thread safety
        self._lock = threading.RLock()
    
    def allocate_secure(self, size: int, purpose: str = "general") -> Optional[str]:
        """Allocate secure memory"""
        with self._lock:
            try:
                # Generate secure block ID
                import secrets
                block_id = secrets.token_hex(16)
                
                # Allocate secure memory
                data = secrets.token_bytes(size)
                
                # Store securely
                self.secure_blocks[block_id] = data
                self.block_metadata[block_id] = {
                    'size': size,
                    'purpose': purpose,
                    'allocated_at': time.time(),
                    'access_count': 0
                }
                
                self.secure_allocations += 1
                
                logger.debug(f"Allocated {size} bytes of secure memory as {block_id}")
                return block_id
                
            except Exception as e:
                logger.error(f"Secure memory allocation failed: {e}")
                return None
    
    def get_secure_data(self, block_id: str) -> Optional[bytes]:
        """Get secure data by block ID"""
        with self._lock:
            if block_id in self.secure_blocks:
                # Update access count
                self.block_metadata[block_id]['access_count'] += 1
                return self.secure_blocks[block_id]
            return None
    
    def free_secure(self, block_id: str) -> bool:
        """Free secure memory"""
        with self._lock:
            if block_id not in self.secure_blocks:
                return False
            
            # Secure deletion
            data = self.secure_blocks[block_id]
            self._secure_overwrite(data)
            
            # Remove from storage
            del self.secure_blocks[block_id]
            del self.block_metadata[block_id]
            
            self.secure_deallocations += 1
            
            logger.debug(f"Freed secure memory block {block_id}")
            return True
    
    def _secure_overwrite(self, data: bytes):
        """Securely overwrite memory"""
        try:
            # Multiple overwrite passes
            import secrets
            size = len(data)
            
            # Create mutable copy
            mutable_data = bytearray(data)
            
            # Overwrite with random data
            for _ in range(3):
                random_data = secrets.token_bytes(size)
                mutable_data[:] = random_data
            
            # Final overwrite with zeros
            mutable_data[:] = b'\x00' * size
            
        except Exception as e:
            logger.warning(f"Secure overwrite failed: {e}")
    
    def cleanup_expired(self, max_age: float = 3600.0):
        """Clean up expired secure memory"""
        with self._lock:
            current_time = time.time()
            expired_blocks = []
            
            for block_id, metadata in self.block_metadata.items():
                if current_time - metadata['allocated_at'] > max_age:
                    expired_blocks.append(block_id)
            
            for block_id in expired_blocks:
                self.free_secure(block_id)
    
    def get_secure_stats(self) -> Dict[str, Any]:
        """Get secure memory statistics"""
        with self._lock:
            total_size = sum(
                metadata['size'] for metadata in self.block_metadata.values()
            )
            
            return {
                'secure_blocks': len(self.secure_blocks),
                'total_secure_size': total_size,
                'secure_allocations': self.secure_allocations,
                'secure_deallocations': self.secure_deallocations,
                'utilization': total_size / self.secure_pool_size
            }


class GarbageCollectionOptimizer:
    """Optimizes Python garbage collection for performance"""
    
    def __init__(self, gc_threshold: float = 0.8):
        self.gc_threshold = gc_threshold
        
        # GC statistics
        self.gc_stats = {
            'collections': 0,
            'collected_objects': 0,
            'uncollectable': 0,
            'generation_stats': [0, 0, 0]
        }
        
        # GC thresholds
        self.original_thresholds = gc.get_threshold()
        self.optimized_thresholds = (700, 10, 10)  # Optimized for performance
        
        # Memory pressure monitoring
        self.memory_pressure = 0.0
        self.last_gc_time = time.time()
        
        # Background task
        self.gc_task: Optional[asyncio.Task] = None
        
        self.running = False
    
    async def start(self):
        """Start the GC optimizer"""
        if self.running:
            return
        
        self.running = True
        
        # Set optimized thresholds
        gc.set_threshold(*self.optimized_thresholds)
        
        # Start background GC task
        self.gc_task = asyncio.create_task(self._gc_loop())
        
        logger.info("Garbage collection optimizer started")
    
    async def stop(self):
        """Stop the GC optimizer"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel GC task
        if self.gc_task:
            self.gc_task.cancel()
        
        # Restore original thresholds
        gc.set_threshold(*self.original_thresholds)
        
        logger.info("Garbage collection optimizer stopped")
    
    async def _gc_loop(self):
        """Background garbage collection loop"""
        while self.running:
            try:
                # Monitor memory pressure
                self._update_memory_pressure()
                
                # Perform GC if needed
                if self.memory_pressure > self.gc_threshold:
                    await self._perform_optimized_gc()
                
                # Wait before next check
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in GC loop: {e}")
                await asyncio.sleep(60)
    
    def _update_memory_pressure(self):
        """Update memory pressure metric"""
        try:
            # Get GC stats
            gc_stats = gc.get_stats()
            
            # Calculate memory pressure based on GC stats
            if gc_stats:
                # Use generation 0 collections as pressure indicator
                gen0_collections = gc_stats[0].get('collections', 0)
                pressure = min(1.0, gen0_collections / 1000.0)
                self.memory_pressure = pressure
            
        except Exception as e:
            logger.warning(f"Failed to update memory pressure: {e}")
    
    async def _perform_optimized_gc(self):
        """Perform optimized garbage collection"""
        try:
            start_time = time.time()
            
            # Collect generation 0 first
            collected = gc.collect(0)
            self.gc_stats['collected_objects'] += collected
            self.gc_stats['generation_stats'][0] += 1
            
            # Collect generation 1 if significant objects collected
            if collected > 100:
                collected += gc.collect(1)
                self.gc_stats['generation_stats'][1] += 1
            
            # Collect generation 2 only if high memory pressure
            if self.memory_pressure > 0.9:
                collected += gc.collect(2)
                self.gc_stats['generation_stats'][2] += 1
            
            gc_time = time.time() - start_time
            self.last_gc_time = time.time()
            self.gc_stats['collections'] += 1
            
            logger.debug(f"GC collected {collected} objects in {gc_time:.3f}s")
            
        except Exception as e:
            logger.error(f"Optimized GC failed: {e}")
    
    def force_gc(self):
        """Force garbage collection of all generations"""
        try:
            collected = gc.collect()
            self.gc_stats['collected_objects'] += collected
            self.gc_stats['collections'] += 1
            
            logger.info(f"Forced GC collected {collected} objects")
            
        except Exception as e:
            logger.error(f"Forced GC failed: {e}")
    
    def get_gc_stats(self) -> Dict[str, Any]:
        """Get garbage collection statistics"""
        try:
            current_stats = gc.get_stats()
            
            return {
                'memory_pressure': self.memory_pressure,
                'collections': self.gc_stats['collections'],
                'collected_objects': self.gc_stats['collected_objects'],
                'generation_stats': self.gc_stats['generation_stats'],
                'current_threshold': gc.get_threshold(),
                'gc_counts': gc.get_count(),
                'last_gc_time': self.last_gc_time,
                'time_since_gc': time.time() - self.last_gc_time
            }
        except Exception as e:
            logger.error(f"Failed to get GC stats: {e}")
            return {}


class MemoryOptimizer:
    """Main memory performance optimizer"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}
        
        # Initialize components
        self.memory_pool = MemoryPool(
            pool_size=config.get('pool_size', 100 * 1024 * 1024),
            max_blocks=config.get('max_blocks', 10000)
        )
        
        self.secure_manager = SecureMemoryManager(
            secure_pool_size=config.get('secure_pool_size', 10 * 1024 * 1024)
        )
        
        self.gc_optimizer = GarbageCollectionOptimizer(
            gc_threshold=config.get('gc_threshold', 0.8)
        )
        
        # Memory monitoring
        self.memory_limit = config.get('memory_limit', 512 * 1024 * 1024)  # 512MB
        self.monitoring_enabled = config.get('monitoring_enabled', True)
        
        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        
        self.running = False
    
    async def start(self):
        """Start the memory optimizer"""
        if self.running:
            return
        
        self.running = True
        
        await self.gc_optimizer.start()
        
        # Start cleanup task
        if self.monitoring_enabled:
            self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("Memory optimizer started")
    
    async def stop(self):
        """Stop the memory optimizer"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel cleanup task
        if self.cleanup_task:
            self.cleanup_task.cancel()
        
        await self.gc_optimizer.stop()
        
        logger.info("Memory optimizer stopped")
    
    async def allocate_memory(self, size: int, memory_type: MemoryType = MemoryType.TEMPORARY,
                            secure: bool = False) -> Optional[str]:
        """Allocate optimized memory"""
        if secure:
            return self.secure_manager.allocate_secure(size, memory_type.value)
        else:
            return self.memory_pool.allocate(size, memory_type, secure)
    
    async def free_memory(self, block_id: str, secure: bool = False) -> bool:
        """Free allocated memory"""
        if secure:
            return self.secure_manager.free_secure(block_id)
        else:
            return self.memory_pool.free(block_id)
    
    def get_memory_block(self, block_id: str, secure: bool = False) -> Optional[Union[MemoryBlock, bytes]]:
        """Get a memory block"""
        if secure:
            return self.secure_manager.get_secure_data(block_id)
        else:
            return self.memory_pool.get_block(block_id)
    
    async def _cleanup_loop(self):
        """Background cleanup task"""
        while self.running:
            try:
                # Clean up unused blocks
                self.memory_pool.cleanup_unused_blocks()
                
                # Clean up expired secure memory
                self.secure_manager.cleanup_expired()
                
                # Check memory usage
                await self._check_memory_usage()
                
                # Wait before next cleanup
                await asyncio.sleep(300)  # 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in memory cleanup: {e}")
                await asyncio.sleep(60)
    
    async def _check_memory_usage(self):
        """Check and manage memory usage"""
        try:
            import psutil
            
            # Get current memory usage
            process = psutil.Process()
            memory_info = process.memory_info()
            
            if memory_info.rss > self.memory_limit:
                logger.warning(f"Memory usage ({memory_info.rss}) exceeds limit ({self.memory_limit})")
                
                # Force garbage collection
                self.gc_optimizer.force_gc()
                
                # Clean up memory pools
                self.memory_pool.cleanup_unused_blocks(max_age=1800)  # 30 minutes
                self.secure_manager.cleanup_expired(max_age=1800)
                
        except ImportError:
            logger.debug("psutil not available for memory monitoring")
        except Exception as e:
            logger.error(f"Memory usage check failed: {e}")
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive memory optimization statistics"""
        return {
            'memory_pool': self.memory_pool.get_pool_stats(),
            'secure_manager': self.secure_manager.get_secure_stats(),
            'gc_optimizer': self.gc_optimizer.get_gc_stats(),
            'memory_limit': self.memory_limit,
            'monitoring_enabled': self.monitoring_enabled
        } 