"""
Large Message and File Transfer Optimizer

Specialized memory optimizations for handling large messages and file transfers
including streaming, chunking, and memory-efficient processing.
"""

import asyncio
import time
import logging
import threading
from typing import Dict, List, Optional, Any, AsyncGenerator, Tuple, Union
from collections import deque
import weakref
import gc

logger = logging.getLogger(__name__)


class StreamingBuffer:
    """Memory-efficient streaming buffer for large data"""

    def __init__(self, chunk_size: int = 64 * 1024, max_memory: int = 100 * 1024 * 1024):
        self.chunk_size = chunk_size
        self.max_memory = max_memory

        # Buffer management
        self.chunks: deque = deque()
        self.current_size = 0
        self.total_size = 0

        # Read/write positions
        self.read_position = 0
        self.write_position = 0

        # Thread safety
        self._lock = threading.RLock()

    def write_chunk(self, data: bytes) -> bool:
        """Write a chunk of data to the buffer"""
        with self._lock:
            chunk_size = len(data)

            # Check memory limit
            if self.current_size + chunk_size > self.max_memory:
                # Try to free some space by removing old chunks
                self._cleanup_old_chunks()

                if self.current_size + chunk_size > self.max_memory:
                    logger.warning("Buffer memory limit exceeded")
                    return False

            # Add chunk
            self.chunks.append(data)
            self.current_size += chunk_size
            self.total_size += chunk_size
            self.write_position += chunk_size

            return True

    def read_chunk(self, size: int) -> Optional[bytes]:
        """Read a chunk of data from the buffer"""
        with self._lock:
            if self.read_position >= self.total_size:
                return None

            # Find chunk containing the read position
            current_pos = 0
            for i, chunk in enumerate(self.chunks):
                chunk_start = current_pos
                chunk_end = current_pos + len(chunk)

                if chunk_start <= self.read_position < chunk_end:
                    # Calculate offset within chunk
                    offset = self.read_position - chunk_start
                    available = min(size, len(chunk) - offset)

                    # Read data
                    data = chunk[offset:offset + available]
                    self.read_position += len(data)

                    # Remove chunk if fully read
                    if self.read_position >= chunk_end:
                        removed_chunk = self.chunks[i]
                        self.current_size -= len(removed_chunk)
                        # Don't remove immediately to avoid index issues

                    return data

                current_pos = chunk_end

            return None

    def _cleanup_old_chunks(self):
        """Remove chunks that have been fully read"""
        while self.chunks:
            chunk = self.chunks[0]
            chunk_end = self.read_position

            # Calculate if this chunk is fully read
            if chunk_end >= len(chunk):
                removed_chunk = self.chunks.popleft()
                self.current_size -= len(removed_chunk)
            else:
                break

    def get_stats(self) -> Dict[str, Any]:
        """Get buffer statistics"""
        with self._lock:
            return {
                'chunk_count': len(self.chunks),
                'current_size': self.current_size,
                'total_size': self.total_size,
                'read_position': self.read_position,
                'write_position': self.write_position,
                'memory_utilization': self.current_size / self.max_memory
            }


class ChunkedFileTransfer:
    """Memory-efficient file transfer with chunking"""

    def __init__(self, chunk_size: int = 128 * 1024, max_concurrent_chunks: int = 10):
        self.chunk_size = chunk_size
        self.max_concurrent_chunks = max_concurrent_chunks

        # Transfer state
        self.active_transfers: Dict[str, Dict[str, Any]] = {}
        self.completed_chunks: Dict[str, Set[int]] = {}
        self.failed_chunks: Dict[str, Set[int]] = {}

        # Thread safety
        self._lock = threading.RLock()

    async def transfer_file_chunked(self, file_path: str, transfer_func: callable,
                                   transfer_id: str) -> AsyncGenerator[Dict[str, Any], None]:
        """Transfer a file in chunks with progress reporting"""

        # Initialize transfer
        file_size = await self._get_file_size(file_path)
        if file_size == 0:
            yield {'status': 'error', 'message': 'Empty file'}
            return

        with self._lock:
            self.active_transfers[transfer_id] = {
                'file_path': file_path,
                'file_size': file_size,
                'chunk_size': self.chunk_size,
                'start_time': time.time(),
                'total_chunks': (file_size + self.chunk_size - 1) // self.chunk_size,
                'completed_chunks': 0,
                'failed_chunks': 0
            }
            self.completed_chunks[transfer_id] = set()
            self.failed_chunks[transfer_id] = set()

        try:
            # Transfer chunks concurrently
            semaphore = asyncio.Semaphore(self.max_concurrent_chunks)

            async def transfer_chunk(chunk_index: int) -> Tuple[int, bool, str]:
                async with semaphore:
                    try:
                        chunk_data = await self._read_file_chunk(file_path, chunk_index)
                        if chunk_data is None:
                            return chunk_index, False, "Failed to read chunk"

                        # Transfer chunk
                        success = await transfer_func(chunk_data, chunk_index)

                        with self._lock:
                            if success:
                                self.completed_chunks[transfer_id].add(chunk_index)
                                self.active_transfers[transfer_id]['completed_chunks'] += 1
                            else:
                                self.failed_chunks[transfer_id].add(chunk_index)
                                self.active_transfers[transfer_id]['failed_chunks'] += 1

                        return chunk_index, success, "" if success else "Transfer failed"

                    except Exception as e:
                        with self._lock:
                            self.failed_chunks[transfer_id].add(chunk_index)
                            self.active_transfers[transfer_id]['failed_chunks'] += 1

                        return chunk_index, False, str(e)

            # Create tasks for all chunks
            tasks = []
            for chunk_index in range(self.active_transfers[transfer_id]['total_chunks']):
                task = asyncio.create_task(transfer_chunk(chunk_index))
                tasks.append(task)

            # Process results as they complete
            completed = 0
            total_chunks = len(tasks)

            for task in asyncio.as_completed(tasks):
                chunk_index, success, error = await task
                completed += 1

                # Calculate progress
                progress = completed / total_chunks

                with self._lock:
                    transfer_info = self.active_transfers[transfer_id]

                yield {
                    'status': 'progress',
                    'chunk_index': chunk_index,
                    'success': success,
                    'error': error,
                    'completed': completed,
                    'total': total_chunks,
                    'progress': progress,
                    'transfer_speed': self._calculate_transfer_speed(transfer_info, completed)
                }

            # Final status
            with self._lock:
                transfer_info = self.active_transfers[transfer_id]
                success = transfer_info['failed_chunks'] == 0

            yield {
                'status': 'completed' if success else 'failed',
                'total_chunks': total_chunks,
                'successful_chunks': transfer_info['completed_chunks'],
                'failed_chunks': transfer_info['failed_chunks'],
                'total_time': time.time() - transfer_info['start_time'],
                'file_size': file_size
            }

        finally:
            # Cleanup
            with self._lock:
                if transfer_id in self.active_transfers:
                    del self.active_transfers[transfer_id]
                if transfer_id in self.completed_chunks:
                    del self.completed_chunks[transfer_id]
                if transfer_id in self.failed_chunks:
                    del self.failed_chunks[transfer_id]

    async def _get_file_size(self, file_path: str) -> int:
        """Get file size"""
        try:
            import os
            return os.path.getsize(file_path)
        except Exception as e:
            logger.error(f"Failed to get file size: {e}")
            return 0

    async def _read_file_chunk(self, file_path: str, chunk_index: int) -> Optional[bytes]:
        """Read a specific chunk from file"""
        try:
            offset = chunk_index * self.chunk_size
            remaining_size = await self._get_file_size(file_path) - offset

            if remaining_size <= 0:
                return None

            read_size = min(self.chunk_size, remaining_size)

            # Read chunk asynchronously
            loop = asyncio.get_event_loop()

            def read_chunk():
                with open(file_path, 'rb') as f:
                    f.seek(offset)
                    return f.read(read_size)

            return await loop.run_in_executor(None, read_chunk)

        except Exception as e:
            logger.error(f"Failed to read file chunk {chunk_index}: {e}")
            return None

    def _calculate_transfer_speed(self, transfer_info: Dict[str, Any], completed_chunks: int) -> float:
        """Calculate current transfer speed in bytes per second"""
        elapsed_time = time.time() - transfer_info['start_time']
        if elapsed_time == 0:
            return 0.0

        bytes_transferred = completed_chunks * transfer_info['chunk_size']
        return bytes_transferred / elapsed_time


class LargeMessageProcessor:
    """Memory-efficient processor for large messages"""

    def __init__(self, max_memory_per_message: int = 50 * 1024 * 1024,  # 50MB
                 chunk_size: int = 64 * 1024):  # 64KB
        self.max_memory_per_message = max_memory_per_message
        self.chunk_size = chunk_size

        # Active message processing
        self.active_messages: Dict[str, Dict[str, Any]] = {}

        # Memory tracking
        self.memory_usage: Dict[str, int] = {}

        # Thread safety
        self._lock = threading.RLock()

    async def process_large_message(self, message_id: str, message_data: bytes,
                                   processor_func: callable) -> AsyncGenerator[Dict[str, Any], None]:
        """Process a large message in chunks"""

        message_size = len(message_data)

        with self._lock:
            self.active_messages[message_id] = {
                'size': message_size,
                'processed_chunks': 0,
                'total_chunks': (message_size + self.chunk_size - 1) // self.chunk_size,
                'start_time': time.time(),
                'status': 'processing'
            }
            self.memory_usage[message_id] = 0

        try:
            # Process message in chunks
            for chunk_index in range(self.active_messages[message_id]['total_chunks']):
                start_pos = chunk_index * self.chunk_size
                end_pos = min(start_pos + self.chunk_size, message_size)
                chunk = message_data[start_pos:end_pos]

                # Process chunk
                try:
                    await processor_func(chunk, chunk_index)

                    with self._lock:
                        self.active_messages[message_id]['processed_chunks'] += 1

                    # Report progress
                    progress = (chunk_index + 1) / self.active_messages[message_id]['total_chunks']

                    yield {
                        'status': 'chunk_processed',
                        'chunk_index': chunk_index,
                        'progress': progress,
                        'chunk_size': len(chunk)
                    }

                except Exception as e:
                    logger.error(f"Failed to process chunk {chunk_index} of message {message_id}: {e}")

                    yield {
                        'status': 'chunk_error',
                        'chunk_index': chunk_index,
                        'error': str(e)
                    }

                    # Continue with other chunks
                    continue

            # Final result
            with self._lock:
                self.active_messages[message_id]['status'] = 'completed'

            yield {
                'status': 'completed',
                'total_chunks': self.active_messages[message_id]['total_chunks'],
                'processing_time': time.time() - self.active_messages[message_id]['start_time']
            }

        except Exception as e:
            logger.error(f"Message processing failed for {message_id}: {e}")

            with self._lock:
                self.active_messages[message_id]['status'] = 'failed'

            yield {
                'status': 'failed',
                'error': str(e)
            }

        finally:
            # Cleanup
            with self._lock:
                if message_id in self.active_messages:
                    del self.active_messages[message_id]
                if message_id in self.memory_usage:
                    del self.memory_usage[message_id]

    def get_processing_stats(self) -> Dict[str, Any]:
        """Get message processing statistics"""
        with self._lock:
            return {
                'active_messages': len(self.active_messages),
                'total_memory_usage': sum(self.memory_usage.values()),
                'max_memory_per_message': self.max_memory_per_message,
                'messages': {k: v.copy() for k, v in self.active_messages.items()}
            }


class MemoryEfficientCache:
    """Memory-efficient cache for frequently accessed data"""

    def __init__(self, max_memory: int = 200 * 1024 * 1024,  # 200MB
                 cleanup_interval: float = 300.0):  # 5 minutes
        self.max_memory = max_memory
        self.cleanup_interval = cleanup_interval

        # Cache storage
        self.cache: Dict[str, Any] = {}
        self.cache_metadata: Dict[str, Dict[str, Any]] = {}
        self.access_order: deque = deque()

        # Memory tracking
        self.current_memory = 0

        # Statistics
        self.hits = 0
        self.misses = 0
        self.evictions = 0

        # Background cleanup
        self.cleanup_task: Optional[asyncio.Task] = None
        self.running = False

        # Thread safety
        self._lock = threading.RLock()

    async def start(self):
        """Start the cache cleanup task"""
        if self.running:
            return

        self.running = True
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())

        logger.info("Memory-efficient cache started")

    async def stop(self):
        """Stop the cache cleanup task"""
        if not self.running:
            return

        self.running = False

        if self.cleanup_task:
            self.cleanup_task.cancel()

        logger.info("Memory-efficient cache stopped")

    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        with self._lock:
            if key not in self.cache:
                self.misses += 1
                return None

            metadata = self.cache_metadata[key]

            # Check if expired
            if time.time() > metadata['expires_at']:
                self._remove_key(key)
                self.misses += 1
                return None

            # Update access order
            self.access_order.remove(key)
            self.access_order.append(key)

            # Update metadata
            metadata['access_count'] += 1
            metadata['last_accessed'] = time.time()

            self.hits += 1
            return self.cache[key]

    def put(self, key: str, value: Any, ttl: float = 3600.0) -> bool:
        """Put value in cache with size management"""
        with self._lock:
            value_size = self._estimate_size(value)

            # Check if we need to evict items
            while (self.current_memory + value_size > self.max_memory and
                   self.cache):
                self._evict_lru()

            # Remove existing key if present
            if key in self.cache:
                self._remove_key(key)

            # Add new item
            current_time = time.time()
            self.cache[key] = value
            self.cache_metadata[key] = {
                'size': value_size,
                'created_at': current_time,
                'expires_at': current_time + ttl,
                'access_count': 0,
                'last_accessed': current_time
            }
            self.access_order.append(key)
            self.current_memory += value_size

            return True

    def _remove_key(self, key: str):
        """Remove a key from cache"""
        if key in self.cache:
            metadata = self.cache_metadata[key]
            self.current_memory -= metadata['size']

            del self.cache[key]
            del self.cache_metadata[key]

            if key in self.access_order:
                self.access_order.remove(key)

    def _evict_lru(self):
        """Evict least recently used item"""
        if self.access_order:
            lru_key = self.access_order.popleft()
            self._remove_key(lru_key)
            self.evictions += 1

    def _estimate_size(self, value: Any) -> int:
        """Estimate memory size of value"""
        try:
            import sys
            size = sys.getsizeof(value)

            # For containers, add size of contents
            if isinstance(value, (list, tuple)):
                size += sum(sys.getsizeof(item) for item in value)
            elif isinstance(value, dict):
                size += sum(sys.getsizeof(k) + sys.getsizeof(v) for k, v in value.items())

            return size
        except:
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

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            hit_rate = self.hits / max(1, self.hits + self.misses)

            return {
                'cache_size': len(self.cache),
                'current_memory': self.current_memory,
                'max_memory': self.max_memory,
                'utilization': self.current_memory / self.max_memory,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': hit_rate,
                'evictions': self.evictions
            }


class LargeMessageOptimizer:
    """Main optimizer for large message and file transfer handling"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}

        # Initialize components
        self.streaming_buffer = StreamingBuffer(
            chunk_size=config.get('chunk_size', 64 * 1024),
            max_memory=config.get('max_memory', 100 * 1024 * 1024)
        )

        self.file_transfer = ChunkedFileTransfer(
            chunk_size=config.get('file_chunk_size', 128 * 1024),
            max_concurrent_chunks=config.get('max_concurrent_chunks', 10)
        )

        self.message_processor = LargeMessageProcessor(
            max_memory_per_message=config.get('max_message_memory', 50 * 1024 * 1024),
            chunk_size=config.get('message_chunk_size', 64 * 1024)
        )

        self.efficient_cache = MemoryEfficientCache(
            max_memory=config.get('cache_max_memory', 200 * 1024 * 1024),
            cleanup_interval=config.get('cache_cleanup_interval', 300.0)
        )

        # Configuration
        self.enable_compression = config.get('enable_compression', True)
        self.compression_threshold = config.get('compression_threshold', 1024)

        # State
        self.running = False

    async def start(self):
        """Start the large message optimizer"""
        if self.running:
            return

        self.running = True
        await self.efficient_cache.start()

        logger.info("Large message optimizer started")

    async def stop(self):
        """Stop the large message optimizer"""
        if not self.running:
            return

        self.running = False
        await self.efficient_cache.stop()

        logger.info("Large message optimizer stopped")

    async def process_large_message(self, message_id: str, message_data: bytes,
                                   processor_func: callable) -> AsyncGenerator[Dict[str, Any], None]:
        """Process a large message with memory optimization"""
        async for progress in self.message_processor.process_large_message(
            message_id, message_data, processor_func
        ):
            yield progress

    async def transfer_file_chunked(self, file_path: str, transfer_func: callable,
                                   transfer_id: str) -> AsyncGenerator[Dict[str, Any], None]:
        """Transfer a file in chunks with progress reporting"""
        async for progress in self.file_transfer.transfer_file_chunked(
            file_path, transfer_func, transfer_id
        ):
            yield progress

    def cache_data(self, key: str, data: Any, ttl: float = 3600.0) -> bool:
        """Cache data efficiently"""
        return self.efficient_cache.put(key, data, ttl)

    def get_cached_data(self, key: str) -> Optional[Any]:
        """Get cached data"""
        return self.efficient_cache.get(key)

    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics"""
        return {
            'streaming_buffer': self.streaming_buffer.get_stats(),
            'file_transfer': {
                'active_transfers': len(self.file_transfer.active_transfers),
                'completed_chunks': sum(len(chunks) for chunks in self.file_transfer.completed_chunks.values()),
                'failed_chunks': sum(len(chunks) for chunks in self.file_transfer.failed_chunks.values())
            },
            'message_processor': self.message_processor.get_processing_stats(),
            'efficient_cache': self.efficient_cache.get_cache_stats(),
            'configuration': {
                'enable_compression': self.enable_compression,
                'compression_threshold': self.compression_threshold
            }
        }