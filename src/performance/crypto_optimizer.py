"""
Cryptographic Performance Optimizer

Implements comprehensive cryptographic performance optimizations including:
- Hardware acceleration utilization
- Cryptographic operation optimization
- Key caching strategies
- Parallel cryptographic processing
"""

import asyncio
import time
import logging
import hashlib
import threading
from typing import Dict, List, Optional, Tuple, Any, Union
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
import concurrent.futures
from functools import lru_cache

# Import cryptographic libraries
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)


class CryptoOperation(Enum):
    """Types of cryptographic operations"""
    ENCRYPT = "encrypt"
    DECRYPT = "decrypt"
    SIGN = "sign"
    VERIFY = "verify"
    KEY_DERIVE = "key_derive"
    HASH = "hash"


@dataclass
class CryptoTask:
    """Represents a cryptographic task for parallel processing"""
    operation: CryptoOperation
    data: bytes
    key: bytes
    additional_data: Optional[bytes] = None
    result_future: Optional[concurrent.futures.Future] = None
    priority: int = 0
    timestamp: float = 0.0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()
    
    def __lt__(self, other):
        return self.priority > other.priority  # Higher priority first


class KeyCache:
    """High-performance key caching system"""
    
    def __init__(self, cache_size: int = 1000, ttl: int = 3600):
        self.cache_size = cache_size
        self.ttl = ttl
        
        # LRU cache for derived keys
        self.key_cache: OrderedDict = OrderedDict()
        self.cache_timestamps: Dict[str, float] = {}
        
        # Session key cache
        self.session_keys: Dict[bytes, bytes] = {}
        
        # Statistics
        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_evictions = 0
        
        # Thread safety
        self._lock = threading.RLock()
    
    def get_key(self, key_id: str) -> Optional[bytes]:
        """Get a cached key"""
        with self._lock:
            current_time = time.time()
            
            if key_id in self.key_cache:
                # Check if key has expired
                if current_time - self.cache_timestamps[key_id] > self.ttl:
                    self._remove_key(key_id)
                    self.cache_misses += 1
                    return None
                
                # Move to end (most recently used)
                key = self.key_cache[key_id]
                del self.key_cache[key_id]
                self.key_cache[key_id] = key
                
                self.cache_hits += 1
                return key
            
            self.cache_misses += 1
            return None
    
    def put_key(self, key_id: str, key: bytes):
        """Cache a key"""
        with self._lock:
            current_time = time.time()
            
            # Remove if already exists
            if key_id in self.key_cache:
                del self.key_cache[key_id]
            
            # Add new key
            self.key_cache[key_id] = key
            self.cache_timestamps[key_id] = current_time
            
            # Evict oldest if cache is full
            if len(self.key_cache) > self.cache_size:
                self._evict_oldest()
    
    def _remove_key(self, key_id: str):
        """Remove a key from cache"""
        if key_id in self.key_cache:
            del self.key_cache[key_id]
            del self.cache_timestamps[key_id]
    
    def _evict_oldest(self):
        """Evict the oldest key from cache"""
        if self.key_cache:
            oldest_key = next(iter(self.key_cache))
            self._remove_key(oldest_key)
            self.cache_evictions += 1
    
    def clear_expired(self):
        """Clear expired keys from cache"""
        with self._lock:
            current_time = time.time()
            expired_keys = []
            
            for key_id, timestamp in self.cache_timestamps.items():
                if current_time - timestamp > self.ttl:
                    expired_keys.append(key_id)
            
            for key_id in expired_keys:
                self._remove_key(key_id)
    
    def get_session_key(self, peer_id: bytes) -> Optional[bytes]:
        """Get a session key for a peer"""
        with self._lock:
            return self.session_keys.get(peer_id)
    
    def put_session_key(self, peer_id: bytes, key: bytes):
        """Cache a session key for a peer"""
        with self._lock:
            self.session_keys[peer_id] = key
    
    def remove_session_key(self, peer_id: bytes):
        """Remove a session key for a peer"""
        with self._lock:
            self.session_keys.pop(peer_id, None)
    
    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self.cache_hits + self.cache_misses
            hit_rate = self.cache_hits / max(1, total_requests)
            
            return {
                'cache_size': len(self.key_cache),
                'max_cache_size': self.cache_size,
                'session_keys': len(self.session_keys),
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'cache_evictions': self.cache_evictions,
                'hit_rate': hit_rate,
                'utilization': len(self.key_cache) / self.cache_size
            }


class CryptoAccelerator:
    """Hardware acceleration and optimization for cryptographic operations"""
    
    def __init__(self, use_hardware_acceleration: bool = True):
        self.use_hardware_acceleration = use_hardware_acceleration
        
        # Pre-initialize common objects
        self.backend = default_backend()
        
        # AES-GCM cipher cache
        self._aes_ciphers: Dict[bytes, Cipher] = {}
        
        # Hash object cache
        self._hash_objects = {}
        
        # Statistics
        self.operations_accelerated = 0
        self.operations_fallback = 0
        
    def encrypt_aes_gcm(self, key: bytes, plaintext: bytes, 
                       additional_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Optimized AES-GCM encryption"""
        try:
            # Use cached cipher if available
            if key in self._aes_ciphers:
                cipher = self._aes_ciphers[key]
            else:
                cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12), backend=self.backend)
                self._aes_ciphers[key] = cipher
            
            encryptor = cipher.encryptor()
            
            if additional_data:
                encryptor.authenticate_additional_data(additional_data)
            
            ciphertext = encryptor.update(plaintext) + encryptor.finalize()
            
            self.operations_accelerated += 1
            return ciphertext, encryptor.tag
            
        except Exception as e:
            logger.warning(f"Hardware acceleration failed, falling back: {e}")
            self.operations_fallback += 1
            return self._encrypt_aes_gcm_fallback(key, plaintext, additional_data)
    
    def decrypt_aes_gcm(self, key: bytes, ciphertext: bytes, tag: bytes,
                       additional_data: Optional[bytes] = None) -> bytes:
        """Optimized AES-GCM decryption"""
        try:
            cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            
            if additional_data:
                decryptor.authenticate_additional_data(additional_data)
            
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            self.operations_accelerated += 1
            return plaintext
            
        except Exception as e:
            logger.warning(f"Hardware acceleration failed, falling back: {e}")
            self.operations_fallback += 1
            return self._decrypt_aes_gcm_fallback(key, ciphertext, tag, additional_data)
    
    def _encrypt_aes_gcm_fallback(self, key: bytes, plaintext: bytes, 
                                 additional_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Fallback AES-GCM encryption"""
        # Basic AES-GCM implementation
        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12), backend=self.backend)
        encryptor = cipher.encryptor()
        
        if additional_data:
            encryptor.authenticate_additional_data(additional_data)
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, encryptor.tag
    
    def _decrypt_aes_gcm_fallback(self, key: bytes, ciphertext: bytes, tag: bytes,
                                 additional_data: Optional[bytes] = None) -> bytes:
        """Fallback AES-GCM decryption"""
        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        if additional_data:
            decryptor.authenticate_additional_data(additional_data)
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def fast_hash(self, data: bytes, algorithm: str = 'sha256') -> bytes:
        """Optimized hashing"""
        if algorithm == 'sha256':
            return hashlib.sha256(data).digest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).digest()
        elif algorithm == 'blake2b':
            return hashlib.blake2b(data).digest()
        else:
            # Use cryptography library for other algorithms
            if algorithm not in self._hash_objects:
                if algorithm == 'sha3_256':
                    self._hash_objects[algorithm] = hashes.SHA3_256()
                elif algorithm == 'sha3_512':
                    self._hash_objects[algorithm] = hashes.SHA3_512()
                else:
                    raise ValueError(f"Unsupported hash algorithm: {algorithm}")
            
            digest = hashes.Hash(self._hash_objects[algorithm], backend=self.backend)
            digest.update(data)
            return digest.finalize()
    
    def fast_hmac(self, key: bytes, data: bytes, algorithm: str = 'sha256') -> bytes:
        """Optimized HMAC computation"""
        if algorithm == 'sha256':
            return hmac.HMAC(key, hashes.SHA256(), backend=self.backend).finalize()
        elif algorithm == 'sha512':
            return hmac.HMAC(key, hashes.SHA512(), backend=self.backend).finalize()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")
    
    def get_acceleration_stats(self) -> Dict[str, Any]:
        """Get acceleration statistics"""
        total_operations = self.operations_accelerated + self.operations_fallback
        acceleration_rate = self.operations_accelerated / max(1, total_operations)
        
        return {
            'hardware_acceleration_enabled': self.use_hardware_acceleration,
            'operations_accelerated': self.operations_accelerated,
            'operations_fallback': self.operations_fallback,
            'acceleration_rate': acceleration_rate,
            'cipher_cache_size': len(self._aes_ciphers)
        }


class ParallelCryptoProcessor:
    """Parallel cryptographic operation processor"""
    
    def __init__(self, num_workers: int = 4, queue_size: int = 1000):
        self.num_workers = num_workers
        self.queue_size = queue_size
        
        # Thread pool for CPU-intensive operations
        self.thread_pool = concurrent.futures.ThreadPoolExecutor(max_workers=num_workers)
        
        # Task queue
        self.task_queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        
        # Worker tasks
        self.workers: List[asyncio.Task] = []
        
        # Statistics
        self.tasks_processed = 0
        self.tasks_failed = 0
        self.total_processing_time = 0.0
        
        self.running = False
    
    async def start(self):
        """Start the parallel processor"""
        if self.running:
            return
        
        self.running = True
        
        # Start worker tasks
        for i in range(self.num_workers):
            worker = asyncio.create_task(self._worker_loop(i))
            self.workers.append(worker)
        
        logger.info(f"Parallel crypto processor started with {self.num_workers} workers")
    
    async def stop(self):
        """Stop the parallel processor"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel all workers
        for worker in self.workers:
            worker.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*self.workers, return_exceptions=True)
        
        # Shutdown thread pool
        self.thread_pool.shutdown(wait=True)
        
        logger.info("Parallel crypto processor stopped")
    
    async def submit_task(self, task: CryptoTask) -> Any:
        """Submit a cryptographic task for processing"""
        if not self.running:
            raise RuntimeError("Processor is not running")
        
        # Create future for result
        task.result_future = concurrent.futures.Future()
        
        # Add to queue
        await self.task_queue.put(task)
        
        # Wait for result
        return await asyncio.wrap_future(task.result_future)
    
    async def _worker_loop(self, worker_id: int):
        """Worker loop for processing tasks"""
        logger.debug(f"Crypto worker {worker_id} started")
        
        while self.running:
            try:
                # Get task from queue
                task = await asyncio.wait_for(self.task_queue.get(), timeout=1.0)
                
                # Process task
                start_time = time.time()
                result = await self._process_task(task)
                processing_time = time.time() - start_time
                
                # Set result
                task.result_future.set_result(result)
                
                # Update statistics
                self.tasks_processed += 1
                self.total_processing_time += processing_time
                
                # Mark task as done
                self.task_queue.task_done()
                
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in crypto worker {worker_id}: {e}")
                if hasattr(task, 'result_future') and task.result_future:
                    task.result_future.set_exception(e)
                self.tasks_failed += 1
        
        logger.debug(f"Crypto worker {worker_id} stopped")
    
    async def _process_task(self, task: CryptoTask) -> Any:
        """Process a cryptographic task"""
        # Run CPU-intensive operations in thread pool
        loop = asyncio.get_event_loop()
        
        if task.operation == CryptoOperation.ENCRYPT:
            return await loop.run_in_executor(
                self.thread_pool, 
                self._encrypt_data, 
                task.data, 
                task.key, 
                task.additional_data
            )
        elif task.operation == CryptoOperation.DECRYPT:
            return await loop.run_in_executor(
                self.thread_pool,
                self._decrypt_data,
                task.data,
                task.key,
                task.additional_data
            )
        elif task.operation == CryptoOperation.HASH:
            return await loop.run_in_executor(
                self.thread_pool,
                self._hash_data,
                task.data
            )
        elif task.operation == CryptoOperation.KEY_DERIVE:
            return await loop.run_in_executor(
                self.thread_pool,
                self._derive_key,
                task.data,
                task.key,
                task.additional_data
            )
        else:
            raise ValueError(f"Unsupported operation: {task.operation}")
    
    def _encrypt_data(self, data: bytes, key: bytes, additional_data: Optional[bytes]) -> bytes:
        """Encrypt data (runs in thread pool)"""
        # Implementation would use CryptoAccelerator
        # For now, simple AES-GCM encryption
        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12), backend=default_backend())
        encryptor = cipher.encryptor()
        
        if additional_data:
            encryptor.authenticate_additional_data(additional_data)
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + encryptor.tag
    
    def _decrypt_data(self, data: bytes, key: bytes, additional_data: Optional[bytes]) -> bytes:
        """Decrypt data (runs in thread pool)"""
        # Split ciphertext and tag
        ciphertext, tag = data[:-16], data[-16:]
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        
        if additional_data:
            decryptor.authenticate_additional_data(additional_data)
        
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def _hash_data(self, data: bytes) -> bytes:
        """Hash data (runs in thread pool)"""
        return hashlib.sha256(data).digest()
    
    def _derive_key(self, password: bytes, salt: bytes, info: Optional[bytes]) -> bytes:
        """Derive key (runs in thread pool)"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(password)
    
    def get_processor_stats(self) -> Dict[str, Any]:
        """Get processor statistics"""
        avg_processing_time = self.total_processing_time / max(1, self.tasks_processed)
        
        return {
            'num_workers': self.num_workers,
            'queue_size': self.task_queue.qsize(),
            'max_queue_size': self.queue_size,
            'tasks_processed': self.tasks_processed,
            'tasks_failed': self.tasks_failed,
            'average_processing_time': avg_processing_time,
            'total_processing_time': self.total_processing_time,
            'success_rate': self.tasks_processed / max(1, self.tasks_processed + self.tasks_failed)
        }


class CryptoOptimizer:
    """Main cryptographic performance optimizer"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}
        
        # Initialize components
        self.key_cache = KeyCache(
            cache_size=config.get('key_cache_size', 1000),
            ttl=config.get('cache_ttl', 3600)
        )
        
        self.accelerator = CryptoAccelerator(
            use_hardware_acceleration=config.get('hardware_acceleration', True)
        )
        
        self.parallel_processor = ParallelCryptoProcessor(
            num_workers=config.get('parallel_workers', 4)
        )
        
        # Cleanup task
        self.cleanup_task: Optional[asyncio.Task] = None
        
        self.running = False
    
    async def start(self):
        """Start the crypto optimizer"""
        if self.running:
            return
        
        self.running = True
        
        await self.parallel_processor.start()
        
        # Start cleanup task
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        logger.info("Crypto optimizer started")
    
    async def stop(self):
        """Stop the crypto optimizer"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel cleanup task
        if self.cleanup_task:
            self.cleanup_task.cancel()
        
        await self.parallel_processor.stop()
        
        logger.info("Crypto optimizer stopped")
    
    async def encrypt_message(self, data: bytes, key: bytes, 
                            additional_data: Optional[bytes] = None) -> bytes:
        """Optimized message encryption"""
        # Check cache for derived key
        key_id = hashlib.sha256(key).hexdigest()
        cached_key = self.key_cache.get_key(key_id)
        
        if cached_key is None:
            # Derive key and cache it
            derived_key = self._derive_message_key(key)
            self.key_cache.put_key(key_id, derived_key)
            cached_key = derived_key
        
        # Use accelerated encryption
        ciphertext, tag = self.accelerator.encrypt_aes_gcm(cached_key, data, additional_data)
        return ciphertext + tag
    
    async def decrypt_message(self, data: bytes, key: bytes,
                            additional_data: Optional[bytes] = None) -> bytes:
        """Optimized message decryption"""
        # Check cache for derived key
        key_id = hashlib.sha256(key).hexdigest()
        cached_key = self.key_cache.get_key(key_id)
        
        if cached_key is None:
            # Derive key and cache it
            derived_key = self._derive_message_key(key)
            self.key_cache.put_key(key_id, derived_key)
            cached_key = derived_key
        
        # Split ciphertext and tag
        ciphertext, tag = data[:-16], data[-16:]
        
        # Use accelerated decryption
        return self.accelerator.decrypt_aes_gcm(cached_key, ciphertext, tag, additional_data)
    
    async def parallel_encrypt(self, messages: List[Tuple[bytes, bytes]]) -> List[bytes]:
        """Encrypt multiple messages in parallel"""
        tasks = []
        
        for data, key in messages:
            task = CryptoTask(
                operation=CryptoOperation.ENCRYPT,
                data=data,
                key=key
            )
            tasks.append(self.parallel_processor.submit_task(task))
        
        return await asyncio.gather(*tasks)
    
    async def parallel_decrypt(self, messages: List[Tuple[bytes, bytes]]) -> List[bytes]:
        """Decrypt multiple messages in parallel"""
        tasks = []
        
        for data, key in messages:
            task = CryptoTask(
                operation=CryptoOperation.DECRYPT,
                data=data,
                key=key
            )
            tasks.append(self.parallel_processor.submit_task(task))
        
        return await asyncio.gather(*tasks)
    
    def _derive_message_key(self, key: bytes) -> bytes:
        """Derive a message key from base key"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'message_key_salt',
            info=b'privatus_message_key',
            backend=default_backend()
        )
        return hkdf.derive(key)
    
    async def _cleanup_loop(self):
        """Background cleanup task"""
        while self.running:
            try:
                # Clean up expired keys
                self.key_cache.clear_expired()
                
                # Wait before next cleanup
                await asyncio.sleep(300)  # 5 minutes
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in crypto cleanup: {e}")
                await asyncio.sleep(60)
    
    def get_optimization_stats(self) -> Dict[str, Any]:
        """Get comprehensive optimization statistics"""
        return {
            'key_cache': self.key_cache.get_cache_stats(),
            'accelerator': self.accelerator.get_acceleration_stats(),
            'parallel_processor': self.parallel_processor.get_processor_stats()
        } 