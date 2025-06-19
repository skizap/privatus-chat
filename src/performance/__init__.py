"""
Performance Optimization Module

This module implements comprehensive performance optimization for Privatus-chat,
including network performance, cryptographic acceleration, memory management,
and scalability enhancements.

Phase 8: Performance & Scalability
"""

# Import main optimization classes
from .network_optimizer import (
    NetworkOptimizer,
    ConnectionPool,
    MessageBatcher,
    BandwidthManager,
    CongestionController
)
from .crypto_optimizer import (
    CryptoOptimizer,
    KeyCache,
    CryptoAccelerator,
    ParallelCryptoProcessor
)
from .memory_optimizer import (
    MemoryOptimizer,
    MemoryPool,
    SecureMemoryManager,
    GarbageCollectionOptimizer
)
from .scalability_optimizer import (
    ScalabilityOptimizer,
    LoadBalancer,
    CachingLayer,
    DatabaseOptimizer
)
from .performance_monitor import (
    PerformanceMonitor,
    MetricsCollector,
    PerformanceProfiler,
    BenchmarkSuite
)

# Version information
__version__ = "1.0.0"

# Public API
__all__ = [
    # Network optimization
    'NetworkOptimizer',
    'ConnectionPool',
    'MessageBatcher',
    'BandwidthManager',
    'CongestionController',
    
    # Cryptographic optimization
    'CryptoOptimizer',
    'KeyCache',
    'CryptoAccelerator',
    'ParallelCryptoProcessor',
    
    # Memory optimization
    'MemoryOptimizer',
    'MemoryPool',
    'SecureMemoryManager',
    'GarbageCollectionOptimizer',
    
    # Scalability optimization
    'ScalabilityOptimizer',
    'LoadBalancer',
    'CachingLayer',
    'DatabaseOptimizer',
    
    # Performance monitoring
    'PerformanceMonitor',
    'MetricsCollector',
    'PerformanceProfiler',
    'BenchmarkSuite',
]

# Performance configuration
PERFORMANCE_CONFIG = {
    'network': {
        'max_connections': 1000,
        'connection_timeout': 30.0,
        'batch_size': 100,
        'batch_timeout': 0.1,
        'bandwidth_limit': 10 * 1024 * 1024,  # 10MB/s
        'congestion_threshold': 0.8
    },
    'crypto': {
        'key_cache_size': 1000,
        'cache_ttl': 3600,  # 1 hour
        'parallel_workers': 4,
        'hardware_acceleration': True
    },
    'memory': {
        'pool_size': 100 * 1024 * 1024,  # 100MB
        'gc_threshold': 0.8,
        'secure_delete': True,
        'memory_limit': 512 * 1024 * 1024  # 512MB
    },
    'scalability': {
        'max_peers': 10000,
        'cache_size': 50 * 1024 * 1024,  # 50MB
        'db_pool_size': 20,
        'load_balance_strategy': 'round_robin'
    }
}

def initialize_performance_system():
    """Initialize the performance optimization system"""
    from .performance_monitor import PerformanceMonitor
    
    monitor = PerformanceMonitor()
    monitor.start()
    
    return {
        'network_optimizer': NetworkOptimizer(),
        'crypto_optimizer': CryptoOptimizer(),
        'memory_optimizer': MemoryOptimizer(),
        'scalability_optimizer': ScalabilityOptimizer(),
        'performance_monitor': monitor
    } 