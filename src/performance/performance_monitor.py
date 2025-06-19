"""
Performance Monitoring System

Implements comprehensive performance monitoring for Privatus-chat including:
- Real-time metrics collection
- Performance profiling
- Benchmark suite
- System resource monitoring
"""

import asyncio
import time
import logging
import psutil
import threading
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import statistics
import json
import csv
from pathlib import Path

logger = logging.getLogger(__name__)


class MetricType(Enum):
    """Types of performance metrics"""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class Metric:
    """Represents a performance metric"""
    name: str
    metric_type: MetricType
    value: float
    timestamp: float
    tags: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary"""
        return {
            'name': self.name,
            'type': self.metric_type.value,
            'value': self.value,
            'timestamp': self.timestamp,
            'tags': self.tags
        }


class MetricsCollector:
    """Collects and aggregates performance metrics"""
    
    def __init__(self, max_metrics: int = 100000):
        self.max_metrics = max_metrics
        
        # Metric storage
        self.metrics: deque = deque(maxlen=max_metrics)
        self.metric_aggregates: Dict[str, Dict[str, Any]] = defaultdict(dict)
        
        # Real-time metrics
        self.counters: Dict[str, int] = defaultdict(int)
        self.gauges: Dict[str, float] = defaultdict(float)
        self.histograms: Dict[str, List[float]] = defaultdict(list)
        self.timers: Dict[str, List[float]] = defaultdict(list)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics
        self.total_metrics_collected = 0
        
    def increment_counter(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None):
        """Increment a counter metric"""
        with self._lock:
            self.counters[name] += value
            self._record_metric(name, MetricType.COUNTER, self.counters[name], tags)
    
    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Set a gauge metric"""
        with self._lock:
            self.gauges[name] = value
            self._record_metric(name, MetricType.GAUGE, value, tags)
    
    def record_histogram(self, name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Record a histogram value"""
        with self._lock:
            self.histograms[name].append(value)
            
            # Keep only recent values for memory efficiency
            if len(self.histograms[name]) > 1000:
                self.histograms[name] = self.histograms[name][-1000:]
            
            self._record_metric(name, MetricType.HISTOGRAM, value, tags)
    
    def record_timer(self, name: str, duration: float, tags: Optional[Dict[str, str]] = None):
        """Record a timer duration"""
        with self._lock:
            self.timers[name].append(duration)
            
            # Keep only recent values
            if len(self.timers[name]) > 1000:
                self.timers[name] = self.timers[name][-1000:]
            
            self._record_metric(name, MetricType.TIMER, duration, tags)
    
    def _record_metric(self, name: str, metric_type: MetricType, value: float, 
                      tags: Optional[Dict[str, str]]):
        """Record a metric"""
        metric = Metric(
            name=name,
            metric_type=metric_type,
            value=value,
            timestamp=time.time(),
            tags=tags or {}
        )
        
        self.metrics.append(metric)
        self.total_metrics_collected += 1
        
        # Update aggregates
        self._update_aggregates(metric)
    
    def _update_aggregates(self, metric: Metric):
        """Update metric aggregates"""
        name = metric.name
        
        if name not in self.metric_aggregates:
            self.metric_aggregates[name] = {
                'count': 0,
                'sum': 0.0,
                'min': float('inf'),
                'max': float('-inf'),
                'last_value': 0.0,
                'last_timestamp': 0.0
            }
        
        agg = self.metric_aggregates[name]
        agg['count'] += 1
        agg['sum'] += metric.value
        agg['min'] = min(agg['min'], metric.value)
        agg['max'] = max(agg['max'], metric.value)
        agg['last_value'] = metric.value
        agg['last_timestamp'] = metric.timestamp
    
    def get_histogram_stats(self, name: str) -> Dict[str, float]:
        """Get histogram statistics"""
        with self._lock:
            values = self.histograms.get(name, [])
            if not values:
                return {}
            
            return {
                'count': len(values),
                'min': min(values),
                'max': max(values),
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'p95': self._percentile(values, 0.95),
                'p99': self._percentile(values, 0.99),
                'stddev': statistics.stdev(values) if len(values) > 1 else 0.0
            }
    
    def get_timer_stats(self, name: str) -> Dict[str, float]:
        """Get timer statistics"""
        with self._lock:
            values = self.timers.get(name, [])
            if not values:
                return {}
            
            return {
                'count': len(values),
                'min': min(values),
                'max': max(values),
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'p95': self._percentile(values, 0.95),
                'p99': self._percentile(values, 0.99),
                'total': sum(values)
            }
    
    def _percentile(self, values: List[float], percentile: float) -> float:
        """Calculate percentile"""
        if not values:
            return 0.0
        
        sorted_values = sorted(values)
        index = int(len(sorted_values) * percentile)
        return sorted_values[min(index, len(sorted_values) - 1)]
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of all metrics"""
        with self._lock:
            return {
                'total_metrics': len(self.metrics),
                'total_collected': self.total_metrics_collected,
                'counters': dict(self.counters),
                'gauges': dict(self.gauges),
                'histogram_count': len(self.histograms),
                'timer_count': len(self.timers),
                'aggregates': dict(self.metric_aggregates)
            }


class TimerContext:
    """Context manager for timing operations"""
    
    def __init__(self, collector: MetricsCollector, name: str, tags: Optional[Dict[str, str]] = None):
        self.collector = collector
        self.name = name
        self.tags = tags
        self.start_time = 0.0
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration = time.time() - self.start_time
        self.collector.record_timer(self.name, duration, self.tags)


class PerformanceProfiler:
    """Performance profiler for detailed analysis"""
    
    def __init__(self, enable_profiling: bool = True):
        self.enable_profiling = enable_profiling
        
        # Profiling data
        self.function_calls: Dict[str, List[float]] = defaultdict(list)
        self.call_stack: List[Tuple[str, float]] = []
        
        # Resource usage tracking
        self.cpu_usage: deque = deque(maxlen=300)  # 5 minutes at 1-second intervals
        self.memory_usage: deque = deque(maxlen=300)
        self.disk_io: deque = deque(maxlen=300)
        self.network_io: deque = deque(maxlen=300)
        
        # Profiling state
        self.profiling_active = False
        
        # Thread safety
        self._lock = threading.RLock()
    
    def start_profiling(self):
        """Start performance profiling"""
        if not self.enable_profiling:
            return
        
        with self._lock:
            self.profiling_active = True
            logger.info("Performance profiling started")
    
    def stop_profiling(self):
        """Stop performance profiling"""
        with self._lock:
            self.profiling_active = False
            logger.info("Performance profiling stopped")
    
    def profile_function(self, func_name: str):
        """Decorator for profiling functions"""
        def decorator(func: Callable):
            def wrapper(*args, **kwargs):
                if not self.profiling_active:
                    return func(*args, **kwargs)
                
                start_time = time.time()
                
                with self._lock:
                    self.call_stack.append((func_name, start_time))
                
                try:
                    result = func(*args, **kwargs)
                    return result
                finally:
                    end_time = time.time()
                    duration = end_time - start_time
                    
                    with self._lock:
                        self.function_calls[func_name].append(duration)
                        if self.call_stack and self.call_stack[-1][0] == func_name:
                            self.call_stack.pop()
            
            return wrapper
        return decorator
    
    def record_resource_usage(self):
        """Record current resource usage"""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=None)
            self.cpu_usage.append(cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage.append(memory.percent)
            
            # Disk I/O
            disk_io = psutil.disk_io_counters()
            if disk_io:
                self.disk_io.append((disk_io.read_bytes, disk_io.write_bytes))
            
            # Network I/O
            network_io = psutil.net_io_counters()
            if network_io:
                self.network_io.append((network_io.bytes_sent, network_io.bytes_recv))
                
        except Exception as e:
            logger.warning(f"Failed to record resource usage: {e}")
    
    def get_function_profile(self, func_name: str) -> Dict[str, Any]:
        """Get profiling data for a function"""
        with self._lock:
            calls = self.function_calls.get(func_name, [])
            if not calls:
                return {}
            
            return {
                'call_count': len(calls),
                'total_time': sum(calls),
                'avg_time': statistics.mean(calls),
                'min_time': min(calls),
                'max_time': max(calls),
                'median_time': statistics.median(calls)
            }
    
    def get_resource_stats(self) -> Dict[str, Any]:
        """Get resource usage statistics"""
        with self._lock:
            stats = {}
            
            if self.cpu_usage:
                stats['cpu'] = {
                    'current': self.cpu_usage[-1] if self.cpu_usage else 0,
                    'avg': statistics.mean(self.cpu_usage),
                    'max': max(self.cpu_usage)
                }
            
            if self.memory_usage:
                stats['memory'] = {
                    'current': self.memory_usage[-1] if self.memory_usage else 0,
                    'avg': statistics.mean(self.memory_usage),
                    'max': max(self.memory_usage)
                }
            
            return stats
    
    def get_profiling_summary(self) -> Dict[str, Any]:
        """Get profiling summary"""
        with self._lock:
            return {
                'profiling_active': self.profiling_active,
                'functions_tracked': len(self.function_calls),
                'total_function_calls': sum(len(calls) for calls in self.function_calls.values()),
                'call_stack_depth': len(self.call_stack),
                'resource_samples': {
                    'cpu': len(self.cpu_usage),
                    'memory': len(self.memory_usage),
                    'disk_io': len(self.disk_io),
                    'network_io': len(self.network_io)
                }
            }


class BenchmarkSuite:
    """Comprehensive benchmark suite"""
    
    def __init__(self):
        self.benchmark_results: Dict[str, Dict[str, Any]] = {}
        
    async def run_crypto_benchmarks(self) -> Dict[str, Any]:
        """Run cryptographic operation benchmarks"""
        results = {}
        
        # Test AES encryption performance
        import secrets
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        
        test_data = secrets.token_bytes(1024)  # 1KB
        key = secrets.token_bytes(32)  # 256-bit key
        
        # Benchmark AES-GCM encryption
        start_time = time.time()
        for _ in range(1000):
            cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(test_data) + encryptor.finalize()
        
        aes_time = time.time() - start_time
        results['aes_gcm_encryption'] = {
            'operations': 1000,
            'total_time': aes_time,
            'ops_per_second': 1000 / aes_time,
            'bytes_per_second': (1000 * 1024) / aes_time
        }
        
        # Benchmark hashing
        import hashlib
        
        start_time = time.time()
        for _ in range(1000):
            hashlib.sha256(test_data).digest()
        
        hash_time = time.time() - start_time
        results['sha256_hashing'] = {
            'operations': 1000,
            'total_time': hash_time,
            'ops_per_second': 1000 / hash_time,
            'bytes_per_second': (1000 * 1024) / hash_time
        }
        
        return results
    
    async def run_network_benchmarks(self) -> Dict[str, Any]:
        """Run network operation benchmarks"""
        results = {}
        
        # Test message serialization
        from src.network.message_protocol import MessageSerializer
        
        serializer = MessageSerializer()
        
        # Create test message
        message = serializer.create_chat_message(
            sender_id=b"test_sender",
            recipient_id=b"test_recipient",
            content="Benchmark test message"
        )
        
        # Benchmark serialization
        start_time = time.time()
        for _ in range(1000):
            serialized = serializer.serialize(message)
            deserialized = serializer.deserialize(serialized)
        
        serialize_time = time.time() - start_time
        results['message_serialization'] = {
            'operations': 1000,
            'total_time': serialize_time,
            'ops_per_second': 1000 / max(serialize_time, 0.000001)  # Avoid division by zero
        }
        
        return results
    
    async def run_memory_benchmarks(self) -> Dict[str, Any]:
        """Run memory operation benchmarks"""
        results = {}
        
        # Test memory allocation performance
        start_time = time.time()
        memory_blocks = []
        
        for _ in range(1000):
            block = bytearray(4096)  # 4KB blocks
            memory_blocks.append(block)
        
        alloc_time = time.time() - start_time
        
        # Test memory access
        start_time = time.time()
        for block in memory_blocks:
            # Simple memory access pattern
            block[0] = 255
            value = block[0]
        
        access_time = time.time() - start_time
        
        results['memory_allocation'] = {
            'operations': 1000,
            'total_time': alloc_time,
            'ops_per_second': 1000 / alloc_time,
            'bytes_allocated': 1000 * 4096
        }
        
        results['memory_access'] = {
            'operations': 1000,
            'total_time': access_time,
            'ops_per_second': 1000 / access_time
        }
        
        return results
    
    async def run_full_benchmark_suite(self) -> Dict[str, Any]:
        """Run complete benchmark suite"""
        logger.info("Starting comprehensive benchmark suite...")
        
        results = {
            'timestamp': time.time(),
            'system_info': self._get_system_info()
        }
        
        try:
            results['crypto'] = await self.run_crypto_benchmarks()
            results['network'] = await self.run_network_benchmarks()
            results['memory'] = await self.run_memory_benchmarks()
            
            logger.info("Benchmark suite completed successfully")
            
        except Exception as e:
            logger.error(f"Benchmark suite failed: {e}")
            results['error'] = str(e)
        
        self.benchmark_results['full_suite'] = results
        return results
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for benchmarks"""
        try:
            return {
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'platform': 'unknown',
                'python_version': psutil.python_version()
            }
        except Exception as e:
            logger.warning(f"Failed to get system info: {e}")
            return {}


class PerformanceMonitor:
    """Main performance monitoring system"""
    
    def __init__(self, monitoring_interval: float = 1.0):
        self.monitoring_interval = monitoring_interval
        
        # Initialize components
        self.metrics_collector = MetricsCollector()
        self.profiler = PerformanceProfiler()
        self.benchmark_suite = BenchmarkSuite()
        
        # Monitoring tasks
        self.monitor_task: Optional[asyncio.Task] = None
        
        self.running = False
    
    async def start(self):
        """Start performance monitoring"""
        if self.running:
            return
        
        self.running = True
        
        # Start profiler
        self.profiler.start_profiling()
        
        # Start monitoring task
        self.monitor_task = asyncio.create_task(self._monitoring_loop())
        
        logger.info("Performance monitoring started")
    
    async def stop(self):
        """Stop performance monitoring"""
        if not self.running:
            return
        
        self.running = False
        
        # Stop profiler
        self.profiler.stop_profiling()
        
        # Cancel monitoring task
        if self.monitor_task:
            self.monitor_task.cancel()
        
        logger.info("Performance monitoring stopped")
    
    async def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.running:
            try:
                # Record system metrics
                self._record_system_metrics()
                
                # Record resource usage
                self.profiler.record_resource_usage()
                
                # Wait for next interval
                await asyncio.sleep(self.monitoring_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {e}")
                await asyncio.sleep(5)
    
    def _record_system_metrics(self):
        """Record system performance metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=None)
            self.metrics_collector.set_gauge('system.cpu.usage', cpu_percent)
            
            # Memory metrics
            memory = psutil.virtual_memory()
            self.metrics_collector.set_gauge('system.memory.usage', memory.percent)
            self.metrics_collector.set_gauge('system.memory.available', memory.available)
            
            # Disk metrics
            disk_usage = psutil.disk_usage('/')
            self.metrics_collector.set_gauge('system.disk.usage', disk_usage.percent)
            
            # Network metrics
            network_io = psutil.net_io_counters()
            if network_io:
                self.metrics_collector.set_gauge('system.network.bytes_sent', network_io.bytes_sent)
                self.metrics_collector.set_gauge('system.network.bytes_recv', network_io.bytes_recv)
                
        except Exception as e:
            logger.warning(f"Failed to record system metrics: {e}")
    
    def timer(self, name: str, tags: Optional[Dict[str, str]] = None) -> TimerContext:
        """Create a timer context manager"""
        return TimerContext(self.metrics_collector, name, tags)
    
    def increment_counter(self, name: str, value: int = 1, tags: Optional[Dict[str, str]] = None):
        """Increment a counter metric"""
        self.metrics_collector.increment_counter(name, value, tags)
    
    def set_gauge(self, name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Set a gauge metric"""
        self.metrics_collector.set_gauge(name, value, tags)
    
    def record_histogram(self, name: str, value: float, tags: Optional[Dict[str, str]] = None):
        """Record a histogram value"""
        self.metrics_collector.record_histogram(name, value, tags)
    
    async def run_benchmarks(self) -> Dict[str, Any]:
        """Run performance benchmarks"""
        return await self.benchmark_suite.run_full_benchmark_suite()
    
    def export_metrics(self, filepath: str, format: str = 'json'):
        """Export metrics to file"""
        try:
            metrics_data = self.get_comprehensive_stats()
            
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)
            
            if format == 'json':
                with open(path, 'w') as f:
                    json.dump(metrics_data, f, indent=2, default=str)
            elif format == 'csv':
                # Export metrics as CSV
                with open(path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Metric', 'Value', 'Type'])
                    
                    for metric_name, metric_data in metrics_data.items():
                        if isinstance(metric_data, dict):
                            for key, value in metric_data.items():
                                writer.writerow([f"{metric_name}.{key}", value, type(value).__name__])
                        else:
                            writer.writerow([metric_name, metric_data, type(metric_data).__name__])
            
            logger.info(f"Metrics exported to {filepath}")
            
        except Exception as e:
            logger.error(f"Failed to export metrics: {e}")
    
    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        return {
            'metrics': self.metrics_collector.get_metrics_summary(),
            'profiler': self.profiler.get_profiling_summary(),
            'resource_stats': self.profiler.get_resource_stats(),
            'benchmarks': self.benchmark_suite.benchmark_results,
            'timestamp': time.time()
        } 