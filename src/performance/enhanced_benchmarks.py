"""
Enhanced Performance Benchmarks

Comprehensive benchmarking suite for key operations including:
- Message encryption/decryption performance
- Key generation and management
- Network operation benchmarks
- P2P communication benchmarks
- File transfer performance
- GUI responsiveness benchmarks
"""

import asyncio
import time
import logging
import secrets
import hashlib
import threading
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
import statistics
import json
import psutil
import os
from pathlib import Path

# Import existing performance components
from src.performance.performance_monitor import PerformanceMonitor, TimerContext
from src.performance.crypto_optimizer import CryptoOptimizer
from src.performance.memory_optimizer import MemoryOptimizer, MemoryType
from src.performance.network_optimizer import NetworkOptimizer

logger = logging.getLogger(__name__)


class BenchmarkType(Enum):
    """Types of benchmarks"""
    CRYPTO_ENCRYPTION = "crypto_encryption"
    CRYPTO_DECRYPTION = "crypto_decryption"
    KEY_GENERATION = "key_generation"
    KEY_DERIVATION = "key_derivation"
    NETWORK_LATENCY = "network_latency"
    NETWORK_THROUGHPUT = "network_throughput"
    MESSAGE_SERIALIZATION = "message_serialization"
    FILE_TRANSFER = "file_transfer"
    MEMORY_ALLOCATION = "memory_allocation"
    GUI_RESPONSIVENESS = "gui_responsiveness"
    DATABASE_OPERATIONS = "database_operations"


@dataclass
class BenchmarkResult:
    """Results from a benchmark run"""
    benchmark_type: BenchmarkType
    operation_count: int
    total_time: float
    avg_time: float
    min_time: float
    max_time: float
    p50_time: float
    p95_time: float
    p99_time: float
    throughput: float  # operations per second
    memory_usage: float  # MB
    cpu_usage: float  # percentage
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            'benchmark_type': self.benchmark_type.value,
            'operation_count': self.operation_count,
            'total_time': self.total_time,
            'avg_time': self.avg_time,
            'min_time': self.min_time,
            'max_time': self.max_time,
            'p50_time': self.p50_time,
            'p95_time': self.p95_time,
            'p99_time': self.p99_time,
            'throughput': self.throughput,
            'memory_usage': self.memory_usage,
            'cpu_usage': self.cpu_usage,
            'timestamp': self.timestamp,
            'metadata': self.metadata
        }


class EnhancedBenchmarkSuite:
    """Enhanced comprehensive benchmark suite"""

    def __init__(self, performance_monitor: PerformanceMonitor):
        self.performance_monitor = performance_monitor
        self.benchmark_results: List[BenchmarkResult] = []

        # System resource monitoring
        self.process = psutil.Process()
        self.baseline_memory = 0
        self.baseline_cpu = 0

        # Thread safety
        self._lock = threading.RLock()

    async def run_comprehensive_benchmarks(self) -> Dict[str, Any]:
        """Run all benchmark suites"""
        logger.info("Starting comprehensive benchmark suite...")

        results = {
            'timestamp': time.time(),
            'system_info': self._get_system_info(),
            'benchmarks': {}
        }

        try:
            # Run crypto benchmarks
            results['benchmarks']['crypto'] = await self.run_crypto_benchmarks()

            # Run key generation benchmarks
            results['benchmarks']['key_generation'] = await self.run_key_generation_benchmarks()

            # Run network benchmarks
            results['benchmarks']['network'] = await self.run_network_benchmarks()

            # Run memory benchmarks
            results['benchmarks']['memory'] = await self.run_memory_benchmarks()

            # Run file transfer benchmarks
            results['benchmarks']['file_transfer'] = await self.run_file_transfer_benchmarks()

            logger.info("Comprehensive benchmark suite completed successfully")

        except Exception as e:
            logger.error(f"Benchmark suite failed: {e}")
            results['error'] = str(e)

        return results

    async def run_crypto_benchmarks(self) -> Dict[str, BenchmarkResult]:
        """Run comprehensive cryptographic benchmarks"""
        logger.info("Running cryptographic benchmarks...")

        results = {}

        # Test data sizes for benchmarking
        test_sizes = [64, 256, 1024, 4096, 16384, 65536]  # 64B to 64KB

        for size in test_sizes:
            # Generate test data
            test_data = secrets.token_bytes(size)
            test_key = secrets.token_bytes(32)

            # Encryption benchmark
            result = await self._run_crypto_benchmark(
                BenchmarkType.CRYPTO_ENCRYPTION,
                lambda: self._encrypt_data(test_data, test_key),
                operation_count=1000,
                metadata={'data_size': size}
            )
            results[f'encryption_{size}b'] = result

            # Decryption benchmark
            encrypted_data = self._encrypt_data(test_data, test_key)
            result = await self._run_crypto_benchmark(
                BenchmarkType.CRYPTO_DECRYPTION,
                lambda: self._decrypt_data(encrypted_data, test_key),
                operation_count=1000,
                metadata={'data_size': size}
            )
            results[f'decryption_{size}b'] = result

        return results

    async def run_key_generation_benchmarks(self) -> Dict[str, BenchmarkResult]:
        """Run key generation and derivation benchmarks"""
        logger.info("Running key generation benchmarks...")

        results = {}

        # Key generation benchmark
        result = await self._run_crypto_benchmark(
            BenchmarkType.KEY_GENERATION,
            self._generate_key_pair,
            operation_count=100,
            metadata={'key_type': 'ed25519'}
        )
        results['key_generation'] = result

        # Key derivation benchmark
        result = await self._run_crypto_benchmark(
            BenchmarkType.KEY_DERIVATION,
            lambda: self._derive_key(secrets.token_bytes(32), secrets.token_bytes(16)),
            operation_count=1000,
            metadata={'algorithm': 'hkdf'}
        )
        results['key_derivation'] = result

        return results

    async def run_network_benchmarks(self) -> Dict[str, BenchmarkResult]:
        """Run network operation benchmarks"""
        logger.info("Running network benchmarks...")

        results = {}

        # Message serialization benchmark
        from src.network.message_protocol import MessageSerializer

        serializer = MessageSerializer()
        message = serializer.create_chat_message(
            sender_id=secrets.token_bytes(32),
            recipient_id=secrets.token_bytes(32),
            content="Benchmark test message with sufficient length for meaningful measurement"
        )

        result = await self._run_crypto_benchmark(
            BenchmarkType.MESSAGE_SERIALIZATION,
            lambda: self._serialize_message(serializer, message),
            operation_count=10000,
            metadata={'message_size': len(serializer.serialize(message))}
        )
        results['message_serialization'] = result

        # Network latency simulation (would need actual network for real benchmarks)
        result = await self._run_crypto_benchmark(
            BenchmarkType.NETWORK_LATENCY,
            lambda: self._simulate_network_latency(),
            operation_count=1000,
            metadata={'simulated': True}
        )
        results['network_latency'] = result

        return results

    async def run_memory_benchmarks(self) -> Dict[str, BenchmarkResult]:
        """Run memory operation benchmarks"""
        logger.info("Running memory benchmarks...")

        results = {}

        # Memory allocation benchmark
        result = await self._run_crypto_benchmark(
            BenchmarkType.MEMORY_ALLOCATION,
            lambda: self._allocate_memory_blocks(1000, 4096),
            operation_count=10,
            metadata={'block_size': 4096, 'block_count': 1000}
        )
        results['memory_allocation'] = result

        # Large message handling benchmark
        large_message = secrets.token_bytes(1024 * 1024)  # 1MB

        result = await self._run_crypto_benchmark(
            BenchmarkType.MEMORY_ALLOCATION,
            lambda: self._process_large_message(large_message),
            operation_count=100,
            metadata={'message_size': len(large_message)}
        )
        results['large_message_handling'] = result

        return results

    async def run_file_transfer_benchmarks(self) -> Dict[str, BenchmarkResult]:
        """Run file transfer benchmarks"""
        logger.info("Running file transfer benchmarks...")

        results = {}

        # Create test file
        test_file_size = 10 * 1024 * 1024  # 10MB
        test_data = secrets.token_bytes(test_file_size)

        # File write benchmark
        result = await self._run_crypto_benchmark(
            BenchmarkType.FILE_TRANSFER,
            lambda: self._write_test_file(test_data),
            operation_count=5,
            metadata={'file_size': test_file_size, 'operation': 'write'}
        )
        results['file_write'] = result

        # File read benchmark
        test_file_path = "/tmp/privatus_benchmark_test"
        with open(test_file_path, 'wb') as f:
            f.write(test_data)

        result = await self._run_crypto_benchmark(
            BenchmarkType.FILE_TRANSFER,
            lambda: self._read_test_file(test_file_path),
            operation_count=5,
            metadata={'file_size': test_file_size, 'operation': 'read'}
        )
        results['file_read'] = result

        # Cleanup
        try:
            os.unlink(test_file_path)
        except:
            pass

        return results

    async def _run_crypto_benchmark(self, benchmark_type: BenchmarkType,
                                   operation_func: Callable,
                                   operation_count: int,
                                   metadata: Optional[Dict[str, Any]] = None) -> BenchmarkResult:
        """Run a cryptographic benchmark with detailed metrics"""

        # Record baseline system state
        self._record_baseline_metrics()

        # Warm up
        for _ in range(min(10, operation_count // 10)):
            operation_func()

        # Actual benchmark
        times = []
        start_time = time.time()

        for _ in range(operation_count):
            op_start = time.time()
            operation_func()
            op_end = time.time()
            times.append(op_end - op_start)

        total_time = time.time() - start_time

        # Calculate statistics
        times_array = sorted(times)
        result = BenchmarkResult(
            benchmark_type=benchmark_type,
            operation_count=operation_count,
            total_time=total_time,
            avg_time=statistics.mean(times),
            min_time=min(times),
            max_time=max(times),
            p50_time=times_array[int(len(times_array) * 0.5)],
            p95_time=times_array[int(len(times_array) * 0.95)],
            p99_time=times_array[int(len(times_array) * 0.99)],
            throughput=operation_count / total_time,
            memory_usage=self._get_memory_usage(),
            cpu_usage=self._get_cpu_usage(),
            metadata=metadata or {}
        )

        # Store result
        with self._lock:
            self.benchmark_results.append(result)

        return result

    def _record_baseline_metrics(self):
        """Record baseline system metrics"""
        try:
            self.baseline_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            self.baseline_cpu = self.process.cpu_percent()
        except Exception as e:
            logger.warning(f"Failed to record baseline metrics: {e}")

    def _get_memory_usage(self) -> float:
        """Get current memory usage in MB"""
        try:
            current_memory = self.process.memory_info().rss / 1024 / 1024  # MB
            return current_memory - self.baseline_memory
        except:
            return 0.0

    def _get_cpu_usage(self) -> float:
        """Get current CPU usage percentage"""
        try:
            return self.process.cpu_percent()
        except:
            return 0.0

    def _encrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data for benchmarking"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return ciphertext + encryptor.tag

    def _decrypt_data(self, data: bytes, key: bytes) -> bytes:
        """Decrypt data for benchmarking"""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        ciphertext, tag = data[:-16], data[-16:]
        cipher = Cipher(algorithms.AES(key), modes.GCM(b'\x00' * 12, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def _generate_key_pair(self) -> Tuple[bytes, bytes]:
        """Generate key pair for benchmarking"""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key.private_bytes_raw(), public_key.public_bytes_raw()

    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive key for benchmarking"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.backends import default_backend

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'benchmark_key_derivation',
            backend=default_backend()
        )
        return hkdf.derive(password)

    def _serialize_message(self, serializer, message) -> bytes:
        """Serialize message for benchmarking"""
        return serializer.serialize(message)

    def _simulate_network_latency(self) -> float:
        """Simulate network latency"""
        time.sleep(0.001)  # 1ms simulated latency
        return 0.001

    def _allocate_memory_blocks(self, count: int, size: int) -> List[bytes]:
        """Allocate memory blocks for benchmarking"""
        blocks = []
        for _ in range(count):
            blocks.append(secrets.token_bytes(size))
        return blocks

    def _process_large_message(self, message: bytes) -> bytes:
        """Process large message for benchmarking"""
        # Simulate message processing
        return hashlib.sha256(message).digest()

    def _write_test_file(self, data: bytes) -> str:
        """Write test file"""
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(data)
            return f.name

    def _read_test_file(self, filepath: str) -> bytes:
        """Read test file"""
        with open(filepath, 'rb') as f:
            return f.read()

    def _get_system_info(self) -> Dict[str, Any]:
        """Get system information for benchmarks"""
        try:
            return {
                'cpu_count': os.cpu_count(),
                'memory_total': psutil.virtual_memory().total / 1024 / 1024,  # MB
                'platform': os.uname().sysname if hasattr(os, 'uname') else 'unknown',
                'python_version': f"{os.sys.version_info.major}.{os.sys.version_info.minor}"
            }
        except Exception as e:
            logger.warning(f"Failed to get system info: {e}")
            return {}

    def export_results(self, filepath: str, format: str = 'json'):
        """Export benchmark results"""
        try:
            export_data = {
                'results': [result.to_dict() for result in self.benchmark_results],
                'summary': self._generate_summary()
            }

            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)

            if format == 'json':
                with open(path, 'w') as f:
                    json.dump(export_data, f, indent=2, default=str)
            elif format == 'csv':
                self._export_csv(path, export_data)

            logger.info(f"Benchmark results exported to {filepath}")

        except Exception as e:
            logger.error(f"Failed to export benchmark results: {e}")

    def _generate_summary(self) -> Dict[str, Any]:
        """Generate benchmark summary"""
        if not self.benchmark_results:
            return {}

        # Group results by type
        by_type = {}
        for result in self.benchmark_results:
            if result.benchmark_type.value not in by_type:
                by_type[result.benchmark_type.value] = []
            by_type[result.benchmark_type.value].append(result)

        summary = {}
        for benchmark_type, results in by_type.items():
            throughputs = [r.throughput for r in results]
            summary[benchmark_type] = {
                'count': len(results),
                'avg_throughput': statistics.mean(throughputs),
                'min_throughput': min(throughputs),
                'max_throughput': max(throughputs),
                'total_operations': sum(r.operation_count for r in results)
            }

        return summary

    def _export_csv(self, filepath: Path, data: Dict[str, Any]):
        """Export results as CSV"""
        import csv

        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)

            # Header
            writer.writerow(['Benchmark Type', 'Operations', 'Total Time (s)', 'Avg Time (s)',
                           'Throughput (ops/s)', 'Memory Usage (MB)', 'CPU Usage (%)', 'Timestamp'])

            # Data rows
            for result in data['results']:
                writer.writerow([
                    result['benchmark_type'],
                    result['operation_count'],
                    result['total_time'],
                    result['avg_time'],
                    result['throughput'],
                    result['memory_usage'],
                    result['cpu_usage'],
                    result['timestamp']
                ])


class PerformanceRegressionTester:
    """Automated performance regression testing"""

    def __init__(self, benchmark_suite: EnhancedBenchmarkSuite):
        self.benchmark_suite = benchmark_suite
        self.baseline_results: Dict[str, BenchmarkResult] = {}
        self.regression_thresholds: Dict[str, float] = {
            'throughput_degradation': 0.1,  # 10% degradation threshold
            'memory_increase': 0.2,        # 20% memory increase threshold
            'latency_increase': 0.15       # 15% latency increase threshold
        }

        # Test history
        self.test_history: List[Dict[str, Any]] = []

    async def establish_baseline(self) -> Dict[str, BenchmarkResult]:
        """Establish performance baseline"""
        logger.info("Establishing performance baseline...")

        results = await self.benchmark_suite.run_comprehensive_benchmarks()
        baseline = {}

        # Extract benchmark results
        for category, benchmarks in results.get('benchmarks', {}).items():
            if isinstance(benchmarks, dict):
                for benchmark_name, result in benchmarks.items():
                    if isinstance(result, BenchmarkResult):
                        baseline[f"{category}_{benchmark_name}"] = result

        self.baseline_results = baseline
        logger.info(f"Established baseline with {len(baseline)} benchmarks")

        return baseline

    async def run_regression_test(self) -> Dict[str, Any]:
        """Run performance regression test"""
        logger.info("Running performance regression test...")

        # Run current benchmarks
        current_results = await self.benchmark_suite.run_comprehensive_benchmarks()
        current_benchmarks = {}

        for category, benchmarks in current_results.get('benchmarks', {}).items():
            if isinstance(benchmarks, dict):
                for benchmark_name, result in benchmarks.items():
                    if isinstance(result, BenchmarkResult):
                        current_benchmarks[f"{category}_{benchmark_name}"] = result

        # Compare with baseline
        regression_report = {
            'timestamp': time.time(),
            'baseline_count': len(self.baseline_results),
            'current_count': len(current_benchmarks),
            'regressions': [],
            'improvements': [],
            'stable': []
        }

        # Compare each benchmark
        for benchmark_name in self.baseline_results:
            if benchmark_name not in current_benchmarks:
                continue

            baseline = self.baseline_results[benchmark_name]
            current = current_benchmarks[benchmark_name]

            comparison = self._compare_results(benchmark_name, baseline, current)
            regression_report[comparison['status']].append(comparison)

        # Store test history
        self.test_history.append(regression_report)

        logger.info(f"Regression test completed: {len(regression_report['regressions'])} regressions, "
                   f"{len(regression_report['improvements'])} improvements")

        return regression_report

    def _compare_results(self, name: str, baseline: BenchmarkResult,
                        current: BenchmarkResult) -> Dict[str, Any]:
        """Compare baseline and current results"""
        comparison = {
            'benchmark_name': name,
            'baseline_throughput': baseline.throughput,
            'current_throughput': current.throughput,
            'baseline_memory': baseline.memory_usage,
            'current_memory': current.memory_usage,
            'baseline_latency': baseline.avg_time,
            'current_latency': current.avg_time,
            'status': 'stable',
            'changes': {}
        }

        # Check throughput regression
        if current.throughput > 0 and baseline.throughput > 0:
            throughput_change = (current.throughput - baseline.throughput) / baseline.throughput
            comparison['changes']['throughput'] = throughput_change

            if throughput_change < -self.regression_thresholds['throughput_degradation']:
                comparison['status'] = 'regression'
            elif throughput_change > self.regression_thresholds['throughput_degradation']:
                comparison['status'] = 'improvement'

        # Check memory regression
        if baseline.memory_usage > 0:
            memory_change = (current.memory_usage - baseline.memory_usage) / baseline.memory_usage
            comparison['changes']['memory'] = memory_change

            if memory_change > self.regression_thresholds['memory_increase']:
                if comparison['status'] == 'regression':
                    comparison['status'] = 'regression'  # Keep as regression if already marked
                else:
                    comparison['status'] = 'regression'

        # Check latency regression
        if baseline.avg_time > 0:
            latency_change = (current.avg_time - baseline.avg_time) / baseline.avg_time
            comparison['changes']['latency'] = latency_change

            if latency_change > self.regression_thresholds['latency_increase']:
                if comparison['status'] == 'regression':
                    comparison['status'] = 'regression'
                else:
                    comparison['status'] = 'regression'

        return comparison

    def export_regression_report(self, filepath: str):
        """Export regression test report"""
        try:
            report_data = {
                'baseline_results': {k: v.to_dict() for k, v in self.baseline_results.items()},
                'test_history': self.test_history,
                'thresholds': self.regression_thresholds
            }

            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            logger.info(f"Regression report exported to {filepath}")

        except Exception as e:
            logger.error(f"Failed to export regression report: {e}")


class PerformanceDashboard:
    """Real-time performance monitoring dashboard"""

    def __init__(self, performance_monitor: PerformanceMonitor):
        self.performance_monitor = performance_monitor
        self.dashboard_data: Dict[str, Any] = {}
        self.update_interval = 5.0  # seconds

        # Dashboard state
        self.running = False
        self.update_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the performance dashboard"""
        if self.running:
            return

        self.running = True
        self.update_task = asyncio.create_task(self._dashboard_loop())

        logger.info("Performance dashboard started")

    async def stop(self):
        """Stop the performance dashboard"""
        if not self.running:
            return

        self.running = False

        if self.update_task:
            self.update_task.cancel()

        logger.info("Performance dashboard stopped")

    async def _dashboard_loop(self):
        """Main dashboard update loop"""
        while self.running:
            try:
                await self._update_dashboard_data()
                await asyncio.sleep(self.update_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Dashboard update error: {e}")
                await asyncio.sleep(10)

    async def _update_dashboard_data(self):
        """Update dashboard data"""
        try:
            # Get comprehensive stats
            stats = self.performance_monitor.get_comprehensive_stats()

            # Add dashboard-specific metrics
            self.dashboard_data = {
                'timestamp': time.time(),
                'system_overview': self._get_system_overview(),
                'performance_metrics': stats,
                'top_bottlenecks': self._identify_bottlenecks(stats),
                'recommendations': self._generate_recommendations(stats)
            }

        except Exception as e:
            logger.error(f"Failed to update dashboard data: {e}")

    def _get_system_overview(self) -> Dict[str, Any]:
        """Get system overview metrics"""
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')

            return {
                'cpu_usage': cpu_percent,
                'memory_usage': memory.percent,
                'memory_available': memory.available / 1024 / 1024,  # MB
                'disk_usage': disk.percent,
                'load_average': os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            }
        except Exception as e:
            logger.warning(f"Failed to get system overview: {e}")
            return {}

    def _identify_bottlenecks(self, stats: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify performance bottlenecks"""
        bottlenecks = []

        try:
            # Check CPU usage
            resource_stats = stats.get('resource_stats', {})
            if resource_stats.get('cpu', {}).get('current', 0) > 80:
                bottlenecks.append({
                    'type': 'cpu',
                    'severity': 'high',
                    'description': 'High CPU usage detected',
                    'current_value': resource_stats['cpu']['current'],
                    'threshold': 80
                })

            # Check memory usage
            if resource_stats.get('memory', {}).get('current', 0) > 85:
                bottlenecks.append({
                    'type': 'memory',
                    'severity': 'high',
                    'description': 'High memory usage detected',
                    'current_value': resource_stats['memory']['current'],
                    'threshold': 85
                })

            # Check for slow operations
            profiler_stats = stats.get('profiler', {})
            if profiler_stats.get('functions_tracked', 0) > 0:
                # This would analyze function profiling data for slow operations
                pass

        except Exception as e:
            logger.warning(f"Failed to identify bottlenecks: {e}")

        return bottlenecks

    def _generate_recommendations(self, stats: Dict[str, Any]) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []

        try:
            resource_stats = stats.get('resource_stats', {})

            # CPU recommendations
            cpu_usage = resource_stats.get('cpu', {}).get('current', 0)
            if cpu_usage > 90:
                recommendations.append("Consider optimizing CPU-intensive operations or scaling horizontally")
            elif cpu_usage > 70:
                recommendations.append("Monitor CPU usage - approaching high utilization")

            # Memory recommendations
            memory_usage = resource_stats.get('memory', {}).get('current', 0)
            if memory_usage > 90:
                recommendations.append("High memory usage - consider memory optimization or scaling")
            elif memory_usage > 80:
                recommendations.append("Memory usage is high - monitor for potential issues")

            # Network recommendations
            network_stats = stats.get('metrics', {}).get('gauges', {})
            if 'system.network.bytes_sent' in network_stats:
                # Add network-specific recommendations based on data

                pass

        except Exception as e:
            logger.warning(f"Failed to generate recommendations: {e}")

        return recommendations

    def get_dashboard_data(self) -> Dict[str, Any]:
        """Get current dashboard data"""
        return self.dashboard_data.copy()

    def export_dashboard_report(self, filepath: str):
        """Export dashboard data to file"""
        try:
            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump(self.dashboard_data, f, indent=2, default=str)

            logger.info(f"Dashboard data exported to {filepath}")

        except Exception as e:
            logger.error(f"Failed to export dashboard data: {e}")


class EnhancedPerformanceMonitor:
    """Enhanced performance monitoring system with all optimizations"""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        if config is None:
            config = {}

        # Initialize core components
        self.performance_monitor = PerformanceMonitor(
            monitoring_interval=config.get('monitoring_interval', 1.0)
        )

        self.crypto_optimizer = CryptoOptimizer(
            config.get('crypto_config', {})
        )

        self.memory_optimizer = MemoryOptimizer(
            config.get('memory_config', {})
        )

        self.network_optimizer = NetworkOptimizer(
            config.get('network_config', {})
        )

        # Initialize enhanced components
        self.benchmark_suite = EnhancedBenchmarkSuite(self.performance_monitor)
        self.regression_tester = PerformanceRegressionTester(self.benchmark_suite)
        self.dashboard = PerformanceDashboard(self.performance_monitor)

        # Configuration
        self.auto_optimization = config.get('auto_optimization', True)
        self.benchmark_interval = config.get('benchmark_interval', 3600)  # 1 hour

        # State
        self.running = False
        self.benchmark_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the enhanced performance monitoring system"""
        if self.running:
            return

        self.running = True

        # Start core components
        await self.performance_monitor.start()
        await self.crypto_optimizer.start()
        await self.memory_optimizer.start()
        await self.network_optimizer.start()
        await self.dashboard.start()

        # Start periodic benchmarking
        if self.auto_optimization:
            self.benchmark_task = asyncio.create_task(self._benchmark_loop())

        logger.info("Enhanced performance monitoring system started")

    async def stop(self):
        """Stop the enhanced performance monitoring system"""
        if not self.running:
            return

        self.running = False

        # Stop periodic benchmarking
        if self.benchmark_task:
            self.benchmark_task.cancel()

        # Stop all components
        await self.dashboard.stop()
        await self.network_optimizer.stop()
        await self.memory_optimizer.stop()
        await self.crypto_optimizer.stop()
        await self.performance_monitor.stop()

        logger.info("Enhanced performance monitoring system stopped")

    async def _benchmark_loop(self):
        """Periodic benchmarking loop"""
        while self.running:
            try:
                # Run benchmarks
                await self.benchmark_suite.run_comprehensive_benchmarks()

                # Run regression test
                await self.regression_tester.run_regression_test()

                # Wait for next interval
                await asyncio.sleep(self.benchmark_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Benchmark loop error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry

    async def run_benchmarks(self) -> Dict[str, Any]:
        """Run comprehensive benchmarks on demand"""
        return await self.benchmark_suite.run_comprehensive_benchmarks()

    async def run_regression_test(self) -> Dict[str, Any]:
        """Run regression test on demand"""
        return await self.regression_tester.run_regression_test()

    def get_comprehensive_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        return {
            'performance_monitor': self.performance_monitor.get_comprehensive_stats(),
            'crypto_optimizer': self.crypto_optimizer.get_optimization_stats(),
            'memory_optimizer': self.memory_optimizer.get_optimization_stats(),
            'network_optimizer': self.network_optimizer.get_optimization_stats(),
            'dashboard': self.dashboard.get_dashboard_data(),
            'benchmark_summary': self.benchmark_suite._generate_summary()
        }

    def export_all_reports(self, base_path: str):
        """Export all performance reports"""
        timestamp = int(time.time())

        # Export benchmark results
        self.benchmark_suite.export_results(f"{base_path}/benchmarks_{timestamp}.json")

        # Export regression report
        self.regression_tester.export_regression_report(f"{base_path}/regression_{timestamp}.json")

        # Export dashboard data
        self.dashboard.export_dashboard_report(f"{base_path}/dashboard_{timestamp}.json")

        # Export comprehensive stats
        try:
            stats = self.get_comprehensive_stats()
            with open(f"{base_path}/comprehensive_{timestamp}.json", 'w') as f:
                json.dump(stats, f, indent=2, default=str)
        except Exception as e:
            logger.error(f"Failed to export comprehensive stats: {e}")

        logger.info(f"All performance reports exported to {base_path}")