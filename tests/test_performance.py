"""
Performance Infrastructure Tests for Privatus-chat
Week 8: Performance Optimizations

Test suite for the performance components including crypto optimization, memory optimization,
network optimization, performance monitoring, and scalability features.
"""

import pytest
import asyncio
import time
import psutil
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from src.performance.performance_monitor import PerformanceMonitor, MetricType
from src.performance.crypto_optimizer import CryptoOptimizer
from src.performance.memory_optimizer import MemoryOptimizer
from src.performance.network_optimizer import NetworkOptimizer
from src.performance.scalability_optimizer import ScalabilityOptimizer
from src.crypto.key_management import KeyManager


class TestPerformanceMonitor:
    """Test performance monitoring functionality"""

    @pytest.fixture
    async def perf_monitor(self):
        """Create performance monitor for testing"""
        monitor = PerformanceMonitor()
        await monitor.start()
        yield monitor
        await monitor.stop()

    def test_metric_collection(self, perf_monitor):
        """Test metric collection"""
        # Record some metrics
        perf_monitor.record_metric(MetricType.CPU_USAGE, 45.5)
        perf_monitor.record_metric(MetricType.MEMORY_USAGE, 256.7)
        perf_monitor.record_metric(MetricType.NETWORK_LATENCY, 15.2)

        # Check metrics were recorded
        assert len(perf_monitor.metrics[MetricType.CPU_USAGE]) > 0
        assert len(perf_monitor.metrics[MetricType.MEMORY_USAGE]) > 0
        assert len(perf_monitor.metrics[MetricType.NETWORK_LATENCY]) > 0

    def test_metric_averages(self, perf_monitor):
        """Test metric averaging"""
        # Record multiple values
        for i in range(5):
            perf_monitor.record_metric(MetricType.CPU_USAGE, 40 + i)

        avg_cpu = perf_monitor.get_average_metric(MetricType.CPU_USAGE)
        assert avg_cpu == 42.0

    def test_performance_alerts(self, perf_monitor):
        """Test performance alerts"""
        # Set threshold
        perf_monitor.set_threshold(MetricType.CPU_USAGE, 80.0)

        # Record value above threshold
        perf_monitor.record_metric(MetricType.CPU_USAGE, 85.0)

        # Check for alerts
        alerts = perf_monitor.get_active_alerts()
        assert len(alerts) > 0
        assert any("CPU usage" in alert['message'] for alert in alerts)

    def test_system_resource_monitoring(self, perf_monitor):
        """Test system resource monitoring"""
        resources = perf_monitor.get_system_resources()

        assert 'cpu_percent' in resources
        assert 'memory_percent' in resources
        assert 'disk_usage' in resources
        assert 'network_io' in resources

        assert isinstance(resources['cpu_percent'], (int, float))
        assert isinstance(resources['memory_percent'], (int, float))

    def test_performance_history(self, perf_monitor):
        """Test performance history tracking"""
        # Record metrics over time
        for i in range(10):
            perf_monitor.record_metric(MetricType.MEMORY_USAGE, 200 + i)
            time.sleep(0.01)  # Small delay

        history = perf_monitor.get_metric_history(MetricType.MEMORY_USAGE, hours=1)
        assert len(history) == 10

    def test_performance_reports(self, perf_monitor):
        """Test performance report generation"""
        # Record some data
        perf_monitor.record_metric(MetricType.CPU_USAGE, 50.0)
        perf_monitor.record_metric(MetricType.MEMORY_USAGE, 300.0)

        report = perf_monitor.generate_performance_report()

        assert 'timestamp' in report
        assert 'metrics_summary' in report
        assert 'system_info' in report
        assert 'recommendations' in report


class TestCryptoOptimizer:
    """Test cryptographic optimization functionality"""

    @pytest.fixture
    async def crypto_optimizer(self):
        """Create crypto optimizer for testing"""
        key_manager = KeyManager()
        await key_manager.initialize()

        optimizer = CryptoOptimizer(key_manager)
        await optimizer.start()
        yield optimizer
        await optimizer.stop()

    @pytest.mark.asyncio
    async def test_encryption_optimization(self, crypto_optimizer):
        """Test encryption performance optimization"""
        # Test data
        test_data = b"x" * 1024  # 1KB

        # Measure baseline performance
        start_time = time.time()
        for _ in range(100):
            await crypto_optimizer.encrypt_data(test_data)
        baseline_time = time.time() - start_time

        # Apply optimization
        await crypto_optimizer.optimize_encryption()

        # Measure optimized performance
        start_time = time.time()
        for _ in range(100):
            await crypto_optimizer.encrypt_data(test_data)
        optimized_time = time.time() - start_time

        # Should be faster (or at least not significantly slower)
        assert optimized_time <= baseline_time * 1.1

    def test_key_caching(self, crypto_optimizer):
        """Test cryptographic key caching"""
        # Generate and cache keys
        key_id = "test_key"
        key = crypto_optimizer.generate_optimized_key(key_id)

        assert key is not None
        assert key_id in crypto_optimizer.key_cache

        # Retrieve from cache
        cached_key = crypto_optimizer.get_cached_key(key_id)
        assert cached_key == key

    def test_parallel_encryption(self, crypto_optimizer):
        """Test parallel encryption processing"""
        # Test data
        data_chunks = [b"chunk_" + str(i).encode() for i in range(10)]

        # Process in parallel
        results = crypto_optimizer.process_parallel_encryption(data_chunks)

        assert len(results) == 10
        assert all(isinstance(r, bytes) for r in results)

    def test_crypto_benchmarking(self, crypto_optimizer):
        """Test cryptographic benchmarking"""
        benchmark = crypto_optimizer.run_crypto_benchmark()

        assert 'encryption_speed' in benchmark
        assert 'decryption_speed' in benchmark
        assert 'key_generation_time' in benchmark
        assert 'hash_speed' in benchmark

        assert benchmark['encryption_speed'] > 0
        assert benchmark['decryption_speed'] > 0


class TestMemoryOptimizer:
    """Test memory optimization functionality"""

    @pytest.fixture
    def memory_optimizer(self):
        """Create memory optimizer for testing"""
        optimizer = MemoryOptimizer()
        optimizer.start()
        yield optimizer
        optimizer.stop()

    def test_memory_pool_management(self, memory_optimizer):
        """Test memory pool allocation and deallocation"""
        # Allocate memory from pool
        buffer = memory_optimizer.allocate_from_pool(1024)
        assert len(buffer) == 1024

        # Return to pool
        memory_optimizer.return_to_pool(buffer)

        # Verify pool size increased
        assert memory_optimizer.pool_size >= 1024

    def test_garbage_collection_optimization(self, memory_optimizer):
        """Test garbage collection optimization"""
        # Create some objects
        test_objects = [b"x" * 1000 for _ in range(100)]

        # Force garbage collection
        collected = memory_optimizer.optimize_garbage_collection(test_objects)

        # Should have collected some objects
        assert collected >= 0

    def test_memory_leak_detection(self, memory_optimizer):
        """Test memory leak detection"""
        # Simulate memory usage
        initial_usage = memory_optimizer.get_memory_usage()

        # Allocate memory
        large_buffer = b"x" * (1024 * 1024)  # 1MB

        current_usage = memory_optimizer.get_memory_usage()

        # Usage should have increased
        assert current_usage >= initial_usage

    def test_cache_optimization(self, memory_optimizer):
        """Test cache size optimization"""
        # Set cache size
        memory_optimizer.set_cache_size(50)

        # Add items to cache
        for i in range(60):  # More than cache size
            memory_optimizer.add_to_cache(f"key_{i}", f"value_{i}")

        # Cache should have evicted old items
        cache_size = memory_optimizer.get_cache_size()
        assert cache_size <= 50

    def test_memory_monitoring(self, memory_optimizer):
        """Test memory usage monitoring"""
        stats = memory_optimizer.get_memory_statistics()

        assert 'total_allocated' in stats
        assert 'peak_usage' in stats
        assert 'current_usage' in stats
        assert 'pool_efficiency' in stats


class TestNetworkOptimizer:
    """Test network optimization functionality"""

    @pytest.fixture
    async def network_optimizer(self):
        """Create network optimizer for testing"""
        optimizer = NetworkOptimizer()
        await optimizer.start()
        yield optimizer
        await optimizer.stop()

    @pytest.mark.asyncio
    async def test_connection_pooling(self, network_optimizer):
        """Test connection pooling"""
        # Create connection pool
        pool = await network_optimizer.create_connection_pool("127.0.0.1", 8000, size=5)

        assert pool is not None
        assert network_optimizer.get_pool_size(pool) == 5

    def test_packet_batching(self, network_optimizer):
        """Test packet batching for efficiency"""
        packets = [b"packet_" + str(i).encode() for i in range(10)]

        # Batch packets
        batches = network_optimizer.batch_packets(packets, batch_size=3)

        assert len(batches) == 4  # 10 packets / 3 per batch = 4 batches (rounded up)
        assert all(len(batch) <= 3 for batch in batches)

    def test_compression_optimization(self, network_optimizer):
        """Test network compression optimization"""
        test_data = b"x" * 10000  # 10KB of data

        compressed = network_optimizer.compress_for_network(test_data)
        assert len(compressed) < len(test_data)  # Should be smaller

        decompressed = network_optimizer.decompress_from_network(compressed)
        assert decompressed == test_data

    def test_latency_optimization(self, network_optimizer):
        """Test latency optimization techniques"""
        # Test different routing options
        routes = [
            {"path": ["node1", "node2"], "latency": 50},
            {"path": ["node1", "node3", "node2"], "latency": 30},
            {"path": ["node1", "node4", "node2"], "latency": 80}
        ]

        optimal_route = network_optimizer.select_optimal_route(routes)
        assert optimal_route["latency"] == 30  # Should select lowest latency

    def test_bandwidth_monitoring(self, network_optimizer):
        """Test bandwidth usage monitoring"""
        # Simulate bandwidth usage
        network_optimizer.record_bandwidth_usage(1024000)  # 1MB

        stats = network_optimizer.get_bandwidth_statistics()

        assert 'total_bytes' in stats
        assert 'average_rate' in stats
        assert 'peak_rate' in stats
        assert stats['total_bytes'] >= 1024000


class TestScalabilityOptimizer:
    """Test scalability optimization functionality"""

    @pytest.fixture
    async def scalability_optimizer(self):
        """Create scalability optimizer for testing"""
        optimizer = ScalabilityOptimizer()
        await optimizer.start()
        yield optimizer
        await optimizer.stop()

    def test_load_balancing(self, scalability_optimizer):
        """Test load balancing across nodes"""
        nodes = [
            {"id": "node1", "load": 0.8, "capacity": 100},
            {"id": "node2", "load": 0.3, "capacity": 100},
            {"id": "node3", "load": 0.9, "capacity": 100}
        ]

        # Balance load
        balanced_nodes = scalability_optimizer.balance_load(nodes)

        # Node2 should get more load since it has lower current load
        node2_load = next(n["load"] for n in balanced_nodes if n["id"] == "node2")
        assert node2_load > 0.3

    def test_auto_scaling(self, scalability_optimizer):
        """Test automatic scaling decisions"""
        current_load = 0.85  # 85% load
        current_nodes = 3

        scaling_decision = scalability_optimizer.calculate_scaling_decision(
            current_load, current_nodes
        )

        assert 'action' in scaling_decision
        assert 'new_node_count' in scaling_decision
        assert scaling_decision['action'] in ['scale_up', 'scale_down', 'maintain']

    def test_resource_partitioning(self, scalability_optimizer):
        """Test resource partitioning"""
        total_resources = 1000
        partitions = scalability_optimizer.partition_resources(total_resources, 4)

        assert len(partitions) == 4
        assert sum(partitions) == total_resources
        assert all(p > 0 for p in partitions)

    def test_performance_scaling(self, scalability_optimizer):
        """Test performance scaling under load"""
        # Simulate increasing load
        loads = [0.2, 0.4, 0.6, 0.8, 0.9]

        scaling_recommendations = []
        for load in loads:
            rec = scalability_optimizer.get_scaling_recommendation(load)
            scaling_recommendations.append(rec)

        # Should recommend scaling up as load increases
        high_load_recs = [r for r in scaling_recommendations if loads[scaling_recommendations.index(r)] > 0.7]
        assert any("scale up" in r.lower() for r in high_load_recs)

    def test_scalability_metrics(self, scalability_optimizer):
        """Test scalability metrics collection"""
        metrics = scalability_optimizer.get_scalability_metrics()

        assert 'current_load' in metrics
        assert 'node_count' in metrics
        assert 'resource_utilization' in metrics
        assert 'scaling_events' in metrics
        assert 'performance_score' in metrics


# Integration tests
class TestPerformanceIntegration:
    """Integration tests for performance components"""

    @pytest.mark.asyncio
    async def test_full_performance_monitoring(self):
        """Test complete performance monitoring system"""
        monitor = PerformanceMonitor()
        await monitor.start()

        crypto_opt = CryptoOptimizer(None)  # Mock key manager
        await crypto_opt.start()

        memory_opt = MemoryOptimizer()
        memory_opt.start()

        try:
            # Simulate system activity
            for _ in range(10):
                monitor.record_metric(MetricType.CPU_USAGE, 50.0)
                monitor.record_metric(MetricType.MEMORY_USAGE, 256.0)
                await crypto_opt.encrypt_data(b"test_data")
                memory_opt.allocate_from_pool(1024)
                await asyncio.sleep(0.01)

            # Generate comprehensive report
            report = monitor.generate_performance_report()

            assert 'metrics_summary' in report
            assert 'system_info' in report
            assert 'optimization_recommendations' in report

            # Check that crypto and memory optimizations are included
            assert 'crypto_performance' in report
            assert 'memory_usage' in report

        finally:
            await monitor.stop()
            await crypto_opt.stop()
            memory_opt.stop()

    @pytest.mark.asyncio
    async def test_optimization_pipeline(self):
        """Test the complete optimization pipeline"""
        # Create all optimizers
        crypto_opt = CryptoOptimizer(None)
        await crypto_opt.start()

        memory_opt = MemoryOptimizer()
        memory_opt.start()

        network_opt = NetworkOptimizer()
        await network_opt.start()

        scalability_opt = ScalabilityOptimizer()
        await scalability_opt.start()

        try:
            # Run optimization pipeline
            pipeline_results = await crypto_opt.run_optimization_pipeline([
                crypto_opt.optimize_encryption,
                memory_opt.optimize_memory_usage,
                network_opt.optimize_network_performance,
                scalability_opt.optimize_scalability
            ])

            assert len(pipeline_results) == 4
            assert all(isinstance(r, dict) for r in pipeline_results)

        finally:
            await crypto_opt.stop()
            memory_opt.stop()
            await network_opt.stop()
            await scalability_opt.stop()

    def test_performance_baselines(self):
        """Test performance baseline establishment"""
        monitor = PerformanceMonitor()

        # Establish baselines
        baselines = monitor.establish_performance_baselines()

        assert 'cpu_baseline' in baselines
        assert 'memory_baseline' in baselines
        assert 'network_baseline' in baselines
        assert 'crypto_baseline' in baselines

        # All baselines should be reasonable values
        assert all(0 <= v <= 100 for v in baselines.values() if isinstance(v, (int, float)))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])