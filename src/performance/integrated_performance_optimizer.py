"""
Integrated Performance Optimizer

Comprehensive integration of all performance optimizations providing:
- Unified performance management interface
- Automatic optimization based on system state
- Performance monitoring and alerting
- Configuration management for all optimizers
- Integration with existing Privatus-chat systems
"""

import asyncio
import time
import logging
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OptimizationLevel(Enum):
    """Optimization levels"""
    NONE = "none"              # No optimizations
    BASIC = "basic"           # Basic optimizations only
    STANDARD = "standard"     # Standard optimizations
    AGGRESSIVE = "aggressive" # Aggressive optimizations
    MAXIMUM = "maximum"       # Maximum optimizations


@dataclass
class PerformanceConfig:
    """Comprehensive performance configuration"""
    optimization_level: OptimizationLevel = OptimizationLevel.STANDARD

    # Component configurations
    crypto_config: Dict[str, Any] = field(default_factory=dict)
    memory_config: Dict[str, Any] = field(default_factory=dict)
    network_config: Dict[str, Any] = field(default_factory=dict)
    caching_config: Dict[str, Any] = field(default_factory=dict)
    gui_config: Dict[str, Any] = field(default_factory=dict)

    # Monitoring configuration
    monitoring_interval: float = 1.0
    enable_dashboard: bool = True
    dashboard_port: int = 8080
    enable_auto_optimization: bool = True

    # Benchmarking configuration
    enable_benchmarking: bool = True
    benchmark_interval: float = 3600.0  # 1 hour
    enable_regression_testing: bool = True

    def get_component_config(self, component: str) -> Dict[str, Any]:
        """Get configuration for a specific component"""
        config_map = {
            'crypto': self.crypto_config,
            'memory': self.memory_config,
            'network': self.network_config,
            'caching': self.caching_config,
            'gui': self.gui_config
        }
        return config_map.get(component, {})


class IntegratedPerformanceOptimizer:
    """Main integrated performance optimizer"""

    def __init__(self, config: Optional[PerformanceConfig] = None):
        self.config = config or PerformanceConfig()

        # Initialize all optimizers
        self.performance_monitor = None
        self.crypto_optimizer = None
        self.memory_optimizer = None
        self.network_optimizer = None
        self.scalability_optimizer = None
        self.caching_strategy = None
        self.gui_optimizer = None
        self.dashboard = None
        self.benchmark_suite = None
        self.regression_tester = None

        # Integration state
        self.running = False
        self.initialized = False

        # Performance state tracking
        self.current_optimization_level = OptimizationLevel.NONE
        self.performance_alerts: List[Dict[str, Any]] = []

        # Thread safety
        self._lock = threading.RLock()

    async def initialize(self):
        """Initialize all performance optimizers"""
        if self.initialized:
            return

        logger.info("Initializing integrated performance optimizer...")

        try:
            # Import here to avoid circular imports
            from src.performance.performance_monitor import PerformanceMonitor
            from src.performance.crypto_optimizer import CryptoOptimizer
            from src.performance.memory_optimizer import MemoryOptimizer
            from src.performance.network_optimizer import NetworkOptimizer
            from src.performance.scalability_optimizer import ScalabilityOptimizer
            from src.performance.caching_strategies import ComprehensiveCachingStrategy
            from src.performance.gui_responsiveness_optimizer import GUIResponsivenessOptimizer
            from src.performance.monitoring_dashboard import PerformanceDashboard
            from src.performance.enhanced_benchmarks import EnhancedBenchmarkSuite, PerformanceRegressionTester

            # Initialize core performance monitor
            self.performance_monitor = PerformanceMonitor(
                monitoring_interval=self.config.monitoring_interval
            )

            # Initialize optimizers based on configuration level
            await self._initialize_optimizers_for_level()

            # Initialize enhanced components
            self.benchmark_suite = EnhancedBenchmarkSuite(self.performance_monitor)
            self.regression_tester = PerformanceRegressionTester(self.benchmark_suite)

            if self.config.enable_dashboard:
                self.dashboard = PerformanceDashboard(
                    performance_monitor=self.performance_monitor,
                    port=self.config.dashboard_port
                )

            self.initialized = True
            logger.info("Integrated performance optimizer initialized successfully")

        except Exception as e:
            logger.error(f"Failed to initialize performance optimizer: {e}")
            raise

    async def _initialize_optimizers_for_level(self):
        """Initialize optimizers based on optimization level"""
        level = self.config.optimization_level

        # Always initialize core optimizers
        self.crypto_optimizer = CryptoOptimizer(self.config.get_component_config('crypto'))
        self.memory_optimizer = MemoryOptimizer(self.config.get_component_config('memory'))
        self.network_optimizer = NetworkOptimizer(self.config.get_component_config('network'))

        # Initialize based on level
        if level in [OptimizationLevel.STANDARD, OptimizationLevel.AGGRESSIVE, OptimizationLevel.MAXIMUM]:
            self.scalability_optimizer = ScalabilityOptimizer()
            self.caching_strategy = ComprehensiveCachingStrategy(self.config.get_component_config('caching'))

        if level in [OptimizationLevel.AGGRESSIVE, OptimizationLevel.MAXIMUM]:
            self.gui_optimizer = GUIResponsivenessOptimizer(self.config.get_component_config('gui'))

    async def start(self):
        """Start all performance optimizers"""
        if not self.initialized:
            await self.initialize()

        if self.running:
            return

        logger.info("Starting integrated performance optimizer...")
        self.running = True

        try:
            # Start core performance monitor
            await self.performance_monitor.start()

            # Start optimizers in order
            if self.crypto_optimizer:
                await self.crypto_optimizer.start()
            if self.memory_optimizer:
                await self.memory_optimizer.start()
            if self.network_optimizer:
                await self.network_optimizer.start()
            if self.scalability_optimizer:
                await self.scalability_optimizer.start()
            if self.caching_strategy:
                await self.caching_strategy.start()
            if self.gui_optimizer:
                await self.gui_optimizer.start()

            # Start enhanced components
            if self.config.enable_benchmarking and self.benchmark_suite:
                # Start periodic benchmarking
                asyncio.create_task(self._benchmark_loop())

            if self.config.enable_dashboard and self.dashboard:
                await self.dashboard.start()

            # Start auto-optimization if enabled
            if self.config.enable_auto_optimization:
                asyncio.create_task(self._auto_optimization_loop())

            logger.info("Integrated performance optimizer started successfully")

        except Exception as e:
            logger.error(f"Failed to start performance optimizer: {e}")
            await self.stop()
            raise

    async def stop(self):
        """Stop all performance optimizers"""
        if not self.running:
            return

        logger.info("Stopping integrated performance optimizer...")
        self.running = False

        # Stop all components in reverse order
        if self.dashboard:
            await self.dashboard.stop()
        if self.gui_optimizer:
            await self.gui_optimizer.stop()
        if self.caching_strategy:
            await self.caching_strategy.stop()
        if self.scalability_optimizer:
            await self.scalability_optimizer.stop()
        if self.network_optimizer:
            await self.network_optimizer.stop()
        if self.memory_optimizer:
            await self.memory_optimizer.stop()
        if self.crypto_optimizer:
            await self.crypto_optimizer.stop()
        if self.performance_monitor:
            await self.performance_monitor.stop()

        logger.info("Integrated performance optimizer stopped")

    async def _benchmark_loop(self):
        """Periodic benchmarking loop"""
        while self.running:
            try:
                if self.benchmark_suite:
                    await self.benchmark_suite.run_comprehensive_benchmarks()

                if self.config.enable_regression_testing and self.regression_tester:
                    await self.regression_tester.run_regression_test()

                await asyncio.sleep(self.config.benchmark_interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Benchmark loop error: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes before retry

    async def _auto_optimization_loop(self):
        """Automatic optimization adjustment loop"""
        while self.running:
            try:
                await self._adjust_optimizations()
                await asyncio.sleep(60)  # Check every minute
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Auto-optimization loop error: {e}")
                await asyncio.sleep(300)

    async def _adjust_optimizations(self):
        """Adjust optimizations based on current system state"""
        try:
            if not self.performance_monitor:
                return

            # Get current performance stats
            stats = self.performance_monitor.get_comprehensive_stats()
            resource_stats = stats.get('resource_stats', {})

            # Check if adjustments are needed
            cpu_usage = resource_stats.get('cpu', {}).get('current', 0)
            memory_usage = resource_stats.get('memory', {}).get('current', 0)

            # Adjust optimization level based on resource usage
            if cpu_usage > 90 or memory_usage > 90:
                await self._increase_optimization_level()
            elif cpu_usage < 30 and memory_usage < 50:
                await self._decrease_optimization_level()

        except Exception as e:
            logger.error(f"Failed to adjust optimizations: {e}")

    async def _increase_optimization_level(self):
        """Increase optimization level"""
        level_progression = [
            OptimizationLevel.NONE,
            OptimizationLevel.BASIC,
            OptimizationLevel.STANDARD,
            OptimizationLevel.AGGRESSIVE,
            OptimizationLevel.MAXIMUM
        ]

        current_index = level_progression.index(self.current_optimization_level)
        if current_index < len(level_progression) - 1:
            new_level = level_progression[current_index + 1]
            await self.set_optimization_level(new_level)

    async def _decrease_optimization_level(self):
        """Decrease optimization level"""
        level_progression = [
            OptimizationLevel.NONE,
            OptimizationLevel.BASIC,
            OptimizationLevel.STANDARD,
            OptimizationLevel.AGGRESSIVE,
            OptimizationLevel.MAXIMUM
        ]

        current_index = level_progression.index(self.current_optimization_level)
        if current_index > 0:
            new_level = level_progression[current_index - 1]
            await self.set_optimization_level(new_level)

    async def set_optimization_level(self, level: OptimizationLevel):
        """Set optimization level and reinitialize if needed"""
        if level == self.current_optimization_level:
            return

        logger.info(f"Changing optimization level from {self.current_optimization_level.value} to {level.value}")

        # Stop current optimizers
        await self.stop()

        # Update configuration
        self.config.optimization_level = level
        self.current_optimization_level = level

        # Restart with new level
        await self.start()

    def get_performance_stats(self) -> Dict[str, Any]:
        """Get comprehensive performance statistics"""
        stats = {
            'optimization_level': self.current_optimization_level.value,
            'running': self.running,
            'initialized': self.initialized
        }

        # Add stats from each optimizer
        if self.performance_monitor:
            stats['performance_monitor'] = self.performance_monitor.get_comprehensive_stats()
        if self.crypto_optimizer:
            stats['crypto_optimizer'] = self.crypto_optimizer.get_optimization_stats()
        if self.memory_optimizer:
            stats['memory_optimizer'] = self.memory_optimizer.get_optimization_stats()
        if self.network_optimizer:
            stats['network_optimizer'] = self.network_optimizer.get_optimization_stats()
        if self.scalability_optimizer:
            stats['scalability_optimizer'] = self.scalability_optimizer.get_optimization_stats()
        if self.caching_strategy:
            stats['caching_strategy'] = self.caching_strategy.get_comprehensive_stats()
        if self.gui_optimizer:
            stats['gui_optimizer'] = self.gui_optimizer.get_optimization_stats()
        if self.benchmark_suite:
            stats['benchmark_summary'] = self.benchmark_suite._generate_summary()

        return stats

    def export_performance_report(self, filepath: str):
        """Export comprehensive performance report"""
        try:
            report_data = {
                'timestamp': time.time(),
                'configuration': {
                    'optimization_level': self.config.optimization_level.value,
                    'monitoring_interval': self.config.monitoring_interval,
                    'enable_dashboard': self.config.enable_dashboard,
                    'enable_auto_optimization': self.config.enable_auto_optimization
                },
                'performance_stats': self.get_performance_stats()
            }

            import json
            from pathlib import Path

            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            logger.info(f"Performance report exported to {filepath}")

        except Exception as e:
            logger.error(f"Failed to export performance report: {e}")

    # Convenience methods for common operations

    async def run_benchmarks(self) -> Dict[str, Any]:
        """Run comprehensive benchmarks"""
        if self.benchmark_suite:
            return await self.benchmark_suite.run_comprehensive_benchmarks()
        return {}

    async def run_regression_test(self) -> Dict[str, Any]:
        """Run performance regression test"""
        if self.regression_tester:
            return await self.regression_tester.run_regression_test()
        return {}

    def get_dashboard_url(self) -> Optional[str]:
        """Get dashboard URL if running"""
        if self.config.enable_dashboard and self.running:
            return f"http://localhost:{self.config.dashboard_port}"
        return None

    def add_performance_alert(self, alert_type: str, message: str, severity: str = "info"):
        """Add a performance alert"""
        alert = {
            'type': alert_type,
            'message': message,
            'severity': severity,
            'timestamp': time.time()
        }

        with self._lock:
            self.performance_alerts.append(alert)

            # Keep only recent alerts
            if len(self.performance_alerts) > 1000:
                self.performance_alerts = self.performance_alerts[-1000:]

        logger.log(
            logging.WARNING if severity == 'warning' else logging.ERROR if severity == 'critical' else logging.INFO,
            f"Performance Alert [{alert_type}]: {message}"
        )

    def get_performance_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent performance alerts"""
        with self._lock:
            return self.performance_alerts[-limit:]


# Global performance optimizer instance
_performance_optimizer: Optional[IntegratedPerformanceOptimizer] = None


def get_performance_optimizer(config: Optional[PerformanceConfig] = None) -> IntegratedPerformanceOptimizer:
    """Get or create the global performance optimizer instance"""
    global _performance_optimizer

    if _performance_optimizer is None:
        _performance_optimizer = IntegratedPerformanceOptimizer(config)

    return _performance_optimizer


async def initialize_performance_optimization(config: Optional[Dict[str, Any]] = None) -> IntegratedPerformanceOptimizer:
    """Initialize performance optimization with configuration"""
    perf_config = PerformanceConfig()
    if config:
        for key, value in config.items():
            if hasattr(perf_config, key):
                setattr(perf_config, key, value)

    optimizer = get_performance_optimizer(perf_config)
    await optimizer.initialize()
    return optimizer


async def start_performance_optimization(config: Optional[Dict[str, Any]] = None) -> IntegratedPerformanceOptimizer:
    """Start performance optimization with configuration"""
    optimizer = await initialize_performance_optimization(config)
    await optimizer.start()
    return optimizer


def get_optimization_stats() -> Dict[str, Any]:
    """Get current optimization statistics"""
    optimizer = get_performance_optimizer()
    return optimizer.get_performance_stats()


# Integration helpers for existing code

class PerformanceOptimizationMixin:
    """Mixin class to add performance optimization to existing classes"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._perf_optimizer = get_performance_optimizer()

    def record_operation_time(self, operation_name: str, duration: float):
        """Record operation timing"""
        if self._perf_optimizer and self._perf_optimizer.performance_monitor:
            self._perf_optimizer.performance_monitor.record_timer(
                f"{self.__class__.__name__}.{operation_name}",
                duration
            )

    def increment_operation_counter(self, operation_name: str, count: int = 1):
        """Increment operation counter"""
        if self._perf_optimizer and self._perf_optimizer.performance_monitor:
            self._perf_optimizer.performance_monitor.increment_counter(
                f"{self.__class__.__name__}.{operation_name}",
                count
            )

    def cache_data(self, key: str, data: Any, ttl: float = 3600.0) -> bool:
        """Cache data using optimization strategy"""
        if self._perf_optimizer and self._perf_optimizer.caching_strategy:
            return self._perf_optimizer.caching_strategy.put(key, data, ttl)
        return False

    def get_cached_data(self, key: str) -> Optional[Any]:
        """Get cached data"""
        if self._perf_optimizer and self._perf_optimizer.caching_strategy:
            return self._perf_optimizer.caching_strategy.get(key)
        return None


# Example usage and integration points

async def example_usage():
    """Example of how to use the integrated performance optimizer"""

    # Configure performance optimization
    config = {
        'optimization_level': 'aggressive',
        'monitoring_interval': 1.0,
        'enable_dashboard': True,
        'dashboard_port': 8080,
        'enable_benchmarking': True,
        'benchmark_interval': 1800,  # 30 minutes
        'crypto_config': {
            'hardware_acceleration': True,
            'parallel_workers': 4,
            'key_cache_size': 2000
        },
        'memory_config': {
            'pool_size': 200 * 1024 * 1024,  # 200MB
            'max_blocks': 20000,
            'gc_threshold': 0.8
        },
        'network_config': {
            'max_connections': 1500,
            'batch_size': 150,
            'bandwidth_limit': 20 * 1024 * 1024  # 20MB/s
        }
    }

    # Start performance optimization
    optimizer = await start_performance_optimization(config)

    # Run initial benchmarks
    benchmarks = await optimizer.run_benchmarks()
    print(f"Benchmark results: {len(benchmarks.get('benchmarks', {}))} categories tested")

    # Get dashboard URL
    dashboard_url = optimizer.get_dashboard_url()
    if dashboard_url:
        print(f"Performance dashboard available at: {dashboard_url}")

    # Export performance report
    optimizer.export_performance_report("/tmp/privatus_performance_report.json")

    return optimizer


if __name__ == "__main__":
    # Example standalone usage
    asyncio.run(example_usage())