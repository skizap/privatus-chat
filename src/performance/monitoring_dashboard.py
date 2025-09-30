"""
Performance Monitoring Dashboard

Real-time performance monitoring and visualization dashboard with:
- Web-based interface for performance metrics
- Real-time updates and alerts
- Historical performance analysis
- Custom dashboard configurations
- Export capabilities for reports
"""

import asyncio
import time
import logging
import json
import threading
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict, deque
import webbrowser
import http.server
import socketserver
from pathlib import Path
import os

logger = logging.getLogger(__name__)


@dataclass
class DashboardMetric:
    """Represents a dashboard metric"""
    name: str
    value: float
    unit: str
    timestamp: float
    category: str
    threshold_warning: Optional[float] = None
    threshold_critical: Optional[float] = None
    trend: List[float] = field(default_factory=list)

    def get_status(self) -> str:
        """Get status based on thresholds"""
        if self.threshold_critical and self.value >= self.threshold_critical:
            return 'critical'
        elif self.threshold_warning and self.value >= self.threshold_warning:
            return 'warning'
        else:
            return 'normal'

    def update_trend(self):
        """Update trend data"""
        self.trend.append(self.value)
        if len(self.trend) > 100:  # Keep last 100 values
            self.trend.pop(0)


class DashboardWidget:
    """Represents a dashboard widget"""

    def __init__(self, widget_id: str, widget_type: str, title: str,
                 position: Dict[str, int], size: Dict[str, int]):
        self.widget_id = widget_id
        self.widget_type = widget_type
        self.title = title
        self.position = position
        self.size = size
        self.metrics: List[str] = []
        self.config: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.widget_id,
            'type': self.widget_type,
            'title': self.title,
            'position': self.position,
            'size': self.size,
            'metrics': self.metrics,
            'config': self.config
        }


class PerformanceDashboardServer:
    """HTTP server for serving the performance dashboard"""

    def __init__(self, dashboard: 'PerformanceDashboard', port: int = 8080):
        self.dashboard = dashboard
        self.port = port
        self.server = None

        # Dashboard HTML template
        self.html_template = self._generate_html_template()

    def _generate_html_template(self) -> str:
        """Generate HTML template for the dashboard"""
        return """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Privatus-chat Performance Dashboard</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }
                .dashboard {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                    gap: 20px;
                    max-width: 1400px;
                    margin: 0 auto;
                }
                .widget {
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    padding: 20px;
                    position: relative;
                }
                .widget-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                    border-bottom: 1px solid #eee;
                    padding-bottom: 10px;
                }
                .metric-value {
                    font-size: 2em;
                    font-weight: bold;
                    margin: 10px 0;
                }
                .metric-unit {
                    color: #666;
                    font-size: 0.9em;
                }
                .status-normal { color: #28a745; }
                .status-warning { color: #ffc107; }
                .status-critical { color: #dc3545; }
                .chart-container {
                    position: relative;
                    height: 200px;
                    margin: 15px 0;
                }
                .refresh-indicator {
                    position: absolute;
                    top: 10px;
                    right: 10px;
                    width: 12px;
                    height: 12px;
                    border-radius: 50%;
                    background-color: #28a745;
                }
                .refresh-indicator.updating {
                    background-color: #ffc107;
                    animation: pulse 1s infinite;
                }
                @keyframes pulse {
                    0% { opacity: 1; }
                    50% { opacity: 0.5; }
                    100% { opacity: 1; }
                }
                .navbar {
                    background: white;
                    padding: 15px 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    margin-bottom: 20px;
                    border-radius: 8px;
                }
                .navbar h1 {
                    margin: 0;
                    color: #333;
                }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 15px;
                    margin-bottom: 20px;
                }
                .stat-card {
                    background: white;
                    padding: 15px;
                    border-radius: 8px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    text-align: center;
                }
                .stat-value {
                    font-size: 1.5em;
                    font-weight: bold;
                    color: #333;
                }
                .stat-label {
                    color: #666;
                    font-size: 0.9em;
                }
            </style>
        </head>
        <body>
            <div class="navbar">
                <h1>🚀 Privatus-chat Performance Dashboard</h1>
                <p>Real-time performance monitoring and analytics</p>
            </div>

            <div class="stats-grid" id="overview-stats">
                <!-- Overview stats will be populated by JavaScript -->
            </div>

            <div class="dashboard" id="dashboard-widgets">
                <!-- Dashboard widgets will be populated by JavaScript -->
            </div>

            <script>
                class PerformanceDashboard {
                    constructor() {
                        this.metrics = {};
                        this.widgets = {};
                        this.isUpdating = false;
                        this.updateInterval = 2000; // 2 seconds

                        this.init();
                    }

                    async init() {
                        await this.loadConfiguration();
                        this.startAutoUpdate();
                    }

                    async loadConfiguration() {
                        try {
                            const response = await fetch('/api/dashboard/config');
                            const config = await response.json();
                            this.createWidgets(config.widgets);
                            this.createOverviewStats(config.overview_metrics);
                        } catch (error) {
                            console.error('Failed to load dashboard configuration:', error);
                        }
                    }

                    createWidgets(widgets) {
                        const container = document.getElementById('dashboard-widgets');
                        container.innerHTML = '';

                        widgets.forEach(widgetConfig => {
                            const widget = this.createWidget(widgetConfig);
                            container.appendChild(widget.element);
                            this.widgets[widgetConfig.id] = widget;
                        });
                    }

                    createWidget(config) {
                        const widgetDiv = document.createElement('div');
                        widgetDiv.className = 'widget';
                        widgetDiv.style.gridColumn = `span ${config.size.width}`;
                        widgetDiv.style.gridRow = `span ${config.size.height}`;

                        const header = document.createElement('div');
                        header.className = 'widget-header';

                        const title = document.createElement('h3');
                        title.textContent = config.title;
                        header.appendChild(title);

                        const refreshIndicator = document.createElement('div');
                        refreshIndicator.className = 'refresh-indicator';
                        header.appendChild(refreshIndicator);

                        widgetDiv.appendChild(header);

                        const chartContainer = document.createElement('div');
                        chartContainer.className = 'chart-container';

                        const canvas = document.createElement('canvas');
                        chartContainer.appendChild(canvas);
                        widgetDiv.appendChild(chartContainer);

                        return {
                            element: widgetDiv,
                            canvas: canvas,
                            chart: null,
                            config: config,
                            refreshIndicator: refreshIndicator
                        };
                    }

                    createOverviewStats(metrics) {
                        const container = document.getElementById('overview-stats');
                        container.innerHTML = '';

                        metrics.forEach(metricName => {
                            const statCard = document.createElement('div');
                            statCard.className = 'stat-card';

                            const value = document.createElement('div');
                            value.className = 'stat-value';
                            value.id = `stat-${metricName}`;
                            value.textContent = '0';
                            statCard.appendChild(value);

                            const label = document.createElement('div');
                            label.className = 'stat-label';
                            label.textContent = this.formatMetricName(metricName);
                            statCard.appendChild(label);

                            container.appendChild(statCard);
                        });
                    }

                    async startAutoUpdate() {
                        setInterval(async () => {
                            if (!this.isUpdating) {
                                await this.updateDashboard();
                            }
                        }, this.updateInterval);
                    }

                    async updateDashboard() {
                        this.isUpdating = true;
                        this.setUpdatingState(true);

                        try {
                            await this.fetchMetrics();
                            this.updateOverviewStats();
                            this.updateWidgets();
                        } catch (error) {
                            console.error('Failed to update dashboard:', error);
                        } finally {
                            this.isUpdating = false;
                            this.setUpdatingState(false);
                        }
                    }

                    setUpdatingState(updating) {
                        Object.values(this.widgets).forEach(widget => {
                            if (updating) {
                                widget.refreshIndicator.classList.add('updating');
                            } else {
                                widget.refreshIndicator.classList.remove('updating');
                            }
                        });
                    }

                    async fetchMetrics() {
                        const response = await fetch('/api/dashboard/metrics');
                        this.metrics = await response.json();
                    }

                    updateOverviewStats() {
                        if (!this.metrics.overview) return;

                        Object.entries(this.metrics.overview).forEach(([key, value]) => {
                            const element = document.getElementById(`stat-${key}`);
                            if (element) {
                                element.textContent = this.formatMetricValue(value);
                            }
                        });
                    }

                    updateWidgets() {
                        Object.values(this.widgets).forEach(widget => {
                            this.updateWidget(widget);
                        });
                    }

                    updateWidget(widget) {
                        const { config } = widget;

                        if (config.type === 'line_chart' || config.type === 'bar_chart') {
                            this.updateChartWidget(widget);
                        } else if (config.type === 'metric') {
                            this.updateMetricWidget(widget);
                        }
                    }

                    updateChartWidget(widget) {
                        const { config, canvas } = widget;

                        if (!widget.chart) {
                            widget.chart = new Chart(canvas.getContext('2d'), {
                                type: config.type === 'line_chart' ? 'line' : 'bar',
                                data: {
                                    labels: [],
                                    datasets: []
                                },
                                options: {
                                    responsive: true,
                                    maintainAspectRatio: false,
                                    scales: {
                                        y: {
                                            beginAtZero: true
                                        }
                                    }
                                }
                            });
                        }

                        // Update chart data
                        config.metrics.forEach((metricName, index) => {
                            if (!this.metrics[metricName]) return;

                            const metric = this.metrics[metricName];
                            const values = metric.trend || [metric.value];

                            if (widget.chart.data.datasets[index]) {
                                widget.chart.data.datasets[index].data = values;
                            } else {
                                widget.chart.data.datasets[index] = {
                                    label: this.formatMetricName(metricName),
                                    data: values,
                                    borderColor: this.getChartColor(index),
                                    backgroundColor: this.getChartColor(index, 0.1),
                                    fill: false
                                };
                            }
                        });

                        widget.chart.update();
                    }

                    updateMetricWidget(widget) {
                        const { config } = widget;
                        const metricName = config.metrics[0];

                        if (!this.metrics[metricName]) return;

                        const metric = this.metrics[metricName];
                        const valueElement = widget.element.querySelector('.metric-value');

                        if (valueElement) {
                            valueElement.textContent = this.formatMetricValue(metric.value);
                            valueElement.className = `metric-value status-${metric.status || 'normal'}`;
                        }
                    }

                    formatMetricValue(value) {
                        if (typeof value === 'number') {
                            if (value >= 1000000) {
                                return (value / 1000000).toFixed(1) + 'M';
                            } else if (value >= 1000) {
                                return (value / 1000).toFixed(1) + 'K';
                            } else {
                                return value.toFixed(2);
                            }
                        }
                        return value;
                    }

                    formatMetricName(name) {
                        return name.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
                    }

                    getChartColor(index, alpha = 1) {
                        const colors = [
                            `rgba(255, 99, 132, ${alpha})`,
                            `rgba(54, 162, 235, ${alpha})`,
                            `rgba(255, 205, 86, ${alpha})`,
                            `rgba(75, 192, 192, ${alpha})`,
                            `rgba(153, 102, 255, ${alpha})`,
                            `rgba(255, 159, 64, ${alpha})`
                        ];
                        return colors[index % colors.length];
                    }
                }

                // Initialize dashboard when page loads
                document.addEventListener('DOMContentLoaded', () => {
                    new PerformanceDashboard();
                });
            </script>
        </body>
        </html>
        """

    def start_server(self):
        """Start the HTTP server"""
        try:
            handler = DashboardRequestHandler
            handler.dashboard = self.dashboard

            with socketserver.TCPServer(("", self.port), handler) as httpd:
                self.server = httpd
                logger.info(f"Dashboard server started on port {self.port}")
                httpd.serve_forever()

        except Exception as e:
            logger.error(f"Failed to start dashboard server: {e}")

    def stop_server(self):
        """Stop the HTTP server"""
        if self.server:
            self.server.shutdown()
            logger.info("Dashboard server stopped")


class DashboardRequestHandler(http.server.SimpleHTTPRequestHandler):
    """HTTP request handler for the dashboard"""

    def do_GET(self):
        """Handle GET requests"""
        if self.path == '/':
            self.send_html_response(200, self.server.html_template)
        elif self.path == '/api/dashboard/metrics':
            self.send_json_response(self.get_metrics())
        elif self.path == '/api/dashboard/config':
            self.send_json_response(self.get_config())
        else:
            self.send_error(404, "Not Found")

    def send_html_response(self, code: int, html: str):
        """Send HTML response"""
        self.send_response(code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(html.encode('utf-8'))

    def send_json_response(self, data: Any):
        """Send JSON response"""
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()

        json_data = json.dumps(data, default=str)
        self.wfile.write(json_data.encode('utf-8'))

    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics from dashboard"""
        return self.dashboard.get_dashboard_metrics()

    def get_config(self) -> Dict[str, Any]:
        """Get dashboard configuration"""
        return self.dashboard.get_dashboard_config()


class PerformanceDashboard:
    """Main performance dashboard class"""

    def __init__(self, performance_monitor, port: int = 8080,
                 auto_open_browser: bool = True):
        self.performance_monitor = performance_monitor
        self.port = port
        self.auto_open_browser = auto_open_browser

        # Dashboard state
        self.metrics_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.alerts: List[Dict[str, Any]] = []
        self.dashboard_widgets: List[DashboardWidget] = []

        # Server
        self.server = PerformanceDashboardServer(self, port)

        # Default widgets
        self._create_default_widgets()

    def _create_default_widgets(self):
        """Create default dashboard widgets"""
        # System Overview Widget
        system_widget = DashboardWidget(
            widget_id='system_overview',
            widget_type='metric_grid',
            title='System Overview',
            position={'x': 0, 'y': 0},
            size={'width': 2, 'height': 1}
        )
        system_widget.metrics = ['cpu_usage', 'memory_usage', 'disk_usage']
        self.dashboard_widgets.append(system_widget)

        # Performance Metrics Widget
        perf_widget = DashboardWidget(
            widget_id='performance_metrics',
            widget_type='line_chart',
            title='Performance Metrics',
            position={'x': 0, 'y': 1},
            size={'width': 2, 'height': 2}
        )
        perf_widget.metrics = ['throughput', 'latency', 'error_rate']
        self.dashboard_widgets.append(perf_widget)

        # Cache Performance Widget
        cache_widget = DashboardWidget(
            widget_id='cache_performance',
            widget_type='bar_chart',
            title='Cache Performance',
            position={'x': 2, 'y': 0},
            size={'width': 1, 'height': 2}
        )
        cache_widget.metrics = ['cache_hit_rate', 'cache_miss_rate']
        self.dashboard_widgets.append(cache_widget)

        # Network Performance Widget
        network_widget = DashboardWidget(
            widget_id='network_performance',
            widget_type='line_chart',
            title='Network Performance',
            position={'x': 2, 'y': 2},
            size={'width': 1, 'height': 2}
        )
        network_widget.metrics = ['network_latency', 'network_throughput']
        self.dashboard_widgets.append(network_widget)

    async def start(self):
        """Start the performance dashboard"""
        # Start metrics collection
        asyncio.create_task(self._metrics_collection_loop())

        # Start HTTP server in thread
        server_thread = threading.Thread(target=self.server.start_server, daemon=True)
        server_thread.start()

        # Auto-open browser if enabled
        if self.auto_open_browser:
            asyncio.create_task(self._open_browser())

        logger.info(f"Performance dashboard started on http://localhost:{self.port}")

    async def stop(self):
        """Stop the performance dashboard"""
        self.server.stop_server()
        logger.info("Performance dashboard stopped")

    async def _metrics_collection_loop(self):
        """Collect metrics for dashboard"""
        while True:
            try:
                await self._collect_dashboard_metrics()
                await asyncio.sleep(2.0)  # Update every 2 seconds
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")
                await asyncio.sleep(5.0)

    async def _collect_dashboard_metrics(self):
        """Collect and process metrics for dashboard"""
        try:
            # Get comprehensive stats
            stats = self.performance_monitor.get_comprehensive_stats()

            # Process metrics for dashboard
            dashboard_metrics = self._process_metrics_for_dashboard(stats)

            # Store in history
            for metric_name, metric_value in dashboard_metrics.items():
                self.metrics_history[metric_name].append(metric_value)

            # Check for alerts
            await self._check_alerts(dashboard_metrics)

        except Exception as e:
            logger.error(f"Failed to collect dashboard metrics: {e}")

    def _process_metrics_for_dashboard(self, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Process raw stats into dashboard metrics"""
        processed = {}

        try:
            # System metrics
            resource_stats = stats.get('resource_stats', {})
            if 'cpu' in resource_stats:
                processed['cpu_usage'] = resource_stats['cpu'].get('current', 0)
            if 'memory' in resource_stats:
                processed['memory_usage'] = resource_stats['memory'].get('current', 0)

            # Performance metrics
            metrics_summary = stats.get('metrics', {})
            if 'gauges' in metrics_summary:
                gauges = metrics_summary['gauges']
                processed['network_latency'] = gauges.get('system.network.latency', 0)
                processed['disk_usage'] = gauges.get('system.disk.usage', 0)

            # Cache metrics
            if 'cache_hit_rate' in stats:
                processed['cache_hit_rate'] = stats['cache_hit_rate']
                processed['cache_miss_rate'] = 1.0 - stats['cache_hit_rate']

            # Network metrics
            if 'network_throughput' in stats:
                processed['network_throughput'] = stats['network_throughput']

            # Calculate derived metrics
            processed['throughput'] = self._calculate_throughput()
            processed['latency'] = self._calculate_average_latency()
            processed['error_rate'] = self._calculate_error_rate()

        except Exception as e:
            logger.error(f"Failed to process metrics: {e}")

        return processed

    def _calculate_throughput(self) -> float:
        """Calculate system throughput"""
        # This would calculate actual throughput based on metrics
        return 100.0  # Placeholder

    def _calculate_average_latency(self) -> float:
        """Calculate average latency"""
        # This would calculate actual latency based on metrics
        return 50.0  # Placeholder

    def _calculate_error_rate(self) -> float:
        """Calculate error rate"""
        # This would calculate actual error rate based on metrics
        return 0.01  # Placeholder

    async def _check_alerts(self, metrics: Dict[str, Any]):
        """Check for performance alerts"""
        alerts_to_check = [
            ('cpu_usage', 80, 90, 'High CPU Usage'),
            ('memory_usage', 85, 95, 'High Memory Usage'),
            ('latency', 100, 200, 'High Latency'),
            ('error_rate', 0.05, 0.1, 'High Error Rate')
        ]

        for metric_name, warning_threshold, critical_threshold, alert_name in alerts_to_check:
            if metric_name in metrics:
                value = metrics[metric_name]

                if value >= critical_threshold:
                    await self._create_alert(alert_name, 'critical',
                                           f'{metric_name} is {value:.2f}, above critical threshold {critical_threshold}')
                elif value >= warning_threshold:
                    await self._create_alert(alert_name, 'warning',
                                           f'{metric_name} is {value:.2f}, above warning threshold {warning_threshold}')

    async def _create_alert(self, title: str, severity: str, message: str):
        """Create a performance alert"""
        alert = {
            'id': f"alert_{int(time.time())}_{len(self.alerts)}",
            'title': title,
            'severity': severity,
            'message': message,
            'timestamp': time.time(),
            'acknowledged': False
        }

        self.alerts.append(alert)

        # Keep only recent alerts
        if len(self.alerts) > 100:
            self.alerts = self.alerts[-100:]

        logger.warning(f"Performance Alert [{severity.upper()}]: {title} - {message}")

    async def _open_browser(self):
        """Open browser to dashboard"""
        await asyncio.sleep(1.0)  # Wait for server to start
        webbrowser.open(f"http://localhost:{self.port}")

    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get current dashboard metrics"""
        current_metrics = {}

        for metric_name, history in self.metrics_history.items():
            if history:
                values = list(history)
                current_metrics[metric_name] = {
                    'value': values[-1],
                    'trend': values,
                    'status': self._get_metric_status(metric_name, values[-1])
                }

        return {
            'timestamp': time.time(),
            'overview': self._get_overview_metrics(),
            **current_metrics
        }

    def _get_overview_metrics(self) -> Dict[str, Any]:
        """Get overview metrics for dashboard"""
        overview = {}

        for metric_name, history in self.metrics_history.items():
            if history:
                values = list(history)
                overview[metric_name] = values[-1]

        return overview

    def _get_metric_status(self, metric_name: str, value: float) -> str:
        """Get status for a metric"""
        # Define thresholds for different metrics
        thresholds = {
            'cpu_usage': (80, 90),
            'memory_usage': (85, 95),
            'latency': (100, 200),
            'error_rate': (0.05, 0.1)
        }

        if metric_name in thresholds:
            warning_threshold, critical_threshold = thresholds[metric_name]
            if value >= critical_threshold:
                return 'critical'
            elif value >= warning_threshold:
                return 'warning'

        return 'normal'

    def get_dashboard_config(self) -> Dict[str, Any]:
        """Get dashboard configuration"""
        return {
            'widgets': [widget.to_dict() for widget in self.dashboard_widgets],
            'overview_metrics': ['cpu_usage', 'memory_usage', 'throughput', 'latency'],
            'refresh_interval': 2000,
            'alerts': self.alerts[-10:]  # Last 10 alerts
        }

    def export_dashboard_report(self, filepath: str):
        """Export dashboard data to file"""
        try:
            report_data = {
                'timestamp': time.time(),
                'metrics_history': {k: list(v) for k, v in self.metrics_history.items()},
                'alerts': self.alerts,
                'widgets': [widget.to_dict() for widget in self.dashboard_widgets]
            }

            path = Path(filepath)
            path.parent.mkdir(parents=True, exist_ok=True)

            with open(path, 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            logger.info(f"Dashboard report exported to {filepath}")

        except Exception as e:
            logger.error(f"Failed to export dashboard report: {e}")