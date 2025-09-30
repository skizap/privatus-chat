"""
Automated Security Monitoring and Alerting System for Privatus-chat

This module provides comprehensive security monitoring and alerting including:
- Real-time security event monitoring
- Anomaly detection and behavioral analysis
- Automated threat response
- Security metrics and dashboards
- Alert correlation and escalation
- Incident response automation
- Performance monitoring under security constraints
"""

import asyncio
import json
import logging
import statistics
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Callable
from pathlib import Path
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart
import requests
import psutil
import os

# Import security modules
try:
    from .audit_trail_manager import AuditTrailManager, AuditEventType, AuditSeverity
    from .vulnerability_scanner import VulnerabilityScanner
    from .enhanced_vulnerability_scanner import EnhancedVulnerabilityScanner
except ImportError:
    AuditTrailManager = None
    VulnerabilityScanner = None
    EnhancedVulnerabilityScanner = None


class AlertSeverity(Enum):
    """Alert severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(Enum):
    """Alert status."""

    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class MonitoringScope(Enum):
    """Monitoring scope levels."""

    APPLICATION = "application"
    NETWORK = "network"
    SYSTEM = "system"
    USER_BEHAVIOR = "user_behavior"
    COMPLIANCE = "compliance"


@dataclass
class SecurityAlert:
    """Security alert with detailed information."""

    alert_id: str
    timestamp: datetime
    severity: AlertSeverity
    title: str
    description: str
    source: str
    category: str
    affected_components: List[str] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)
    evidence: List[str] = field(default_factory=list)
    status: AlertStatus = AlertStatus.NEW
    assigned_to: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolution_notes: Optional[str] = None
    false_positive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to dictionary."""
        return {
            'alert_id': self.alert_id,
            'timestamp': self.timestamp.isoformat(),
            'severity': self.severity.value,
            'title': self.title,
            'description': self.description,
            'source': self.source,
            'category': self.category,
            'affected_components': self.affected_components,
            'indicators': self.indicators,
            'evidence': self.evidence,
            'status': self.status.value,
            'assigned_to': self.assigned_to,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'resolution_notes': self.resolution_notes,
            'false_positive': self.false_positive
        }


@dataclass
class SecurityMetric:
    """Security metric for monitoring."""

    name: str
    value: float
    timestamp: datetime
    unit: str = ""
    threshold: Optional[float] = None
    status: str = "normal"  # normal, warning, critical

    def to_dict(self) -> Dict[str, Any]:
        """Convert metric to dictionary."""
        return {
            'name': self.name,
            'value': self.value,
            'timestamp': self.timestamp.isoformat(),
            'unit': self.unit,
            'threshold': self.threshold,
            'status': self.status
        }


@dataclass
class AnomalyDetection:
    """Anomaly detection configuration."""

    metric_name: str
    baseline_window: int = 100  # Number of samples for baseline
    threshold_multiplier: float = 2.0  # Standard deviations
    min_samples: int = 10
    enabled: bool = True


class SecurityMonitor:
    """Comprehensive security monitoring and alerting system."""

    def __init__(self, audit_manager: Optional['AuditTrailManager'] = None):
        """
        Initialize security monitor.

        Args:
            audit_manager: Audit trail manager for event logging
        """
        self.audit_manager = audit_manager
        self.logger = logging.getLogger(__name__)

        # Alert management
        self.active_alerts: Dict[str, SecurityAlert] = {}
        self.alert_history: List[SecurityAlert] = []
        self.alert_callbacks: List[Callable[[SecurityAlert], None]] = []

        # Metrics collection
        self.security_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.metric_thresholds: Dict[str, float] = {}
        self.anomaly_detectors: Dict[str, AnomalyDetection] = {}

        # Monitoring configuration
        self.monitoring_enabled = True
        self.alert_cooldowns: Dict[str, datetime] = {}  # Prevent alert spam

        # Performance monitoring
        self.performance_baselines = {}
        self.resource_monitoring = True

        # Threat intelligence
        self.threat_indicators = self._load_threat_indicators()

        # Background monitoring tasks
        self._start_monitoring_tasks()

    def _load_threat_indicators(self) -> Dict[str, Any]:
        """Load threat intelligence indicators."""
        # In production, this would load from threat intelligence feeds
        return {
            'suspicious_ip_ranges': [],
            'known_malicious_patterns': [],
            'attack_signatures': {},
            'compromised_keys': set()
        }

    def register_alert_callback(self, callback: Callable[[SecurityAlert], None]):
        """Register callback for security alerts."""
        self.alert_callbacks.append(callback)

    def log_security_metric(self, name: str, value: float, unit: str = ""):
        """Log a security metric for monitoring."""
        metric = SecurityMetric(
            name=name,
            value=value,
            timestamp=datetime.now(),
            unit=unit
        )

        self.security_metrics[name].append(metric)

        # Check thresholds
        if name in self.metric_thresholds:
            threshold = self.metric_thresholds[name]
            if value > threshold:
                self._trigger_threshold_alert(name, value, threshold)

        # Anomaly detection
        if name in self.anomaly_detectors:
            self._check_for_anomalies(name, value)

    def _trigger_threshold_alert(self, metric_name: str, value: float, threshold: float):
        """Trigger alert when metric exceeds threshold."""
        alert_id = f"threshold_{metric_name}_{int(time.time())}"

        # Check cooldown to prevent spam
        cooldown_key = f"threshold_{metric_name}"
        if cooldown_key in self.alert_cooldowns:
            time_since_last = (datetime.now() - self.alert_cooldowns[cooldown_key]).total_seconds()
            if time_since_last < 300:  # 5 minute cooldown
                return

        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title=f"Security Metric Threshold Exceeded: {metric_name}",
            description=f"Metric {metric_name} value {value} exceeds threshold {threshold}",
            source="security_monitor",
            category="threshold_violation",
            indicators={'metric_name': metric_name, 'value': value, 'threshold': threshold}
        )

        self._raise_alert(alert)
        self.alert_cooldowns[cooldown_key] = datetime.now()

    def _check_for_anomalies(self, metric_name: str, value: float):
        """Check for anomalies in security metrics."""
        detector = self.anomaly_detectors[metric_name]

        if not detector.enabled or len(self.security_metrics[metric_name]) < detector.min_samples:
            return

        # Calculate baseline statistics
        recent_values = [m.value for m in list(self.security_metrics[metric_name])[-detector.baseline_window:]]
        mean_value = statistics.mean(recent_values)
        std_dev = statistics.stdev(recent_values) if len(recent_values) > 1 else 0

        # Check for anomaly
        threshold = mean_value + (detector.threshold_multiplier * std_dev)
        if value > threshold:
            alert_id = f"anomaly_{metric_name}_{int(time.time())}"

            alert = SecurityAlert(
                alert_id=alert_id,
                timestamp=datetime.now(),
                severity=AlertSeverity.MEDIUM,
                title=f"Anomaly Detected: {metric_name}",
                description=f"Unusual {metric_name} value detected: {value} (baseline: {mean_value:.2f})",
                source="anomaly_detector",
                category="behavioral_anomaly",
                indicators={
                    'metric_name': metric_name,
                    'value': value,
                    'baseline_mean': mean_value,
                    'baseline_std': std_dev,
                    'threshold': threshold
                }
            )

            self._raise_alert(alert)

    def monitor_authentication_events(self, events: List[Dict[str, Any]]):
        """Monitor authentication events for suspicious patterns."""
        if not events:
            return

        # Analyze authentication patterns
        recent_events = [e for e in events if e.get('event_type') == 'authentication_failure']

        if len(recent_events) >= 5:  # Multiple failures
            # Check for brute force patterns
            timestamps = [datetime.fromisoformat(e['timestamp']) for e in recent_events[-10:]]
            time_diffs = [(timestamps[i] - timestamps[i-1]).total_seconds()
                         for i in range(1, len(timestamps))]

            if time_diffs and statistics.mean(time_diffs) < 10:  # Less than 10 seconds between attempts
                self._trigger_brute_force_alert(recent_events)

    def _trigger_brute_force_alert(self, events: List[Dict[str, Any]]):
        """Trigger alert for brute force attack detection."""
        alert_id = f"brute_force_{int(time.time())}"

        # Extract attack details
        ip_addresses = list(set(e.get('ip_address', 'unknown') for e in events[-10:]))
        user_ids = list(set(e.get('user_id', 'unknown') for e in events[-10:]))

        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="Brute Force Attack Detected",
            description=f"Multiple authentication failures detected from {len(ip_addresses)} source(s)",
            source="authentication_monitor",
            category="authentication_attack",
            affected_components=["authentication_system"],
            indicators={
                'failure_count': len(events),
                'ip_addresses': ip_addresses,
                'target_users': user_ids,
                'time_window': str((datetime.now() - datetime.fromisoformat(events[0]['timestamp'])).total_seconds())
            },
            evidence=[f"Authentication failure from {e.get('ip_address', 'unknown')}" for e in events[-5:]]
        )

        self._raise_alert(alert)

    def monitor_network_traffic(self, traffic_data: Dict[str, Any]):
        """Monitor network traffic for security anomalies."""
        # Extract traffic metrics
        packets_per_second = traffic_data.get('packets_per_second', 0)
        bytes_per_second = traffic_data.get('bytes_per_second', 0)
        connection_count = traffic_data.get('connection_count', 0)

        # Log metrics
        self.log_security_metric('network_packets_per_second', packets_per_second, 'packets/s')
        self.log_security_metric('network_bytes_per_second', bytes_per_second, 'bytes/s')
        self.log_security_metric('network_connection_count', connection_count, 'connections')

        # Check for DDoS indicators
        if packets_per_second > 10000 or connection_count > 1000:
            self._trigger_ddos_alert(traffic_data)

    def _trigger_ddos_alert(self, traffic_data: Dict[str, Any]):
        """Trigger alert for potential DDoS attack."""
        alert_id = f"ddos_{int(time.time())}"

        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            severity=AlertSeverity.CRITICAL,
            title="Potential DDoS Attack Detected",
            description="Unusual network traffic patterns detected",
            source="network_monitor",
            category="dos_attack",
            affected_components=["network_layer"],
            indicators=traffic_data,
            evidence=[
                f"Packets/sec: {traffic_data.get('packets_per_second', 0)}",
                f"Connections: {traffic_data.get('connection_count', 0)}"
            ]
        )

        self._raise_alert(alert)

    def monitor_file_access(self, file_events: List[Dict[str, Any]]):
        """Monitor file access patterns for anomalies."""
        if not file_events:
            return

        # Analyze file access patterns
        access_by_user = defaultdict(int)
        access_by_file = defaultdict(int)

        for event in file_events:
            user_id = event.get('user_id', 'unknown')
            file_path = event.get('resource', 'unknown')

            access_by_user[user_id] += 1
            access_by_file[file_path] += 1

        # Check for suspicious patterns
        for user_id, access_count in access_by_user.items():
            if access_count > 100:  # Unusual number of file accesses
                self._trigger_suspicious_file_access_alert(user_id, access_count, file_events)

    def _trigger_suspicious_file_access_alert(self, user_id: str, access_count: int, events: List[Dict]):
        """Trigger alert for suspicious file access patterns."""
        alert_id = f"suspicious_access_{user_id}_{int(time.time())}"

        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            severity=AlertSeverity.MEDIUM,
            title=f"Suspicious File Access Pattern: {user_id}",
            description=f"User {user_id} accessed {access_count} files in short time period",
            source="file_monitor",
            category="suspicious_behavior",
            affected_components=["file_system"],
            indicators={'user_id': user_id, 'access_count': access_count},
            evidence=[f"Accessed: {e.get('resource', 'unknown')}" for e in events[-10:]]
        )

        self._raise_alert(alert)

    def monitor_system_resources(self):
        """Monitor system resources for security implications."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.log_security_metric('system_cpu_percent', cpu_percent, '%')

            # Memory usage
            memory = psutil.virtual_memory()
            self.log_security_metric('system_memory_percent', memory.percent, '%')

            # Disk usage
            disk = psutil.disk_usage('/')
            self.log_security_metric('system_disk_percent', disk.percent, '%')

            # Network connections
            connections = psutil.net_connections()
            self.log_security_metric('system_connection_count', len(connections), 'connections')

            # Check for resource exhaustion
            if memory.percent > 90 or disk.percent > 90:
                self._trigger_resource_exhaustion_alert(memory.percent, disk.percent)

        except Exception as e:
            self.logger.error(f"Error monitoring system resources: {e}")

    def _trigger_resource_exhaustion_alert(self, memory_percent: float, disk_percent: float):
        """Trigger alert for resource exhaustion."""
        alert_id = f"resource_exhaustion_{int(time.time())}"

        issues = []
        if memory_percent > 90:
            issues.append(f"High memory usage: {memory_percent}%")
        if disk_percent > 90:
            issues.append(f"High disk usage: {disk_percent}%")

        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            severity=AlertSeverity.HIGH,
            title="System Resource Exhaustion",
            description="System resources are critically low",
            source="resource_monitor",
            category="resource_exhaustion",
            affected_components=["system"],
            indicators={'memory_percent': memory_percent, 'disk_percent': disk_percent},
            evidence=issues
        )

        self._raise_alert(alert)

    def monitor_cryptographic_operations(self, crypto_events: List[Dict[str, Any]]):
        """Monitor cryptographic operations for security issues."""
        if not crypto_events:
            return

        # Analyze key usage patterns
        key_operations = [e for e in crypto_events if 'key' in e.get('action', '').lower()]

        if len(key_operations) > 50:  # Unusual key operation frequency
            self._trigger_cryptographic_anomaly_alert(key_operations)

    def _trigger_cryptographic_anomaly_alert(self, events: List[Dict]):
        """Trigger alert for cryptographic anomalies."""
        alert_id = f"crypto_anomaly_{int(time.time())}"

        alert = SecurityAlert(
            alert_id=alert_id,
            timestamp=datetime.now(),
            severity=AlertSeverity.MEDIUM,
            title="Cryptographic Operation Anomaly",
            description=f"Unusual cryptographic operation patterns detected",
            source="crypto_monitor",
            category="cryptographic_anomaly",
            affected_components=["crypto_system"],
            indicators={'operation_count': len(events)},
            evidence=[f"{e.get('action', 'unknown')} on {e.get('resource', 'unknown')}" for e in events[-5:]]
        )

        self._raise_alert(alert)

    def _raise_alert(self, alert: SecurityAlert):
        """Raise security alert and notify callbacks."""
        self.active_alerts[alert.alert_id] = alert
        self.alert_history.append(alert)

        # Log to audit trail
        if self.audit_manager:
            self.audit_manager.log_security_event(
                AuditEventType.INCIDENT_DETECTED,
                AuditSeverity.HIGH,
                alert.source,
                alert.title,
                alert.category,
                details=alert.indicators
            )

        # Notify callbacks
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                self.logger.error(f"Error in alert callback: {e}")

        self.logger.warning(f"Security Alert: {alert.title} - {alert.description}")

    def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Acknowledge a security alert."""
        if alert_id not in self.active_alerts:
            return False

        alert = self.active_alerts[alert_id]
        alert.status = AlertStatus.ACKNOWLEDGED
        alert.assigned_to = user_id

        return True

    def resolve_alert(self, alert_id: str, resolution_notes: str, user_id: str) -> bool:
        """Resolve a security alert."""
        if alert_id not in self.active_alerts:
            return False

        alert = self.active_alerts[alert_id]
        alert.status = AlertStatus.RESOLVED
        alert.resolved_at = datetime.now()
        alert.resolution_notes = resolution_notes
        alert.assigned_to = user_id

        # Remove from active alerts
        del self.active_alerts[alert_id]

        return True

    def mark_false_positive(self, alert_id: str, user_id: str) -> bool:
        """Mark alert as false positive."""
        if alert_id not in self.active_alerts:
            return False

        alert = self.active_alerts[alert_id]
        alert.status = AlertStatus.FALSE_POSITIVE
        alert.resolved_at = datetime.now()
        alert.assigned_to = user_id

        # Remove from active alerts
        del self.active_alerts[alert_id]

        return True

    def get_active_alerts(self) -> List[SecurityAlert]:
        """Get all active security alerts."""
        return list(self.active_alerts.values())

    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        total_alerts = len(self.alert_history)
        active_count = len(self.active_alerts)

        # Alerts by severity
        severity_counts = defaultdict(int)
        for alert in self.alert_history:
            severity_counts[alert.severity.value] += 1

        # Alerts by category
        category_counts = defaultdict(int)
        for alert in self.alert_history:
            category_counts[alert.category] += 1

        # Resolution statistics
        resolved_count = len([a for a in self.alert_history if a.status == AlertStatus.RESOLVED])
        false_positive_count = len([a for a in self.alert_history if a.status == AlertStatus.FALSE_POSITIVE])

        return {
            'total_alerts': total_alerts,
            'active_alerts': active_count,
            'resolved_alerts': resolved_count,
            'false_positives': false_positive_count,
            'alerts_by_severity': dict(severity_counts),
            'alerts_by_category': dict(category_counts),
            'average_resolution_time': self._calculate_average_resolution_time()
        }

    def _calculate_average_resolution_time(self) -> Optional[float]:
        """Calculate average time to resolve alerts."""
        resolved_alerts = [a for a in self.alert_history
                          if a.status == AlertStatus.RESOLVED and a.resolved_at]

        if not resolved_alerts:
            return None

        total_time = sum(
            (a.resolved_at - a.timestamp).total_seconds()
            for a in resolved_alerts
        )

        return total_time / len(resolved_alerts)

    def configure_anomaly_detection(self, metric_name: str, detector: AnomalyDetection):
        """Configure anomaly detection for a metric."""
        self.anomaly_detectors[metric_name] = detector

    def set_metric_threshold(self, metric_name: str, threshold: float):
        """Set threshold for security metric."""
        self.metric_thresholds[metric_name] = threshold

    def generate_security_dashboard_data(self) -> Dict[str, Any]:
        """Generate data for security dashboard."""
        # Get recent metrics
        recent_metrics = {}
        for metric_name, metrics in self.security_metrics.items():
            if metrics:
                recent_metrics[metric_name] = [m.to_dict() for m in list(metrics)[-50:]]  # Last 50 values

        # Get alert summary
        alert_summary = self.get_alert_statistics()

        # Get system health
        system_health = self._assess_system_health()

        return {
            'timestamp': datetime.now().isoformat(),
            'system_health': system_health,
            'recent_metrics': recent_metrics,
            'alert_summary': alert_summary,
            'active_alerts': [a.to_dict() for a in self.get_active_alerts()],
            'top_security_metrics': self._get_top_security_metrics()
        }

    def _assess_system_health(self) -> Dict[str, str]:
        """Assess overall system security health."""
        health_scores = {
            'authentication': 'good',
            'network': 'good',
            'cryptography': 'good',
            'compliance': 'good',
            'overall': 'good'
        }

        # Check recent alerts for health indicators
        recent_alerts = [a for a in self.alert_history[-100:] if a.timestamp > datetime.now() - timedelta(hours=1)]

        if len(recent_alerts) > 10:
            health_scores['overall'] = 'warning'
        if len([a for a in recent_alerts if a.severity == AlertSeverity.CRITICAL]) > 0:
            health_scores['overall'] = 'critical'

        return health_scores

    def _get_top_security_metrics(self) -> List[Dict[str, Any]]:
        """Get top security metrics for dashboard."""
        top_metrics = []

        for metric_name, metrics in self.security_metrics.items():
            if metrics:
                recent_values = [m.value for m in list(metrics)[-10:]]
                if recent_values:
                    avg_value = statistics.mean(recent_values)
                    top_metrics.append({
                        'name': metric_name,
                        'current_value': recent_values[-1],
                        'average_value': avg_value,
                        'trend': 'up' if recent_values[-1] > avg_value else 'down'
                    })

        # Sort by importance
        return sorted(top_metrics, key=lambda x: x['current_value'], reverse=True)[:10]

    def _start_monitoring_tasks(self):
        """Start background monitoring tasks."""
        # System resource monitoring
        def resource_monitoring_task():
            while self.monitoring_enabled:
                try:
                    self.monitor_system_resources()
                    time.sleep(30)  # Monitor every 30 seconds
                except Exception as e:
                    self.logger.error(f"Error in resource monitoring: {e}")
                    time.sleep(60)

        resource_thread = threading.Thread(target=resource_monitoring_task, daemon=True)
        resource_thread.start()

        # Alert cleanup task
        def alert_cleanup_task():
            while self.monitoring_enabled:
                try:
                    self._cleanup_old_alerts()
                    time.sleep(3600)  # Clean up every hour
                except Exception as e:
                    self.logger.error(f"Error in alert cleanup: {e}")
                    time.sleep(3600)

        cleanup_thread = threading.Thread(target=alert_cleanup_task, daemon=True)
        cleanup_thread.start()

    def _cleanup_old_alerts(self):
        """Clean up old resolved alerts."""
        cutoff_time = datetime.now() - timedelta(days=30)

        # Remove old resolved alerts from history
        self.alert_history = [
            alert for alert in self.alert_history
            if not (alert.status in [AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE] and
                   alert.resolved_at and alert.resolved_at < cutoff_time)
        ]

    def export_monitoring_data(self, format: str = 'json') -> str:
        """Export monitoring data for analysis."""
        if format == 'json':
            export_data = {
                'export_timestamp': datetime.now().isoformat(),
                'monitoring_enabled': self.monitoring_enabled,
                'active_alerts': [a.to_dict() for a in self.get_active_alerts()],
                'alert_statistics': self.get_alert_statistics(),
                'security_metrics': {
                    name: [m.to_dict() for m in list(metrics)[-100:]]
                    for name, metrics in self.security_metrics.items()
                },
                'anomaly_detectors': {
                    name: {
                        'enabled': detector.enabled,
                        'baseline_window': detector.baseline_window,
                        'threshold_multiplier': detector.threshold_multiplier
                    }
                    for name, detector in self.anomaly_detectors.items()
                }
            }

            return json.dumps(export_data, indent=2)

        return ""

    def stop_monitoring(self):
        """Stop all monitoring activities."""
        self.monitoring_enabled = False
        self.logger.info("Security monitoring stopped")


class AlertNotifier:
    """Handles security alert notifications."""

    def __init__(self, monitor: SecurityMonitor):
        self.monitor = monitor
        self.notification_channels = []

        # Register as alert callback
        monitor.register_alert_callback(self._handle_alert)

    def add_email_notification(self, smtp_server: str, smtp_port: int,
                             username: str, password: str, recipients: List[str]):
        """Add email notification channel."""
        self.notification_channels.append({
            'type': 'email',
            'config': {
                'smtp_server': smtp_server,
                'smtp_port': smtp_port,
                'username': username,
                'password': password,
                'recipients': recipients
            }
        })

    def add_webhook_notification(self, webhook_url: str, headers: Dict[str, str] = None):
        """Add webhook notification channel."""
        self.notification_channels.append({
            'type': 'webhook',
            'config': {
                'url': webhook_url,
                'headers': headers or {}
            }
        })

    def _handle_alert(self, alert: SecurityAlert):
        """Handle security alert notification."""
        for channel in self.notification_channels:
            try:
                if channel['type'] == 'email':
                    self._send_email_alert(alert, channel['config'])
                elif channel['type'] == 'webhook':
                    self._send_webhook_alert(alert, channel['config'])
            except Exception as e:
                self.monitor.logger.error(f"Error sending alert notification: {e}")

    def _send_email_alert(self, alert: SecurityAlert, config: Dict[str, Any]):
        """Send alert via email."""
        msg = MimeMultipart()
        msg['From'] = config['username']
        msg['To'] = ', '.join(config['recipients'])
        msg['Subject'] = f"Security Alert [{alert.severity.value.upper()}] {alert.title}"

        # Email body
        body = f"""
Security Alert Details:

Title: {alert.title}
Severity: {alert.severity.value.upper()}
Timestamp: {alert.timestamp.isoformat()}
Source: {alert.source}
Category: {alert.category}

Description:
{alert.description}

Affected Components:
{', '.join(alert.affected_components)}

Indicators:
{json.dumps(alert.indicators, indent=2)}

Evidence:
{chr(10).join(f"- {evidence}" for evidence in alert.evidence)}

Alert ID: {alert.alert_id}
        """

        msg.attach(MimeText(body, 'plain'))

        # Send email
        try:
            server = smtplib.SMTP(config['smtp_server'], config['smtp_port'])
            server.starttls()
            server.login(config['username'], config['password'])
            server.send_message(msg)
            server.quit()
        except Exception as e:
            self.monitor.logger.error(f"Failed to send email alert: {e}")

    def _send_webhook_alert(self, alert: SecurityAlert, config: Dict[str, Any]):
        """Send alert via webhook."""
        payload = {
            'alert': alert.to_dict(),
            'timestamp': datetime.now().isoformat()
        }

        try:
            response = requests.post(
                config['url'],
                json=payload,
                headers=config['headers'],
                timeout=10
            )

            if response.status_code != 200:
                self.monitor.logger.error(f"Webhook alert failed: {response.status_code}")

        except Exception as e:
            self.monitor.logger.error(f"Failed to send webhook alert: {e}")


class ThreatIntelligenceFeed:
    """Manages threat intelligence feeds."""

    def __init__(self, monitor: SecurityMonitor):
        self.monitor = monitor
        self.feeds = []
        self.last_update = None

    def add_threat_feed(self, feed_url: str, feed_type: str, update_interval: int = 3600):
        """Add threat intelligence feed."""
        self.feeds.append({
            'url': feed_url,
            'type': feed_type,
            'update_interval': update_interval,
            'last_update': None
        })

    async def update_feeds(self):
        """Update all threat intelligence feeds."""
        for feed in self.feeds:
            try:
                await self._update_feed(feed)
            except Exception as e:
                self.monitor.logger.error(f"Error updating threat feed {feed['url']}: {e}")

    async def _update_feed(self, feed: Dict[str, Any]):
        """Update individual threat feed."""
        # In production, would fetch and parse actual threat feeds
        # For now, simulate feed update

        feed['last_update'] = datetime.now()
        self.last_update = datetime.now()

        self.monitor.logger.info(f"Updated threat feed: {feed['url']}")


class AutomatedResponse:
    """Automated security response system."""

    def __init__(self, monitor: SecurityMonitor):
        self.monitor = monitor
        self.response_rules = []
        self.response_history = []

        # Register as alert callback
        monitor.register_alert_callback(self._handle_alert)

    def add_response_rule(self, condition: Callable[[SecurityAlert], bool],
                         action: Callable[[SecurityAlert], None], description: str):
        """Add automated response rule."""
        self.response_rules.append({
            'condition': condition,
            'action': action,
            'description': description,
            'enabled': True
        })

    def _handle_alert(self, alert: SecurityAlert):
        """Handle alert with automated responses."""
        for rule in self.response_rules:
            if not rule['enabled']:
                continue

            try:
                if rule['condition'](alert):
                    rule['action'](alert)
                    self.response_history.append({
                        'timestamp': datetime.now(),
                        'alert_id': alert.alert_id,
                        'rule_description': rule['description']
                    })
            except Exception as e:
                self.monitor.logger.error(f"Error in automated response: {e}")

    def get_response_statistics(self) -> Dict[str, Any]:
        """Get automated response statistics."""
        return {
            'total_responses': len(self.response_history),
            'active_rules': len([r for r in self.response_rules if r['enabled']]),
            'responses_by_rule': self._group_responses_by_rule()
        }

    def _group_responses_by_rule(self) -> Dict[str, int]:
        """Group response history by rule description."""
        rule_counts = defaultdict(int)
        for response in self.response_history:
            rule_counts[response['rule_description']] += 1
        return dict(rule_counts)