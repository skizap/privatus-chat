# Monitoring and Alerting Setup Guide

This document provides comprehensive instructions for setting up monitoring, alerting, and observability for Privatus-chat in production environments.

## Overview

Effective monitoring and alerting are critical for maintaining Privatus-chat's reliability, performance, and security. This guide covers metrics collection, log aggregation, alerting rules, and dashboard configuration.

## Monitoring Architecture

### Components Overview
```
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Application   │  │   System        │  │   External      │
│   Metrics       │  │   Metrics       │  │   Services      │
└─────────────────┘  └─────────────────┘  └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                        ┌─────────────────┐
                        │   Metrics       │
                        │   Collector     │
                        │   (Prometheus)  │
                        └─────────────────┘
                                 │
         ┌───────────────────────┼───────────────────────┐
         │                       │                       │
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Log           │  │   Alert         │  │   Visualization │
│   Aggregation   │  │   Manager       │  │   Dashboard     │
│   (ELK Stack)   │  │   (Alertmanager)│  │   (Grafana)     │
└─────────────────┘  └─────────────────┘  └─────────────────┘
```

## Metrics Collection

### Application Metrics

#### Core Application Metrics
```python
from prometheus_client import Counter, Histogram, Gauge, Info

# Application information
app_info = Info('privatus_app', 'Application information')
app_info.info({
    'version': '1.0.0',
    'environment': 'production'
})

# Message metrics
messages_sent = Counter(
    'privatus_messages_sent_total',
    'Total number of messages sent',
    ['message_type', 'status']
)

messages_received = Counter(
    'privatus_messages_received_total',
    'Total number of messages received',
    ['message_type', 'status']
)

# Performance metrics
message_processing_time = Histogram(
    'privatus_message_processing_seconds',
    'Time spent processing messages',
    ['operation']
)

active_connections = Gauge(
    'privatus_active_connections',
    'Number of active connections',
    ['connection_type']
)

# Error metrics
errors_total = Counter(
    'privatus_errors_total',
    'Total number of errors',
    ['error_type', 'component']
)
```

#### DHT Metrics
```python
# DHT performance metrics
dht_peers_connected = Gauge(
    'privatus_dht_peers_connected',
    'Number of DHT peers connected'
)

dht_lookup_duration = Histogram(
    'privatus_dht_lookup_duration_seconds',
    'Time taken for DHT lookups'
)

dht_routing_table_size = Gauge(
    'privatus_dht_routing_table_size',
    'Size of DHT routing table'
)

dht_bootstrap_success = Counter(
    'privatus_dht_bootstrap_success_total',
    'Successful DHT bootstrap operations'
)
```

#### Storage Metrics
```python
# Database metrics
database_connections = Gauge(
    'privatus_db_connections',
    'Number of database connections',
    ['state']
)

database_query_duration = Histogram(
    'privatus_db_query_duration_seconds',
    'Database query execution time'
)

# Cache metrics
cache_operations = Counter(
    'privatus_cache_operations_total',
    'Cache operations',
    ['operation', 'status']
)

cache_size = Gauge(
    'privatus_cache_size_bytes',
    'Cache size in bytes',
    ['cache_type']
)
```

### System Metrics

#### Resource Utilization
```bash
# Prometheus node exporter configuration
scrape_configs:
  - job_name: 'node'
    static_configs:
      - targets: ['localhost:9100']
    scrape_interval: 15s
```

#### Key System Metrics
- **CPU Usage**: Per-core and overall utilization
- **Memory Usage**: RAM consumption and availability
- **Disk I/O**: Read/write operations and throughput
- **Network Traffic**: Bandwidth usage and error rates
- **File System**: Disk space and inode usage

## Log Aggregation

### Application Logging

#### Structured Logging Configuration
```python
import logging.config
import json

LOGGING_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            'format': json.dumps({
                'timestamp': '%(asctime)s',
                'level': '%(levelname)s',
                'logger': '%(name)s',
                'message': '%(message)s',
                'module': '%(module)s',
                'function': '%(funcName)s',
                'line': '%(lineno)d',
                'thread': '%(thread)d',
                'process': '%(process)d'
            })
        }
    },
    'handlers': {
        'file': {
            'class': 'logging.FileHandler',
            'filename': '/var/log/privatus-chat/app.log',
            'formatter': 'json'
        }
    },
    'loggers': {
        'privatus': {
            'handlers': ['file'],
            'level': 'INFO',
            'propagate': False
        }
    }
}
```

#### Log Levels and Categories
- **ERROR**: Critical errors requiring immediate attention
- **WARNING**: Issues that may impact functionality
- **INFO**: General operational information
- **DEBUG**: Detailed debugging information

### Log Aggregation with ELK Stack

#### Elasticsearch Configuration
```yaml
# elasticsearch.yml
cluster.name: privatus-chat-logs
node.name: log-node-1

path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

network.host: 0.0.0.0
http.port: 9200

# Security
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true

# Performance
indices.query.bool.max_clause_count: 10000
search.max_buckets: 100000
```

#### Logstash Pipeline Configuration
```conf
# logstash.conf
input {
  file {
    path => "/var/log/privatus-chat/*.log"
    start_position => "beginning"
    codec => "json"
  }
}

filter {
  json {
    source => "message"
  }

  mutate {
    add_field => {
      "log_type" => "application"
      "service" => "privatus-chat"
    }
  }

  date {
    match => ["timestamp", "ISO8601"]
    target => "@timestamp"
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "privatus-logs-%{+YYYY.MM.dd}"
  }
}
```

#### Kibana Dashboard Setup
```json
{
  "title": "Privatus-chat Overview",
  "panels": [
    {
      "type": "gauge",
      "title": "Active Connections",
      "targets": [
        {
          "expr": "privatus_active_connections",
          "refId": "A"
        }
      ]
    },
    {
      "type": "graph",
      "title": "Message Throughput",
      "targets": [
        {
          "expr": "rate(privatus_messages_sent_total[5m])",
          "refId": "A"
        }
      ]
    }
  ]
}
```

## Alerting System

### Alert Manager Configuration

#### Alert Rules
```yaml
groups:
  - name: privatus-chat
    rules:
      # Critical alerts
      - alert: DatabaseDown
        expr: up{job="database"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database is down"
          description: "Database has been down for more than 1 minute"

      - alert: HighErrorRate
        expr: rate(privatus_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          description: "Error rate is above 10% for 5 minutes"

      # Performance alerts
      - alert: HighLatency
        expr: privatus_message_processing_seconds{quantile="0.95"} > 2
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "High message processing latency"
          description: "95th percentile latency above 2 seconds"

      # Security alerts
      - alert: FailedAuthentications
        expr: increase(privatus_failed_authentications_total[5m]) > 10
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Multiple failed authentication attempts"
          description: "More than 10 failed logins in 5 minutes"
```

#### Notification Channels
```yaml
route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'default-receiver'

receivers:
  - name: 'default-receiver'
    email_configs:
      - to: 'ops@privatus-chat.org'
        from: 'alerts@privatus-chat.org'
        smarthost: 'smtp.example.com:587'
        auth_username: 'alerts@privatus-chat.org'
        auth_password: 'secure-password'

  - name: 'critical-alerts'
    slack_configs:
      - api_url: 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
        channel: '#critical-alerts'
        title: 'Critical Alert'
        text: '{{ .CommonAnnotations.summary }}'
```

### Custom Alerting Logic

#### Security Event Correlation
```python
def detect_suspicious_activity():
    """Detect patterns of suspicious behavior"""

    # Check for multiple failed logins from same IP
    failed_logins = redis.get('failed_logins_last_hour')
    if failed_logins > 50:
        trigger_alert('BRUTE_FORCE_ATTACK', {
            'failed_attempts': failed_logins,
            'time_window': '1_hour'
        })

    # Check for unusual message patterns
    message_rate = get_message_rate()
    if message_rate > normal_rate * 10:
        trigger_alert('MESSAGE_FLOOD', {
            'rate': message_rate,
            'threshold': normal_rate * 10
        })
```

## Dashboard Configuration

### Grafana Dashboard Setup

#### Main Overview Dashboard
```json
{
  "dashboard": {
    "title": "Privatus-chat Overview",
    "panels": [
      {
        "title": "Active Users",
        "type": "stat",
        "targets": [
          {
            "expr": "privatus_active_connections",
            "refId": "A"
          }
        ]
      },
      {
        "title": "Message Throughput",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(privatus_messages_sent_total[5m])",
            "refId": "A"
          },
          {
            "expr": "rate(privatus_messages_received_total[5m])",
            "refId": "B"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(privatus_errors_total[5m])",
            "refId": "A"
          }
        ]
      },
      {
        "title": "DHT Health",
        "type": "stat",
        "targets": [
          {
            "expr": "privatus_dht_peers_connected",
            "refId": "A"
          }
        ]
      }
    ]
  }
}
```

#### Performance Dashboard
```json
{
  "dashboard": {
    "title": "Performance Monitoring",
    "panels": [
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(privatus_message_processing_seconds_bucket[5m]))",
            "refId": "A"
          }
        ]
      },
      {
        "title": "Database Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "privatus_db_query_duration_seconds",
            "refId": "A"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "process_memory_usage",
            "refId": "A"
          }
        ]
      }
    ]
  }
}
```

## Health Checks

### Application Health Checks

#### Basic Health Check
```python
@app.route('/health')
def health_check():
    checks = {
        'database': check_database(),
        'redis': check_redis(),
        'dht': check_dht(),
        'disk_space': check_disk_space(),
        'memory': check_memory()
    }

    status_code = 200 if all(checks.values()) else 503

    return jsonify({
        'status': 'healthy' if status_code == 200 else 'unhealthy',
        'timestamp': datetime.utcnow().isoformat(),
        'checks': checks
    }), status_code
```

#### Detailed Health Check
```python
@app.route('/health/detailed')
def detailed_health_check():
    return jsonify({
        'application': {
            'version': get_version(),
            'uptime': get_uptime(),
            'active_connections': get_active_connections()
        },
        'database': {
            'connection_pool': get_db_connection_info(),
            'query_performance': get_query_stats()
        },
        'dht': {
            'connected_peers': get_dht_peer_count(),
            'routing_table_size': get_routing_table_size()
        },
        'system': {
            'cpu_usage': get_cpu_usage(),
            'memory_usage': get_memory_usage(),
            'disk_usage': get_disk_usage()
        }
    })
```

### External Monitoring Integration

#### Kubernetes Health Checks
```yaml
apiVersion: v1
kind: Pod
spec:
  containers:
  - name: privatus-chat
    livenessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 30
      periodSeconds: 10
      timeoutSeconds: 5
      failureThreshold: 3
    readinessProbe:
      httpGet:
        path: /health
        port: 8080
      initialDelaySeconds: 5
      periodSeconds: 5
      timeoutSeconds: 3
      failureThreshold: 3
```

## Real-time Monitoring

### Metrics Collection Setup

#### Prometheus Configuration
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'privatus-chat'
    static_configs:
      - targets: ['privatus-chat:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'node'
    static_configs:
      - targets: ['node-exporter:9100']
    scrape_interval: 30s

  - job_name: 'database'
    static_configs:
      - targets: ['postgres-exporter:9187']
    scrape_interval: 30s
```

#### Metrics Endpoints
```python
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

@app.route('/metrics')
def metrics():
    return generate_latest(), 200, {'Content-Type': CONTENT_TYPE_LATEST}
```

### Log Streaming

#### Fluentd Configuration
```xml
<source>
  @type tail
  path /var/log/privatus-chat/*.log
  pos_file /var/log/fluentd/privatus.log.pos
  tag privatus.application
  <parse>
    @type json
  </parse>
</source>

<match privatus.**>
  @type stdout
</match>
```

## Alert Response Procedures

### Alert Classification

#### Critical Alerts (P0)
- **Database failures**: Immediate response required
- **Security breaches**: Immediate security team notification
- **Service downtime**: Automated failover procedures
- **Data loss**: Emergency backup restoration

#### High Priority Alerts (P1)
- **Performance degradation**: Investigation within 1 hour
- **High error rates**: Analysis and resolution within 4 hours
- **Resource exhaustion**: Capacity planning review
- **Security events**: Security team review

#### Medium Priority Alerts (P2)
- **Warning conditions**: Review within 24 hours
- **Minor performance issues**: Scheduled optimization
- **Resource warnings**: Capacity planning
- **Configuration issues**: Scheduled fixes

### Escalation Procedures

#### Automated Escalation
```python
def handle_critical_alert(alert):
    """Handle critical system alerts"""

    # Immediate notification
    notify_on_call_engineer(alert)

    # Automated response
    if alert.type == 'DATABASE_DOWN':
        trigger_database_failover()

    elif alert.type == 'HIGH_MEMORY_USAGE':
        trigger_memory_cleanup()

    # Log incident
    log_incident(alert, 'AUTOMATED_RESPONSE')
```

#### Manual Escalation Process
1. **Initial Detection**: Alert triggered by monitoring system
2. **Triage**: On-call engineer assesses severity
3. **Investigation**: Detailed analysis of root cause
4. **Resolution**: Implement fix or workaround
5. **Post-Mortem**: Document incident and lessons learned

## Monitoring Best Practices

### Metrics Collection Guidelines
1. **Relevant Metrics**: Collect only actionable metrics
2. **Cardinality Management**: Avoid high-cardinality labels
3. **Retention Policies**: Configure appropriate data retention
4. **Performance Impact**: Minimize monitoring overhead

### Alerting Best Practices
1. **Actionable Alerts**: Every alert should require action
2. **Alert Fatigue Prevention**: Avoid noisy or redundant alerts
3. **Escalation Paths**: Clear escalation procedures
4. **False Positive Reduction**: Tune thresholds carefully

### Dashboard Design Principles
1. **Information Hierarchy**: Most important info first
2. **Context Preservation**: Show trends and baselines
3. **Drill-Down Capability**: Enable detailed investigation
4. **Mobile Responsiveness**: Accessible on mobile devices

## Integration with External Systems

### PagerDuty Integration
```python
from pdpyras import EventsAPISession

def trigger_pagerduty_alert(alert):
    """Send alert to PagerDuty"""

    session = EventsAPISession('your-routing-key')

    session.trigger(
        summary=alert.title,
        source='Privatus-chat',
        severity=alert.severity,
        component='application',
        group='infrastructure',
        class='system'
    )
```

### Slack Notifications
```python
import requests

def send_slack_notification(alert):
    """Send alert to Slack"""

    payload = {
        'channel': '#alerts',
        'username': 'Privatus-chat Monitor',
        'icon_emoji': ':warning:',
        'attachments': [{
            'color': get_color_for_severity(alert.severity),
            'title': alert.title,
            'text': alert.description,
            'fields': [
                {
                    'title': 'Severity',
                    'value': alert.severity,
                    'short': True
                },
                {
                    'title': 'Component',
                    'value': alert.component,
                    'short': True
                }
            ]
        }]
    }

    requests.post('https://hooks.slack.com/services/YOUR/WEBHOOK/URL',
                 json=payload)
```

## Maintenance and Troubleshooting

### Monitoring System Maintenance

#### Regular Tasks
- **Metrics validation**: Ensure all metrics are being collected
- **Alert testing**: Regular alert rule validation
- **Dashboard updates**: Keep dashboards current and relevant
- **Performance review**: Monitor monitoring system performance

#### Troubleshooting Common Issues
- **Missing metrics**: Check application health and configuration
- **False alerts**: Review and adjust alert thresholds
- **Performance impact**: Optimize metric collection frequency
- **Storage growth**: Implement proper data retention policies

### Log Management

#### Log Rotation
```bash
# Logrotate configuration for application logs
/var/log/privatus-chat/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 privatus privatus
    postrotate
        systemctl reload privatus-chat
    endscript
}
```

#### Log Analysis
```bash
# Common log analysis commands

# Error rate analysis
grep "ERROR" /var/log/privatus-chat/app.log | wc -l

# Top error types
grep "ERROR" /var/log/privatus-chat/app.log | \
    cut -d' ' -f3- | sort | uniq -c | sort -nr

# Performance analysis
grep "processing_seconds" /var/log/privatus-chat/app.log | \
    awk '{sum+=$NF} END {print "Average: " sum/NR}'
```

## Security Monitoring

### Security Event Detection

#### Authentication Monitoring
```python
def monitor_authentication_events():
    """Monitor for suspicious authentication patterns"""

    # Track failed login attempts
    failed_logins = redis.get('failed_logins_1h', 0)

    if failed_logins > 50:
        trigger_alert('BRUTE_FORCE_SUSPICION', {
            'failed_attempts': failed_logins,
            'time_window': '1_hour'
        })

    # Track unusual login patterns
    login_rate = get_login_rate()
    if login_rate > baseline_rate * 5:
        trigger_alert('UNUSUAL_LOGIN_ACTIVITY', {
            'rate': login_rate,
            'baseline': baseline_rate
        })
```

#### Network Security Monitoring
```python
def monitor_network_security():
    """Monitor network-level security events"""

    # Detect unusual connection patterns
    connection_rate = get_connection_rate()

    if connection_rate > normal_rate * 10:
        trigger_alert('CONNECTION_FLOOD', {
            'rate': connection_rate,
            'threshold': normal_rate * 10
        })

    # Monitor for known malicious IPs
    malicious_connections = check_malicious_ips()

    if malicious_connections > 0:
        trigger_alert('MALICIOUS_CONNECTION', {
            'count': malicious_connections,
            'source_ips': get_malicious_ip_list()
        })
```

## Performance Monitoring

### Application Performance Monitoring

#### Custom Performance Metrics
```python
# Message processing performance
message_processing_timer = Histogram(
    'privatus_message_processing_duration_seconds',
    'Message processing time',
    ['message_type', 'operation']
)

# Database performance
db_query_timer = Histogram(
    'privatus_db_query_duration_seconds',
    'Database query execution time',
    ['query_type', 'table']
)

# Cache performance
cache_operation_timer = Histogram(
    'privatus_cache_operation_duration_seconds',
    'Cache operation time',
    ['operation', 'cache_type']
)
```

### Infrastructure Monitoring

#### System Resource Monitoring
```bash
# CPU monitoring
mpstat 1 10

# Memory monitoring
free -h

# Disk I/O monitoring
iostat -x 1 10

# Network monitoring
iftop -i eth0
```

#### Database Performance Monitoring
```sql
-- Query performance analysis
SELECT query, calls, total_time, mean_time
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;

-- Connection monitoring
SELECT state, count(*) FROM pg_stat_activity
GROUP BY state;

-- Table bloat analysis
SELECT schemaname, tablename,
       pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;
```

## Conclusion

This monitoring and alerting setup provides comprehensive observability for Privatus-chat, enabling proactive issue detection, rapid incident response, and continuous performance optimization. The system combines application metrics, system monitoring, log aggregation, and intelligent alerting to ensure reliable operation.

Regular review and tuning of monitoring configuration ensures the system remains effective as the application evolves and scales.

---

*Last updated: January 2025*
*Version: 1.0.0*