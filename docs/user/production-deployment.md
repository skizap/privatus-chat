# Production Deployment Guide

This document provides comprehensive instructions for deploying Privatus-chat in production environments, including server setup, configuration, scaling, and operational best practices.

## Overview

Privatus-chat can be deployed in various production configurations ranging from single-server installations to large-scale distributed deployments. This guide covers deployment strategies, system requirements, configuration management, and operational procedures.

## Deployment Architecture

### Single Server Deployment
```
┌─────────────────────────────────────┐
│           Privatus-chat Server      │
├─────────────────────────────────────┤
│  Web Application + API              │
│  Database (SQLite/PostgreSQL)       │
│  File Storage                       │
│  Cache (Redis/Memory)               │
│  Load Balancer (Optional)           │
└─────────────────────────────────────┘
```

### Distributed Deployment
```
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│  Load       │  │ Application │  │ Application │
│  Balancer   │  │ Server 1    │  │ Server 2    │
└─────────────┘  └─────────────┘  └─────────────┘
        │               │               │
        └───────────────┼───────────────┘
                        │
               ┌────────▼────────┐
               │   Database      │
               │   Cluster       │
               └─────────────────┘
```

## System Requirements

### Hardware Requirements

#### Minimum Requirements (Single Server)
- **CPU**: 2 cores (2.4 GHz or better)
- **RAM**: 4 GB
- **Storage**: 20 GB SSD
- **Network**: 100 Mbps

#### Recommended Requirements (Production)
- **CPU**: 4+ cores (3.0 GHz or better)
- **RAM**: 8 GB minimum, 16 GB recommended
- **Storage**: 100 GB NVMe SSD
- **Network**: 1 Gbps with low latency

#### High-Performance Deployment
- **CPU**: 8+ cores with AES-NI support
- **RAM**: 32 GB for large deployments
- **Storage**: 500 GB NVMe SSD in RAID configuration
- **Network**: 10 Gbps with RDMA support

### Software Requirements

#### Operating System
- **Linux**: Ubuntu 20.04+, CentOS 8+, Debian 11+
- **Container**: Docker 20.10+, Podman 4.0+
- **Orchestration**: Kubernetes 1.24+, Docker Swarm

#### Runtime Dependencies
- **Python**: 3.9+ with cryptography support
- **Database**: SQLite 3.35+ or PostgreSQL 13+
- **Web Server**: Nginx 1.20+ or Apache 2.4+
- **Cache**: Redis 6.0+ (optional)

## Installation and Setup

### Docker Deployment (Recommended)

#### Single Server Docker Compose
```yaml
version: '3.8'
services:
  privatus-chat:
    image: privatus-chat:latest
    ports:
      - "8080:8080"
      - "6881:6881/udp"
    environment:
      - DATABASE_URL=sqlite:///app/data/privatus.db
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY=your-secret-key-here
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

volumes:
  redis_data:
```

#### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: privatus-chat
spec:
  replicas: 3
  selector:
    matchLabels:
      app: privatus-chat
  template:
    metadata:
      labels:
        app: privatus-chat
    spec:
      containers:
      - name: privatus-chat
        image: privatus-chat:latest
        ports:
        - containerPort: 8080
        - containerPort: 6881
          protocol: UDP
        env:
        - name: DATABASE_URL
          value: "postgresql://user:pass@db:5432/privatus"
        - name: REDIS_URL
          value: "redis://redis:6379"
        volumeMounts:
        - name: config
          mountPath: /app/config
      volumes:
      - name: config
        configMap:
          name: privatus-config
```

### Manual Installation

#### System Package Installation
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3.9 python3.9-pip postgresql redis-server nginx

# CentOS/RHEL
sudo yum install python39 postgresql redis nginx
```

#### Application Setup
```bash
# Create application user
sudo useradd -r -s /bin/false privatus

# Create directories
sudo mkdir -p /opt/privatus-chat/{app,data,config,logs}
sudo chown -R privatus:privatus /opt/privatus-chat

# Clone repository
git clone https://github.com/privatus-chat/privatus-chat.git /opt/privatus-chat/app
cd /opt/privatus-chat/app

# Install dependencies
pip3 install -r requirements.txt

# Setup database
python3 setup_database.py

# Configure application
cp config/production.env config/.env
# Edit configuration as needed
```

## Configuration Management

### Environment Configuration

#### Production Environment Variables
```bash
# Database Configuration
DATABASE_URL=postgresql://privatus:secure_password@db:5432/privatus_prod
REDIS_URL=redis://redis:6379/1

# Security Configuration
SECRET_KEY=your-256-bit-secret-key-here
ENCRYPTION_MASTER_KEY=your-master-key-here

# Network Configuration
BIND_ADDRESS=0.0.0.0
PORT=8080
DHT_PORT=6881

# Performance Configuration
MAX_WORKERS=8
CACHE_SIZE=1GB
MAX_MESSAGE_SIZE=100MB

# Monitoring Configuration
LOG_LEVEL=INFO
METRICS_ENABLED=true
HEALTH_CHECK_PATH=/health
```

### Security Hardening

#### File Permissions
```bash
# Set secure permissions
sudo chown -R privatus:privatus /opt/privatus-chat
sudo chmod -R 750 /opt/privatus-chat
sudo chmod 600 /opt/privatus-chat/config/.env
sudo chmod 600 /opt/privatus-chat/data/*.db
```

#### Firewall Configuration
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow 6881/udp
sudo ufw --force enable

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --permanent --add-port=6881/udp
sudo firewall-cmd --reload
```

## Database Setup

### PostgreSQL Configuration

#### Production PostgreSQL Setup
```sql
-- Create production database
CREATE DATABASE privatus_prod
    WITH OWNER privatus
    ENCODING 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TEMPLATE = template0;

-- Configure for performance
ALTER DATABASE privatus_prod SET
    work_mem = '256MB',
    maintenance_work_mem = '512MB',
    effective_cache_size = '2GB',
    shared_buffers = '512MB';

-- Create user with limited permissions
CREATE USER privatus WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE privatus_prod TO privatus;
```

#### Connection Pooling (PgBouncer)
```ini
[databases]
privatus_prod = host=localhost port=5432 dbname=privatus_prod

[pgbouncer]
pool_mode = transaction
listen_port = 6432
listen_addr = *
auth_type = md5
auth_file = /etc/pgbouncer/userlist.txt

# Pool settings
max_client_conn = 1000
default_pool_size = 20
min_pool_size = 5
```

### Redis Configuration

#### Production Redis Setup
```bash
# Redis configuration (/etc/redis/redis.conf)
bind 127.0.0.1
port 6379
timeout 300
tcp-keepalive 300
daemonize yes
supervised systemd
loglevel notice
logfile /var/log/redis/redis-server.log

# Memory management
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence (if needed)
save 900 1
save 300 10
save 60 10000

# Security
requirepass your_secure_redis_password
rename-command FLUSHDB ""
rename-command FLUSHALL ""
```

## Load Balancing and Scaling

### Nginx Load Balancer Configuration
```nginx
upstream privatus_backend {
    least_conn;
    server app1:8080 max_fails=3 fail_timeout=30s;
    server app2:8080 max_fails=3 fail_timeout=30s;
    server app3:8080 max_fails=3 fail_timeout=30s;
}

server {
    listen 80;
    server_name chat.example.com;

    # Health checks
    location /health {
        proxy_pass http://privatus_backend/health;
        proxy_connect_timeout 5s;
        proxy_read_timeout 10s;
    }

    # API endpoints
    location /api/ {
        proxy_pass http://privatus_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket support for real-time features
    location /ws/ {
        proxy_pass http://privatus_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
```

### Horizontal Scaling

#### Application Server Scaling
```bash
# Systemd service for multiple instances
for i in {1..3}; do
    cat > /etc/systemd/system/privatus-chat@$i.service << EOF
[Unit]
Description=Privatus-chat Application Server %i
After=network.target postgresql.service redis.service

[Service]
Type=simple
User=privatus
WorkingDirectory=/opt/privatus-chat/app
EnvironmentFile=/opt/privatus-chat/config/.env
ExecStart=/usr/bin/python3 -m gunicorn app:app \
    --bind 0.0.0.0:8080 \
    --workers 4 \
    --worker-class eventlet \
    --max-requests 1000 \
    --max-requests-jitter 50 \
    --log-level info \
    --access-logfile /opt/privatus-chat/logs/access.log \
    --error-logfile /opt/privatus-chat/logs/error.log
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl enable privatus-chat@$i
    sudo systemctl start privatus-chat@$i
done
```

## Monitoring and Alerting

### Health Check Endpoints

#### Application Health Check
```python
@app.route('/health')
def health_check():
    checks = {
        'database': check_database_connection(),
        'redis': check_redis_connection(),
        'disk_space': check_disk_space(),
        'memory_usage': check_memory_usage(),
        'dht_status': check_dht_status()
    }

    all_healthy = all(checks.values())
    status_code = 200 if all_healthy else 503

    return jsonify({
        'status': 'healthy' if all_healthy else 'unhealthy',
        'timestamp': datetime.utcnow().isoformat(),
        'checks': checks
    }), status_code
```

#### DHT Health Check
```python
def check_dht_status():
    try:
        # Check DHT connectivity
        peers = dht_manager.get_connected_peers()
        return len(peers) >= MINIMUM_PEERS
    except Exception:
        return False
```

### Metrics Collection

#### Prometheus Metrics
```python
from prometheus_client import Counter, Histogram, Gauge

# Message metrics
messages_sent = Counter('privatus_messages_sent_total',
                       'Total messages sent', ['message_type'])
messages_received = Counter('privatus_messages_received_total',
                           'Total messages received', ['message_type'])

# Performance metrics
message_latency = Histogram('privatus_message_latency_seconds',
                           'Message processing latency')
active_connections = Gauge('privatus_active_connections',
                          'Number of active connections')

# DHT metrics
dht_peers = Gauge('privatus_dht_peers', 'Number of DHT peers')
dht_lookups = Counter('privatus_dht_lookups_total',
                     'Total DHT lookups', ['result'])
```

### Alerting Configuration

#### Alert Rules
```yaml
groups:
  - name: privatus-chat
    rules:
      - alert: HighErrorRate
        expr: rate(privatus_errors_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"

      - alert: DatabaseConnectionFailure
        expr: privatus_database_up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database connection lost"

      - alert: HighMemoryUsage
        expr: process_memory_usage > 0.9 * process_memory_limit
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage detected"
```

## Backup and Recovery

### Automated Backup Strategy

#### Database Backup
```bash
#!/bin/bash
# Daily database backup script

BACKUP_DIR="/opt/privatus-chat/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# PostgreSQL backup
pg_dump -h localhost -U privatus privatus_prod \
    | gzip > $BACKUP_DIR/db_backup_$DATE.sql.gz

# File storage backup
tar -czf $BACKUP_DIR/files_backup_$DATE.tar.gz \
    /opt/privatus-chat/data/files/

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -type f -mtime +30 -delete
```

#### Configuration Backup
```bash
#!/bin/bash
# Configuration backup script

CONFIG_DIR="/opt/privatus-chat/config"
BACKUP_DIR="/opt/privatus-chat/backups"

# Backup configuration files
tar -czf $BACKUP_DIR/config_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    $CONFIG_DIR/

# Backup SSL certificates
tar -czf $BACKUP_DIR/ssl_backup_$(date +%Y%m%d_%H%M%S).tar.gz \
    /etc/ssl/certs/privatus-chat*
```

### Recovery Procedures

#### Database Recovery
```bash
#!/bin/bash
# Database recovery script

LATEST_BACKUP=$(ls -t /opt/privatus-chat/backups/db_backup_*.sql.gz | head -1)

# Restore database
gunzip < $LATEST_BACKUP | psql -h localhost -U privatus privatus_prod

# Verify restoration
psql -h localhost -U privatus privatus_prod -c "SELECT COUNT(*) FROM contacts;"
```

#### Full System Recovery
```bash
#!/bin/bash
# Complete system recovery script

# Stop services
sudo systemctl stop privatus-chat@*

# Restore database
./restore_database.sh

# Restore configuration
./restore_config.sh

# Restore file storage
./restore_files.sh

# Start services
sudo systemctl start privatus-chat@*

# Verify system health
curl -f http://localhost:8080/health
```

## Security Hardening

### SSL/TLS Configuration

#### Nginx SSL Configuration
```nginx
server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate /etc/ssl/certs/privatus-chat.crt;
    ssl_certificate_key /etc/ssl/private/privatus-chat.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    # SSL security
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
}
```

### SELinux/AppArmor Configuration

#### AppArmor Profile
```apparmor
#include <tunables/global>

/opt/privatus-chat/app {
  #include <abstractions/base>
  #include <abstractions/python>

  /opt/privatus-chat/app/** r,
  /opt/privatus-chat/data/** rw,
  /opt/privatus-chat/config/** r,
  /opt/privatus-chat/logs/** rw,

  # Network access
  network inet dgram,
  network inet stream,

  # Deny dangerous operations
  deny /bin/** w,
  deny /sbin/** w,
  deny /usr/bin/** w,
  deny /usr/sbin/** w,
}
```

## Performance Tuning

### System Optimization

#### Kernel Tuning
```bash
# /etc/sysctl.conf optimizations

# Network performance
net.core.somaxconn = 65536
net.ipv4.tcp_max_syn_backlog = 65536
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 300

# Memory management
vm.swappiness = 10
vm.dirty_ratio = 10
vm.dirty_background_ratio = 5

# File system
fs.file-max = 2097152
```

#### Application Tuning
```python
# Gunicorn configuration for production
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "eventlet"
max_requests = 1000
max_requests_jitter = 50
keepalive = 2
timeout = 30
```

### Database Optimization

#### PostgreSQL Tuning
```sql
-- Production PostgreSQL configuration
ALTER SYSTEM SET shared_buffers = '512MB';
ALTER SYSTEM SET effective_cache_size = '2GB';
ALTER SYSTEM SET work_mem = '256MB';
ALTER SYSTEM SET maintenance_work_mem = '512MB';
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;
ALTER SYSTEM SET random_page_cost = 1.1;
ALTER SYSTEM SET effective_io_concurrency = 200;
```

## Operational Procedures

### Deployment Process

#### Rolling Deployment
```bash
#!/bin/bash
# Rolling deployment script

# Deploy to first half of servers
for server in app1 app2; do
    echo "Deploying to $server"
    ssh $server 'cd /opt/privatus-chat && git pull && pip install -r requirements.txt'
    ssh $server 'sudo systemctl reload privatus-chat@1 privatus-chat@2'
done

# Wait for health checks
sleep 30

# Deploy to second half
for server in app3 app4; do
    echo "Deploying to $server"
    ssh $server 'cd /opt/privatus-chat && git pull && pip install -r requirements.txt'
    ssh $server 'sudo systemctl reload privatus-chat@1 privatus-chat@2'
done
```

### Log Management

#### Log Rotation
```bash
# Logrotate configuration
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

#### Centralized Logging
```yaml
# Fluentd configuration for log aggregation
<source>
  @type tail
  path /opt/privatus-chat/logs/*.log
  pos_file /var/log/fluentd/privatus.pos
  tag privatus.application
  <parse>
    @type json
  </parse>
</source>

<match privatus.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name privatus-${tag}
</match>
```

## Troubleshooting

### Common Deployment Issues

#### Database Connection Issues
**Symptoms**: Application fails to start, database errors in logs
**Solutions**:
- Verify database server is running
- Check connection credentials
- Ensure database user has proper permissions
- Review firewall and network configuration

#### Performance Issues
**Symptoms**: Slow response times, high CPU/memory usage
**Solutions**:
- Monitor system resources
- Check database query performance
- Review application logs for bottlenecks
- Scale horizontally if needed

#### DHT Connectivity Issues
**Symptoms**: Cannot discover peers, connection failures
**Solutions**:
- Verify UDP port accessibility
- Check bootstrap node configuration
- Monitor network connectivity
- Review DHT statistics

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily Tasks
- Review application logs for errors
- Check system resource usage
- Verify backup completion
- Monitor security events

#### Weekly Tasks
- Review performance metrics
- Check disk space usage
- Update security patches
- Test backup restoration

#### Monthly Tasks
- Database optimization and maintenance
- Security audit and review
- Capacity planning and scaling review
- Documentation updates

### Emergency Procedures

#### Service Restoration
```bash
#!/bin/bash
# Emergency service restoration

# Check system health
if curl -f http://localhost:8080/health; then
    echo "Service is healthy"
    exit 0
fi

# Restart services
sudo systemctl restart privatus-chat@*

# Wait for startup
sleep 30

# Verify health
if curl -f http://localhost:8080/health; then
    echo "Service restored successfully"
else
    echo "Service restoration failed"
    # Escalate to on-call engineer
fi
```

## Support and Monitoring

### Monitoring Dashboard

#### Key Metrics to Monitor
- **Application Health**: Response time, error rate, uptime
- **System Resources**: CPU, memory, disk, network usage
- **Database Performance**: Query time, connection count, cache hit rate
- **DHT Health**: Peer count, lookup success rate, network latency
- **Security Events**: Failed logins, suspicious activity, audit events

### Support Escalation

#### Level 1: Self-Service
- Check status page and health endpoints
- Review application and system logs
- Verify configuration and environment
- Test basic connectivity

#### Level 2: Application Support
- Database connection and query issues
- Application configuration problems
- Performance and scaling issues
- Integration and API problems

#### Level 3: Infrastructure Support
- System-level issues and failures
- Network and security problems
- Hardware and platform issues
- Disaster recovery situations

## Conclusion

This production deployment guide provides comprehensive instructions for deploying and operating Privatus-chat in production environments. The guide covers system requirements, installation procedures, configuration management, monitoring, and operational best practices.

Successful production deployment requires careful planning, proper configuration, and ongoing maintenance. Regular monitoring, security updates, and performance optimization ensure reliable and secure operation.

---

*Last updated: January 2025*
*Version: 1.0.0*