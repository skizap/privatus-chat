# Comprehensive Docker Deployment Guide

This guide provides detailed instructions for deploying Privatus-chat using Docker and container orchestration technologies. It covers everything from basic Docker usage to advanced production deployments with Kubernetes and Docker Swarm.

## Table of Contents

- [Quick Start](#quick-start)
- [Docker Images](#docker-images)
- [Docker Compose Deployment](#docker-compose-deployment)
- [Production Deployment](#production-deployment)
- [Container Orchestration](#container-orchestration)
- [Monitoring and Logging](#monitoring-and-logging)
- [Security Hardening](#security-hardening)
- [Performance Optimization](#performance-optimization)
- [Troubleshooting](#troubleshooting)
- [Advanced Configuration](#advanced-configuration)

## Quick Start

### Basic Docker Run

```bash
# Pull the latest image
docker pull privatus-chat/privatus-chat:latest

# Run with basic configuration
docker run -d \
  --name privatus-chat \
  -p 8080:8080 \
  -p 8000-9000:8000-9000 \
  -v privatus_data:/app/data \
  -e SECRET_KEY="your-secret-key-here" \
  privatus-chat/privatus-chat:latest
```

### Docker Compose Quick Start

```bash
# Clone the repository
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat

# Start all services
docker-compose -f deployment/docker-compose.yml up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f privatus-chat
```

## Docker Images

### Available Image Variants

#### Production Image
```bash
docker pull privatus-chat/privatus-chat:latest
# or specific version
docker pull privatus-chat/privatus-chat:v3.0.0
```

#### Development Image
```bash
docker pull privatus-chat/privatus-chat:development
```

#### Multi-Stage Build Features

The Docker images use multi-stage builds for optimal size and security:

- **Builder Stage**: Compiles Python extensions and installs build dependencies
- **Production Stage**: Minimal runtime image with only necessary components
- **Development Stage**: Includes development tools and debugging utilities

### Custom Image Building

#### Build Production Image
```bash
# Build production image
docker build \
  -f deployment/Dockerfile.multistage \
  --target production \
  -t privatus-chat:production \
  .

# Build with specific features
docker build \
  --build-arg ENABLE_FEATURES="file_transfer,voice_calls,performance_monitoring" \
  -t privatus-chat:full \
  .
```

#### Build Development Image
```bash
# Build development image
docker build \
  -f deployment/Dockerfile.multistage \
  --target development \
  -t privatus-chat:dev \
  .

# Run development container with volume mount
docker run -d \
  --name privatus-dev \
  -p 8001:8000 \
  -v $(pwd):/app \
  -v privatus_dev_data:/app/data \
  privatus-chat:dev
```

## Docker Compose Deployment

### Single Server Deployment

#### Basic Single Server Setup
```yaml
version: '3.8'
services:
  privatus-chat:
    image: privatus-chat:latest
    ports:
      - "8080:8080"
      - "8000-9000:8000-9000"
    environment:
      - DATABASE_URL=sqlite:///app/data/privatus.db
      - SECRET_KEY=your-secret-key-here
      - LOG_LEVEL=INFO
    volumes:
      - privatus_data:/app/data
    restart: unless-stopped

volumes:
  privatus_data:
```

#### Full Stack Deployment
```yaml
version: '3.8'
services:
  privatus-chat:
    image: privatus-chat:latest
    depends_on:
      - redis
      - postgres
    environment:
      - DATABASE_URL=postgresql://privatus:password@postgres:5432/privatus
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY=your-secret-key-here
    volumes:
      - privatus_data:/app/data
      - ./config:/app/config:ro

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass your_secure_password
    volumes:
      - redis_data:/data

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=privatus
      - POSTGRES_USER=privatus
      - POSTGRES_PASSWORD=your_secure_password
    volumes:
      - postgres_data:/var/lib/postgresql/data

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - privatus-chat

volumes:
  privatus_data:
  redis_data:
  postgres_data:
```

### Multi-Server Deployment

#### Load Balanced Setup
```yaml
version: '3.8'
services:
  # Load balancer
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - app1
      - app2
      - app3

  # Application servers
  app1:
    image: privatus-chat:latest
    environment:
      - NODE_ID=app1
      - CLUSTER_NODES=app1,app2,app3

  app2:
    image: privatus-chat:latest
    environment:
      - NODE_ID=app2
      - CLUSTER_NODES=app1,app2,app3

  app3:
    image: privatus-chat:latest
    environment:
      - NODE_ID=app3
      - CLUSTER_NODES=app1,app2,app3

  # Shared database
  postgres:
    image: postgres:15-alpine
    volumes:
      - postgres_data:/var/lib/postgresql/data

  # Shared Redis cluster
  redis-cluster:
    image: redis:7-alpine
    command: redis-cli --cluster create redis1:6379 redis2:6379 redis3:6379 --cluster-replicas 0

volumes:
  postgres_data:
```

## Production Deployment

### High Availability Setup

#### PostgreSQL with Replication
```yaml
version: '3.8'
services:
  postgres-master:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=privatus
      - POSTGRES_USER=privatus
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_master:/var/lib/postgresql/data
    command: >
      postgres
      -c wal_level=replica
      -c max_wal_senders=3
      -c wal_keep_size=64

  postgres-replica:
    image: postgres:15-alpine
    environment:
      - POSTGRES_DB=privatus
      - POSTGRES_USER=privatus
      - POSTGRES_PASSWORD=secure_password
    volumes:
      - postgres_replica:/var/lib/postgresql/data
    command: >
      postgres
      -c hot_standby=on
    depends_on:
      - postgres-master

  pgbouncer:
    image: pgbouncer/pgbouncer:latest
    environment:
      - DATABASES_HOST=postgres-master
      - DATABASES_PORT=5432
      - DATABASES_USER=privatus
      - DATABASES_PASSWORD=secure_password
    volumes:
      - ./pgbouncer.ini:/etc/pgbouncer/pgbouncer.ini:ro

volumes:
  postgres_master:
  postgres_replica:
```

#### Redis Cluster Setup
```yaml
version: '3.8'
services:
  redis-node1:
    image: redis:7-alpine
    command: redis-server --cluster-enabled yes --cluster-config-file nodes.conf --cluster-node-timeout 5000 --appendonly yes --port 6379

  redis-node2:
    image: redis:7-alpine
    command: redis-server --cluster-enabled yes --cluster-config-file nodes.conf --cluster-node-timeout 5000 --appendonly yes --port 6379

  redis-node3:
    image: redis:7-alpine
    command: redis-server --cluster-enabled yes --cluster-config-file nodes.conf --cluster-node-timeout 5000 --appendonly yes --port 6379

  redis-cluster-init:
    image: redis:7-alpine
    depends_on:
      - redis-node1
      - redis-node2
      - redis-node3
    command: >
      bash -c "
        sleep 10 &&
        redis-cli --cluster create redis-node1:6379 redis-node2:6379 redis-node3:6379 --cluster-replicas 0 &&
        echo 'Redis cluster created'
      "
```

### Environment Configuration

#### Production Environment Variables
```bash
# Database Configuration
DATABASE_URL=postgresql://privatus:secure_password@postgres-cluster:5432/privatus_prod
REDIS_URL=redis://redis-cluster:6379/0

# Security Configuration
SECRET_KEY=your-256-bit-secret-key-here
ENCRYPTION_MASTER_KEY=your-master-key-here
SSL_CERT_FILE=/app/ssl/privatus-chat.crt
SSL_KEY_FILE=/app/ssl/privatus-chat.key

# Network Configuration
BIND_ADDRESS=0.0.0.0
PORT=8080
DHT_PORT=6881
PUBLIC_IP=auto

# Performance Configuration
MAX_WORKERS=8
CACHE_SIZE=2GB
MAX_MESSAGE_SIZE=100MB
MAX_CONNECTIONS=10000

# Monitoring Configuration
LOG_LEVEL=INFO
METRICS_ENABLED=true
HEALTH_CHECK_PATH=/health
PROMETHEUS_GATEWAY=http://monitoring:9091

# Cluster Configuration
CLUSTER_ENABLED=true
CONSUL_HOST=consul:8500
```

#### Docker Secrets Management
```bash
# Create secrets
echo "your-secret-key-here" | docker secret create privatus_secret_key -
echo "your-master-key-here" | docker secret create privatus_encryption_key -
echo "secure_password" | docker secret create privatus_db_password -

# Use secrets in compose file
version: '3.8'
services:
  privatus-chat:
    image: privatus-chat:latest
    secrets:
      - privatus_secret_key
      - privatus_encryption_key
      - privatus_db_password
    environment:
      - SECRET_KEY_FILE=/run/secrets/privatus_secret_key
      - ENCRYPTION_MASTER_KEY_FILE=/run/secrets/privatus_encryption_key
      - DATABASE_PASSWORD_FILE=/run/secrets/privatus_db_password
```

## Container Orchestration

### Kubernetes Deployment

#### Basic Kubernetes Deployment
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
          value: "postgresql://privatus:$(DATABASE_PASSWORD)@postgres:5432/privatus"
        - name: REDIS_URL
          value: "redis://redis:6379"
        volumeMounts:
        - name: config
          mountPath: /app/config
      volumes:
      - name: config
        secret:
          secretName: privatus-config
```

#### Kubernetes Service
```yaml
apiVersion: v1
kind: Service
metadata:
  name: privatus-chat-service
spec:
  selector:
    app: privatus-chat
  ports:
  - name: http
    port: 8080
    targetPort: 8080
  - name: dht
    port: 6881
    targetPort: 6881
    protocol: UDP
  type: LoadBalancer
```

#### StatefulSet for Database
```yaml
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: postgres
spec:
  serviceName: postgres
  replicas: 3
  selector:
    matchLabels:
      app: postgres
  template:
    metadata:
      labels:
        app: postgres
    spec:
      containers:
      - name: postgres
        image: postgres:15-alpine
        ports:
        - containerPort: 5432
        env:
        - name: POSTGRES_DB
          value: privatus
        - name: POSTGRES_USER
          value: privatus
        - name: POSTGRES_PASSWORD
          valueFrom:
            secretKeyRef:
              name: postgres-secret
              key: password
        volumeMounts:
        - name: postgres-data
          mountPath: /var/lib/postgresql/data
  volumeClaimTemplates:
  - metadata:
      name: postgres-data
    spec:
      accessModes: ["ReadWriteOnce"]
      resources:
        requests:
          storage: 100Gi
```

### Docker Swarm Deployment

#### Swarm Stack Deployment
```yaml
version: '3.8'
services:
  privatus-chat:
    image: privatus-chat:latest
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    environment:
      - DATABASE_URL=postgresql://privatus:password@postgres:5432/privatus
    networks:
      - privatus-overlay

  postgres:
    image: postgres:15-alpine
    deploy:
      placement:
        constraints:
          - node.role == manager
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - privatus-overlay

networks:
  privatus-overlay:
    driver: overlay
    attachable: true

volumes:
  postgres_data:
    driver: local
```

#### Swarm Service Management
```bash
# Deploy the stack
docker stack deploy -c docker-compose.swarm.yml privatus-chat

# Scale the application
docker service scale privatus-chat_privatus-chat=5

# Update the service
docker service update --image privatus-chat:v3.0.1 privatus-chat_privatus-chat

# View service status
docker service ps privatus-chat_privatus-chat
docker service logs privatus-chat_privatus-chat
```

## Monitoring and Logging

### Prometheus Metrics Collection

#### Prometheus Configuration
```yaml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'privatus-chat'
    static_configs:
      - targets: ['privatus-chat:9090']
    metrics_path: '/metrics'
    scrape_interval: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']
```

#### Grafana Dashboard Configuration
```json
{
  "dashboard": {
    "title": "Privatus-chat Dashboard",
    "panels": [
      {
        "title": "Active Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "privatus_active_connections"
          }
        ]
      },
      {
        "title": "Messages per Second",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(privatus_messages_sent_total[5m])"
          }
        ]
      }
    ]
  }
}
```

### Centralized Logging

#### Fluentd Configuration
```xml
<source>
  @type tail
  path /var/lib/docker/containers/*/*-json.log
  pos_file /var/log/fluentd/docker.pos
  tag docker.*
  format json
  time_format %Y-%m-%dT%H:%M:%S.%NZ
</source>

<filter docker.*>
  @type kubernetes_metadata
</filter>

<match docker.privatus-chat>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name fluentd-privatus-chat
</match>
```

#### ELK Stack Setup
```yaml
version: '3.8'
services:
  elasticsearch:
    image: elasticsearch:8.5.0
    environment:
      - discovery.type=single-node
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  logstash:
    image: logstash:8.5.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf:ro
    depends_on:
      - elasticsearch

  kibana:
    image: kibana:8.5.0
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

volumes:
  elasticsearch_data:
```

## Security Hardening

### Image Security

#### Multi-Stage Build Security
```dockerfile
# Build stage
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app user for build stage
RUN useradd --create-home --shell /bin/bash builduser

USER builduser
WORKDIR /home/builduser

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --user --no-cache-dir -r requirements.txt

# Runtime stage
FROM python:3.11-slim

# Create runtime user
RUN useradd --create-home --shell /bin/bash privatus

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

USER privatus
WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /home/builduser/.local /home/privatus/.local

# Copy application code
COPY --chown=privatus:privatus src/ ./src/
COPY --chown=privatus:privatus launch_gui.py ./

CMD ["python", "launch_gui.py"]
```

#### Security Scanning
```bash
# Scan image for vulnerabilities
docker scan privatus-chat:latest

# Use Trivy for comprehensive scanning
trivy image privatus-chat:latest

# Use Grype for vulnerability scanning
grype privatus-chat:latest
```

### Runtime Security

#### Seccomp Profile
```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "syscalls": [
    {
      "name": "accept",
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "name": "bind",
      "action": "SCMP_ACT_ALLOW"
    },
    {
      "name": "listen",
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

#### AppArmor Profile
```apparmor
#include <tunables/global>

profile privatus-chat /docker/*/privatus-chat {
  #include <abstractions/base>
  #include <abstractions/python>

  /app/** r,
  /app/data/** rw,
  /app/logs/** rw,

  network inet dgram,
  network inet stream,

  deny /bin/** w,
  deny /sbin/** w,
  deny /usr/bin/** w,
  deny /usr/sbin/** w,

  deny /sys/** w,
  deny /proc/** w,
}
```

## Performance Optimization

### Resource Management

#### Docker Resource Limits
```yaml
version: '3.8'
services:
  privatus-chat:
    image: privatus-chat:latest
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '0.5'
          memory: 512M
```

#### Horizontal Scaling
```bash
# Scale application horizontally
docker-compose up -d --scale privatus-chat=5

# Scale with Docker Swarm
docker service scale privatus-chat_privatus-chat=10

# Scale with Kubernetes
kubectl scale deployment privatus-chat --replicas=10
```

### Caching Strategies

#### Redis Caching Configuration
```bash
# Redis configuration for caching
maxmemory 2gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000

# TCP keepalive
tcp-keepalive 300

# Performance tuning
timeout 300
```

#### Application-Level Caching
```python
# Cache configuration in application
CACHE_CONFIG = {
    'default': {
        'backend': 'redis://redis:6379/1',
        'options': {
            'MAX_ENTRIES': 10000,
            'TTL': 3600,
        }
    }
}
```

## Troubleshooting

### Common Issues and Solutions

#### Container Startup Issues
```bash
# Check container logs
docker logs privatus-chat

# Check container resource usage
docker stats privatus-chat

# Debug container interactively
docker exec -it privatus-chat /bin/bash

# Check health status
curl http://localhost:8080/health
```

#### Network Connectivity Issues
```bash
# Check container networking
docker network ls
docker network inspect privatus-network

# Test service discovery
docker exec privatus-chat nslookup redis

# Check port bindings
docker port privatus-chat

# Test external connectivity
docker exec privatus-chat curl -I http://example.com
```

#### Performance Issues
```bash
# Monitor resource usage
docker stats --no-stream

# Check application metrics
curl http://localhost:8080/metrics

# Profile container performance
docker exec privatus-chat python -m cProfile -o profile.out launch_gui.py

# Memory analysis
docker exec privatus-chat python -c "import psutil; print(psutil.virtual_memory())"
```

### Debugging Tools

#### Docker Debug Container
```yaml
version: '3.8'
services:
  debug-tools:
    image: nicolaferraro/debug-tools:latest
    container_name: privatus-debug
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    networks:
      - privatus-network
    profiles:
      - debug
```

#### Log Aggregation and Analysis
```bash
# Aggregate logs from all containers
docker-compose logs -f > combined.log

# Filter specific log entries
docker-compose logs -f privatus-chat | grep -E "(ERROR|WARN)"

# Real-time log monitoring
docker-compose logs -f -t --tail=100
```

## Advanced Configuration

### Custom Docker Networks

#### Network Segmentation
```yaml
version: '3.8'
networks:
  privatus-frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

  privatus-backend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.21.0.0/16
    internal: true

  privatus-database:
    driver: bridge
    ipam:
      config:
        - subnet: 172.22.0.0/16
    internal: true
```

### Health Checks and Monitoring

#### Advanced Health Checks
```yaml
version: '3.8'
services:
  privatus-chat:
    image: privatus-chat:latest
    healthcheck:
      test: ["CMD", "python", "-c", "
        import sys, requests, time
        sys.path.append('.')
        try:
            response = requests.get('http://localhost:8080/health', timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'healthy':
                    sys.exit(0)
            sys.exit(1)
        except:
            sys.exit(1)
      "]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

#### Custom Monitoring Endpoints
```python
@app.route('/metrics')
def metrics():
    return Response(generate_latest(), mimetype='text/plain')

@app.route('/health/detailed')
def detailed_health():
    checks = {
        'database': check_database(),
        'redis': check_redis(),
        'dht': check_dht(),
        'disk_space': check_disk_space(),
        'memory': check_memory()
    }
    return jsonify(checks)
```

### Backup and Recovery

#### Automated Backup Strategy
```yaml
version: '3.8'
services:
  backup:
    image: alpine:latest
    container_name: privatus-backup
    volumes:
      - privatus_data:/data:ro
      - postgres_data:/postgres:ro
      - ./backups:/backup
    command: >
      sh -c "
        tar -czf /backup/data-backup-\$$(date +%Y%m%d-%H%M%S).tar.gz /data &&
        tar -czf /backup/postgres-backup-\$$(date +%Y%m%d-%H%M%S).tar.gz /postgres &&
        find /backup -name '*.tar.gz' -mtime +7 -delete
      "
    schedules:
      - cron: "0 2 * * *"
```

#### Recovery Procedures
```bash
#!/bin/bash
# recovery.sh

# Stop application
docker-compose down

# Restore data volume
docker run --rm \
  -v privatus_data:/data \
  -v $(pwd)/backups:/backup \
  alpine:latest \
  sh -c "cd /data && tar -xzf /backup/data-backup-latest.tar.gz"

# Restore database
docker-compose up -d postgres
sleep 30
docker exec postgres psql -U privatus privatus < latest-backup.sql

# Start application
docker-compose up -d
```

## Best Practices

### Production Checklist

- [ ] Use specific image versions (not latest)
- [ ] Implement proper secrets management
- [ ] Configure resource limits and health checks
- [ ] Set up monitoring and alerting
- [ ] Implement backup and recovery procedures
- [ ] Use read-only filesystems where possible
- [ ] Configure proper logging and log rotation
- [ ] Implement security scanning in CI/CD pipeline
- [ ] Use multi-stage builds for smaller images
- [ ] Configure proper networking and firewall rules

### Security Checklist

- [ ] Run containers as non-root user
- [ ] Use minimal base images
- [ ] Scan images for vulnerabilities
- [ ] Implement security profiles (seccomp, AppArmor)
- [ ] Use secrets management for sensitive data
- [ ] Configure TLS/SSL properly
- [ ] Implement proper authentication and authorization
- [ ] Monitor for security events
- [ ] Keep images and dependencies updated
- [ ] Implement network security policies

## Support and Resources

### Getting Help

- **Docker Documentation**: [Official Docker Docs](https://docs.docker.com/)
- **Kubernetes Documentation**: [Official Kubernetes Docs](https://kubernetes.io/docs/)
- **GitHub Issues**: [Report Issues](https://github.com/privatus-chat/privatus-chat/issues)
- **Discussions**: [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)

### Example Configurations

- **Complete Docker Compose**: [docker-compose.yml](deployment/docker-compose.yml)
- **Kubernetes Manifests**: [kubernetes/](deployment/kubernetes/)
- **Monitoring Setup**: [monitoring/](deployment/monitoring/)

---

*Last updated: January 2025*
*Privatus-chat v3.0.0 - Enhanced Deployment Edition*