# Load Balancing and Scaling Strategies Guide

This comprehensive guide covers load balancing techniques, scaling strategies, and performance optimization for Privatus-chat deployments across different infrastructure types.

## Table of Contents

- [Load Balancing Strategies](#load-balancing-strategies)
- [Horizontal Scaling](#horizontal-scaling)
- [Vertical Scaling](#vertical-scaling)
- [Auto-Scaling](#auto-scaling)
- [Performance Optimization](#performance-optimization)
- [Monitoring and Alerting](#monitoring-and-alerting)
- [Capacity Planning](#capacity-planning)
- [Disaster Recovery](#disaster-recovery)

## Load Balancing Strategies

### Layer 4 Load Balancing

#### TCP/UDP Load Balancing
```nginx
# Layer 4 load balancing with Nginx
stream {
    upstream privatus_backend {
        least_conn;
        server app1:8080 max_fails=3 fail_timeout=30s;
        server app2:8080 max_fails=3 fail_timeout=30s;
        server app3:8080 max_fails=3 fail_timeout=30s;
    }

    server {
        listen 8080;
        proxy_pass privatus_backend;
        proxy_timeout 30s;
        proxy_connect_timeout 10s;
    }

    # DHT UDP load balancing
    server {
        listen 6881 udp;
        proxy_pass privatus_dht_backend;
        proxy_timeout 60s;
    }
}
```

#### HAProxy Configuration
```haproxy
# HAProxy Layer 4 configuration
frontend privatus_frontend
    bind *:8080
    mode tcp
    default_backend privatus_backend

frontend privatus_dht_frontend
    bind *:6881
    mode udp
    default_backend privatus_dht_backend

backend privatus_backend
    mode tcp
    balance leastconn
    server app1 app1:8080 check port 8080 inter 10s fall 3 rise 2
    server app2 app2:8080 check port 8080 inter 10s fall 3 rise 2
    server app3 app3:8080 check port 8080 inter 10s fall 3 rise 2

backend privatus_dht_backend
    mode udp
    balance leastconn
    server app1 app1:6881 check inter 10s fall 3 rise 2
    server app2 app2:6881 check inter 10s fall 3 rise 2
    server app3 app3:6881 check inter 10s fall 3 rise 2
```

### Layer 7 Load Balancing

#### HTTP/WebSocket Load Balancing
```nginx
# Layer 7 load balancing with Nginx
upstream privatus_http_backend {
    least_conn;
    server app1:8080 max_fails=3 fail_timeout=30s;
    server app2:8080 max_fails=3 fail_timeout=30s;
    server app3:8080 max_fails=3 fail_timeout=30s;
}

# HTTP server
server {
    listen 80;
    server_name chat.example.com;

    # Health checks
    location /health {
        proxy_pass http://privatus_http_backend/health;
        proxy_connect_timeout 5s;
        proxy_read_timeout 10s;
    }

    # API endpoints
    location /api/ {
        proxy_pass http://privatus_http_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
        proxy_send_timeout 300s;
    }

    # WebSocket support for real-time features
    location /ws/ {
        proxy_pass http://privatus_http_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
    }
}
```

#### Advanced Routing Rules
```nginx
# Content-based routing
upstream privatus_api_backend {
    server app1:8080;
    server app2:8080;
}

upstream privatus_file_backend {
    server app3:8080;  # Dedicated file server
}

server {
    listen 80;

    # Route API calls to specific backends
    location /api/v1/messages {
        proxy_pass http://privatus_api_backend;
    }

    # Route file transfers to dedicated servers
    location /api/v1/files {
        proxy_pass http://privatus_file_backend;
    }

    # Route based on user agent or other headers
    location /mobile/ {
        if ($http_user_agent ~* "(Mobile|Android|iOS)") {
            proxy_pass http://privatus_mobile_backend;
        }
    }
}
```

### Global Load Balancing

#### DNS-Based Load Balancing
```bash
# Configure multiple A records for round-robin DNS
chat.example.com. 300 IN A 192.168.1.10
chat.example.com. 300 IN A 192.168.1.11
chat.example.com. 300 IN A 192.168.1.12

# Health check script for DNS updates
#!/bin/bash
# check_and_update_dns.sh

for server in app1 app2 app3; do
    if curl -f http://$server:8080/health > /dev/null 2>&1; then
        echo "$server is healthy"
        # Update DNS if needed
    else
        echo "$server is unhealthy"
        # Remove from DNS rotation
    fi
done
```

#### Geographic Load Balancing
```nginx
# GeoIP-based routing with Nginx Plus
split_clients "${remote_addr}AAA" $backend {
    33.33%  app1:8080;
    33.33%  app2:8080;
    33.34%  app3:8080;
}

server {
    location / {
        proxy_pass http://$backend;
    }
}
```

## Horizontal Scaling

### Application Scaling

#### Stateless Application Design
```python
# Application configuration for horizontal scaling
class ScalableConfig:
    # Use external session storage
    SESSION_TYPE = 'redis'
    SESSION_REDIS = Redis(host='redis-cluster', port=6379)

    # Use external cache
    CACHE_TYPE = 'redis'
    CACHE_REDIS_URL = 'redis://redis-cluster:6379/0'

    # Use shared file storage
    FILE_STORAGE = 's3://privatus-files-bucket'

    # Database connection pooling
    DATABASE_POOL_SIZE = 20
    DATABASE_MAX_OVERFLOW = 30
```

#### Session Affinity Management
```nginx
# Sticky sessions for stateful features
upstream privatus_sticky_backend {
    sticky;
    server app1:8080;
    server app2:8080;
    server app3:8080;
}

server {
    location / {
        proxy_pass http://privatus_sticky_backend;
    }
}
```

### Database Scaling

#### Read/Write Splitting
```yaml
# ProxySQL configuration for read/write splitting
version: '3.8'
services:
  proxysql:
    image: proxysql/proxysql:latest
    environment:
      - MYSQL_ROOT_PASSWORD=root_password
    volumes:
      - ./proxysql.cnf:/etc/proxysql.cnf:ro

  mysql-master:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=root_password

  mysql-slave:
    image: mysql:8.0
    environment:
      - MYSQL_ROOT_PASSWORD=root_password
    depends_on:
      - mysql-master
```

#### Database Sharding Strategy
```python
# Application-level sharding logic
class MessageRouter:
    def get_shard(self, user_id):
        # Hash-based sharding
        shard_id = hash(user_id) % NUM_SHARDS
        return f"shard_{shard_id}"

    def route_query(self, query):
        if query.type == 'write':
            return self.master_db
        else:
            # Route reads to appropriate shard
            shard = self.get_shard(query.user_id)
            return self.shard_dbs[shard]
```

### Storage Scaling

#### Distributed File Storage
```yaml
# MinIO for distributed file storage
version: '3.8'
services:
  minio1:
    image: minio/minio
    command: server /data --console-address ":9001"
    environment:
      - MINIO_ROOT_USER=admin
      - MINIO_ROOT_PASSWORD=password
    volumes:
      - minio_data1:/data

  minio2:
    image: minio/minio
    command: server http://minio1:9000/data http://minio2:9001/data --console-address ":9002"
    depends_on:
      - minio1

  minio3:
    image: minio/minio
    command: server http://minio1:9000/data http://minio2:9001/data http://minio3:9002/data --console-address ":9003"
    depends_on:
      - minio2
```

## Vertical Scaling

### Resource Optimization

#### CPU Optimization
```bash
# System tuning for CPU performance
echo 'vm.nr_hugepages = 1024' >> /etc/sysctl.conf
echo 'kernel.sched_autogroup_enabled = 0' >> /etc/sysctl.conf
echo 'kernel.sched_migration_cost_ns = 500000' >> /etc/sysctl.conf

# Application CPU tuning
export GUNICORN_WORKERS=$(python -c "import multiprocessing; print(multiprocessing.cpu_count() * 2 + 1)")
export GUNICORN_WORKER_CLASS=eventlet
export GUNICORN_MAX_REQUESTS=1000
```

#### Memory Optimization
```python
# Memory-efficient configuration
MEMORY_CONFIG = {
    'max_message_size': '50MB',
    'cache_size': '1GB',
    'buffer_size': '64KB',
    'max_connections': 1000,
    'worker_memory_limit': '512MB'
}

# Garbage collection tuning
import gc
gc.set_threshold(700, 10, 10)
```

#### Storage I/O Optimization
```bash
# Filesystem tuning for better I/O
echo 'deadline' > /sys/block/sda/queue/scheduler
echo '4096' > /sys/block/sda/queue/nr_requests
echo '256' > /proc/sys/vm/dirty_ratio
echo '128' > /proc/sys/vm/dirty_background_ratio

# Database I/O optimization
echo 'vm.dirty_expire_centisecs = 3000' >> /etc/sysctl.conf
echo 'vm.dirty_writeback_centisecs = 500' >> /etc/sysctl.conf
```

## Auto-Scaling

### Infrastructure Auto-Scaling

#### Kubernetes Horizontal Pod Autoscaler
```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: privatus-chat-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: privatus-chat
  minReplicas: 3
  maxReplicas: 20
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
  behavior:
    scaleDown:
      stabilizationWindowSeconds: 300
      policies:
      - type: Percent
        value: 10
        periodSeconds: 60
    scaleUp:
      stabilizationWindowSeconds: 120
      policies:
      - type: Percent
        value: 50
        periodSeconds: 60
```

#### AWS Auto Scaling Group
```json
{
  "AutoScalingGroupName": "privatus-chat-asg",
  "LaunchConfigurationName": "privatus-chat-lc",
  "MinSize": "3",
  "MaxSize": "20",
  "DesiredCapacity": "5",
  "AvailabilityZones": ["us-east-1a", "us-east-1b", "us-east-1c"],
  "LoadBalancerNames": ["privatus-chat-elb"],
  "HealthCheckType": "ELB",
  "HealthCheckGracePeriod": 300,
  "Tags": [
    {
      "Key": "Name",
      "Value": "privatus-chat-instance",
      "PropagateAtLaunch": true
    }
  ]
}
```

### Application-Level Auto-Scaling

#### Dynamic Worker Scaling
```python
class AutoScaler:
    def __init__(self):
        self.base_workers = 4
        self.max_workers = 32
        self.current_workers = self.base_workers

    def scale_workers(self, metrics):
        cpu_usage = metrics['cpu_percent']
        memory_usage = metrics['memory_percent']
        queue_size = metrics['message_queue_size']

        # Scale up logic
        if (cpu_usage > 80 or memory_usage > 85 or queue_size > 1000):
            if self.current_workers < self.max_workers:
                self.current_workers = min(self.current_workers * 2, self.max_workers)
                self.update_workers()

        # Scale down logic
        elif (cpu_usage < 30 and memory_usage < 40 and queue_size < 100):
            if self.current_workers > self.base_workers:
                self.current_workers = max(self.current_workers // 2, self.base_workers)
                self.update_workers()

    def update_workers(self):
        # Update Gunicorn workers
        os.kill(os.getppid(), signal.SIGHUP)
```

## Performance Optimization

### Network Optimization

#### TCP Optimization
```bash
# TCP tuning for high throughput
echo 'net.core.rmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 134217728' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 5000' >> /etc/sysctl.conf
echo 'net.unix.max_dgram_qlen = 1000' >> /etc/sysctl.conf

# TCP connection tuning
echo 'net.ipv4.tcp_window_scaling = 1' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_timestamps = 1' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_sack = 1' >> /etc/sysctl.conf
```

#### UDP Optimization for DHT
```bash
# UDP tuning for DHT performance
echo 'net.core.rmem_default = 134217728' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 134217728' >> /etc/sysctl.conf
echo 'net.unix.max_dgram_qlen = 1000' >> /etc/sysctl.conf

# Increase UDP buffer limits
echo 'net.core.optmem_max = 65536' >> /etc/sysctl.conf
echo 'net.ipv4.udp_mem = 192576 256768 385152' >> /etc/sysctl.conf
```

### Application Performance Tuning

#### Gunicorn Optimization
```python
# Optimal Gunicorn configuration for different loads
def get_gunicorn_config():
    import multiprocessing

    workers = multiprocessing.cpu_count() * 2 + 1
    worker_class = "eventlet"  # For WebSocket support
    max_requests = 1000
    max_requests_jitter = 50
    keepalive = 2
    timeout = 30
    preload_app = True
    worker_tmp_dir = "/dev/shm"

    return {
        'workers': workers,
        'worker_class': worker_class,
        'max_requests': max_requests,
        'max_requests_jitter': max_requests_jitter,
        'keepalive': keepalive,
        'timeout': timeout,
        'preload_app': preload_app,
        'worker_tmp_dir': worker_tmp_dir
    }
```

#### Database Connection Pooling
```python
# Database connection pool configuration
DATABASE_POOL_CONFIG = {
    'pool_size': 20,
    'max_overflow': 30,
    'pool_timeout': 30,
    'pool_recycle': 3600,
    'pool_pre_ping': True
}

# Redis connection pooling
REDIS_POOL_CONFIG = {
    'max_connections': 50,
    'retry_on_timeout': True,
    'socket_timeout': 5,
    'socket_connect_timeout': 5
}
```

## Monitoring and Alerting

### Metrics Collection

#### Application Metrics
```python
# Custom metrics for load balancing
from prometheus_client import Counter, Histogram, Gauge

# Load balancing metrics
requests_per_backend = Counter('privatus_requests_per_backend',
                              'Requests per backend server',
                              ['backend'])

backend_response_time = Histogram('privatus_backend_response_time_seconds',
                                 'Backend response time',
                                 ['backend'])

active_connections_per_backend = Gauge('privatus_active_connections_per_backend',
                                      'Active connections per backend',
                                      ['backend'])

load_balancer_health = Gauge('privatus_load_balancer_health',
                            'Load balancer health status')
```

#### Infrastructure Metrics
```yaml
# Prometheus configuration for infrastructure monitoring
scrape_configs:
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node1:9100', 'node2:9100', 'node3:9100']
    scrape_interval: 15s

  - job_name: 'cadvisor'
    static_configs:
      - targets: ['cadvisor:8080']
    scrape_interval: 15s

  - job_name: 'nginx-exporter'
    static_configs:
      - targets: ['nginx-exporter:9113']
    scrape_interval: 15s
```

### Alerting Rules

#### Load Balancing Alerts
```yaml
groups:
  - name: load-balancing
    rules:
      - alert: HighBackendErrorRate
        expr: rate(nginx_http_backend_requests_total[5m]) - rate(nginx_http_backend_requests_total{status=~"2.."}[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate on backend servers"

      - alert: BackendServerDown
        expr: up{job="privatus-backend"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Backend server is down"

      - alert: UnevenLoadDistribution
        expr: (max(privatus_requests_per_backend) - min(privatus_requests_per_backend)) / max(privatus_requests_per_backend) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Uneven load distribution detected"
```

## Capacity Planning

### Load Testing

#### Artillery Load Testing
```yaml
# artillery.yml for load testing
config:
  target: 'https://chat.example.com'
  phases:
    - duration: 300
      arrivalRate: 10
      name: "Warm up"
    - duration: 600
      arrivalRate: 50
      name: "Sustained load"
    - duration: 300
      arrivalRate: 100
      name: "Peak load"

scenarios:
  - name: "Message sending"
    weight: 70
    flow:
      - post:
          url: "/api/v1/messages"
          json:
            content: "Test message {{ $randomString() }}"
          headers:
            Authorization: "Bearer {{ $processEnvironment.USER_TOKEN }}"

  - name: "File upload"
    weight: 20
    flow:
      - post:
          url: "/api/v1/files"
          multipart:
            - name: "file"
              type: "application/octet-stream"
              size: "1MB"

  - name: "Health check"
    weight: 10
    flow:
      - get:
          url: "/health"
```

#### K6 Load Testing Script
```javascript
import http from 'k6/http';
import { check, sleep } from 'k6';

export let options = {
  stages: [
    { duration: '5m', target: 100 },  // Ramp up to 100 users
    { duration: '10m', target: 100 }, // Stay at 100 users
    { duration: '5m', target: 200 },  // Ramp up to 200 users
    { duration: '10m', target: 200 }, // Stay at 200 users
    { duration: '5m', target: 0 },    // Ramp down to 0 users
  ],
  thresholds: {
    http_req_duration: ['p(95)<500'], // 95% of requests should be below 500ms
    http_req_failed: ['rate<0.1'],    // Error rate should be below 10%
  },
};

export default function () {
  let response = http.post('https://chat.example.com/api/v1/messages', {
    content: `Test message ${Math.random()}`,
  });

  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 500ms': (r) => r.timings.duration < 500,
  });

  sleep(Math.random() * 2 + 1); // Random sleep between 1-3 seconds
}
```

### Capacity Estimation

#### Resource Calculation
```python
class CapacityPlanner:
    def __init__(self):
        # Base resource requirements per user
        self.base_cpu_per_user = 0.01  # CPU cores
        self.base_memory_per_user = 10  # MB
        self.base_storage_per_user = 1  # MB

        # Network requirements
        self.network_per_user = 0.1  # Mbps

    def calculate_requirements(self, peak_users, growth_factor=1.2):
        """Calculate resource requirements for given user load"""

        # Apply growth factor for future capacity
        total_users = peak_users * growth_factor

        requirements = {
            'cpu_cores': math.ceil(total_users * self.base_cpu_per_user * 2),  # 2x for safety
            'memory_gb': math.ceil(total_users * self.base_memory_per_user / 1024 * 1.5),
            'storage_gb': math.ceil(total_users * self.base_storage_per_user / 1024 * 2),
            'network_mbps': math.ceil(total_users * self.network_per_user * 1.3),
            'estimated_cost': self.calculate_cost(requirements)
        }

        return requirements

    def calculate_cost(self, requirements):
        """Estimate infrastructure cost"""
        # This would integrate with cloud provider pricing APIs
        return {
            'monthly_compute': requirements['cpu_cores'] * 50,  # Example pricing
            'monthly_storage': requirements['storage_gb'] * 0.10,
            'monthly_network': requirements['network_mbps'] * 0.05
        }
```

## Disaster Recovery

### Backup Strategies

#### Multi-Region Deployment
```yaml
# Multi-region deployment configuration
version: '3.8'
services:
  privatus-chat-us-east:
    image: privatus-chat:latest
    environment:
      - REGION=us-east
      - BACKUP_REGION=us-west
    deploy:
      placement:
        constraints:
          - node.labels.region == us-east

  privatus-chat-us-west:
    image: privatus-chat:latest
    environment:
      - REGION=us-west
      - BACKUP_REGION=us-east
    deploy:
      placement:
        constraints:
          - node.labels.region == us-west
```

#### Automated Failover
```bash
#!/bin/bash
# failover.sh

PRIMARY_REGION="us-east"
BACKUP_REGION="us-west"
HEALTH_CHECK_URL="https://chat-$PRIMARY_REGION.example.com/health"

# Check primary region health
if ! curl -f -s $HEALTH_CHECK_URL > /dev/null; then
    echo "Primary region unhealthy, failing over to $BACKUP_REGION"

    # Update DNS to point to backup region
    # This would integrate with your DNS provider API

    # Update load balancer configuration
    # This would update your load balancer to route to backup region

    # Send notifications
    notify_failover $BACKUP_REGION
fi
```

### Recovery Procedures

#### Gradual Recovery
```bash
#!/bin/bash
# gradual_recovery.sh

FAILED_REGION="us-east"
RECOVERY_REGION="us-west"

# Step 1: Verify backup region health
if curl -f "https://chat-$RECOVERY_REGION.example.com/health"; then
    echo "Backup region healthy"

    # Step 2: Sync data from failed region
    sync_data $FAILED_REGION $RECOVERY_REGION

    # Step 3: Gradually route traffic
    for percentage in 10 25 50 75 100; do
        update_traffic_split $percentage $RECOVERY_REGION
        sleep 300  # Wait 5 minutes between steps
    done

    # Step 4: Verify full recovery
    verify_recovery $RECOVERY_REGION
fi
```

## Best Practices

### Load Balancing Best Practices

- [ ] Use health checks for all backend servers
- [ ] Implement proper session affinity when needed
- [ ] Monitor load distribution across backends
- [ ] Use connection pooling for database connections
- [ ] Implement circuit breakers for fault tolerance
- [ ] Use consistent hashing for DHT load distribution
- [ ] Monitor and alert on backend response times
- [ ] Implement proper logging and tracing
- [ ] Use A/B testing for load balancing algorithm optimization
- [ ] Implement graceful degradation strategies

### Scaling Best Practices

- [ ] Design applications to be stateless when possible
- [ ] Use external storage for shared state
- [ ] Implement proper database indexing
- [ ] Use caching strategies effectively
- [ ] Monitor resource utilization continuously
- [ ] Implement automated scaling policies
- [ ] Test scaling procedures regularly
- [ ] Plan for both horizontal and vertical scaling
- [ ] Use infrastructure as code for consistent deployments
- [ ] Implement proper backup and recovery procedures

## Troubleshooting

### Common Load Balancing Issues

#### Uneven Load Distribution
```bash
# Check backend server weights and health
curl -s http://load-balancer/metrics | grep backend

# Verify server capacities
for server in app1 app2 app3; do
    ssh $server "htop" &
done

# Check for sticky session issues
curl -H "Cookie: SESSION_ID=test" http://load-balancer/debug
```

#### High Response Times
```bash
# Check backend response times
curl -w "@curl-format.txt" -s -o /dev/null http://load-balancer/

# Monitor database performance
docker exec postgres psql -c "SELECT * FROM pg_stat_activity;"

# Check network latency between load balancer and backends
for server in app1 app2 app3; do
    ping -c 5 $server
done
```

#### Connection Failures
```bash
# Check backend server logs
for server in app1 app2 app3; do
    ssh $server "tail -f /var/log/privatus-chat/error.log" &
done

# Verify firewall rules
sudo iptables -L -n -v | grep 8080

# Check system resource limits
ulimit -n  # Check open file limits
cat /proc/sys/net/core/somaxconn  # Check socket backlog
```

## Support and Resources

### Getting Help

- **Load Testing Tools**: [Artillery](https://artillery.io/), [K6](https://k6.io/)
- **Monitoring Solutions**: [Prometheus](https://prometheus.io/), [Grafana](https://grafana.com/)
- **Load Balancers**: [NGINX](https://nginx.com/), [HAProxy](http://www.haproxy.org/)
- **GitHub Issues**: [Report Issues](https://github.com/privatus-chat/privatus-chat/issues)
- **Discussions**: [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)

### Example Configurations

- **NGINX Load Balancer**: [nginx.conf](deployment/config/nginx-lb.conf)
- **HAProxy Configuration**: [haproxy.cfg](deployment/config/haproxy.cfg)
- **Kubernetes HPA**: [hpa.yml](deployment/kubernetes/hpa.yml)

---

*Last updated: January 2025*
*Privatus-chat v3.0.0 - Enhanced Deployment Edition*