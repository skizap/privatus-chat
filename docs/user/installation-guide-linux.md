# Linux Installation Guide

This guide provides detailed instructions for installing Privatus-chat on Linux systems.

## Supported Distributions

Privatus-chat supports the following Linux distributions:

### Debian/Ubuntu-based
- Ubuntu 20.04 LTS, 22.04 LTS, 23.04, 23.10
- Debian 11 (Bullseye), 12 (Bookworm)
- Linux Mint 20.x, 21.x
- elementary OS 6.x, 7.x
- Zorin OS 16, 17

### Red Hat/Fedora-based
- Fedora 37, 38, 39
- CentOS 8, 9
- RHEL 8, 9
- Rocky Linux 8, 9
- AlmaLinux 8, 9

### Arch-based
- Arch Linux
- Manjaro
- EndeavourOS

### Other
- openSUSE 15.4, 15.5
- Mageia 8, 9
- PCLinuxOS

## System Requirements

### Minimum Requirements
- **Operating System**: 64-bit Linux distribution
- **Kernel**: Linux 5.4 or later
- **Processor**: x86-64 or ARM64 processor
- **Memory**: 512 MB RAM
- **Storage**: 200 MB available disk space
- **Network**: Internet connection for initial setup

### Recommended Requirements
- **Memory**: 1 GB RAM or more
- **Storage**: 500 MB available disk space
- **Network**: Broadband internet connection

## Installation Methods

### Method 1: DEB Package (Debian/Ubuntu)

1. **Download the DEB Package**
   ```bash
   wget https://github.com/privatus-chat/privatus-chat/releases/download/v3.0.0/privatus-chat_3.0.0_amd64.deb
   ```

2. **Install the Package**
   ```bash
   sudo dpkg -i privatus-chat_3.0.0_amd64.deb
   ```

3. **Fix Dependencies (if needed)**
   ```bash
   sudo apt-get install -f
   ```

4. **Launch Privatus-chat**
   ```bash
   privatus-chat
   ```

### Method 2: RPM Package (Red Hat/Fedora)

1. **Download the RPM Package**
   ```bash
   wget https://github.com/privatus-chat/privatus-chat/releases/download/v3.0.0/privatus-chat-3.0.0-1.x86_64.rpm
   ```

2. **Install the Package**
   ```bash
   sudo rpm -ivh privatus-chat-3.0.0-1.x86_64.rpm
   ```

3. **Launch Privatus-chat**
   ```bash
   privatus-chat
   ```

### Method 3: AppImage (Universal)

1. **Download the AppImage**
   ```bash
   wget https://github.com/privatus-chat/privatus-chat/releases/download/v3.0.0/privatus-chat-3.0.0-x86_64.AppImage
   ```

2. **Make it Executable**
   ```bash
   chmod +x privatus-chat-3.0.0-x86_64.AppImage
   ```

3. **Run Privatus-chat**
   ```bash
   ./privatus-chat-3.0.0-x86_64.AppImage
   ```

### Method 4: Snap Package (Ubuntu/Debian)

1. **Install via Snap**
   ```bash
   sudo snap install privatus-chat
   ```

2. **Launch Privatus-chat**
   ```bash
   snap run privatus-chat
   ```

### Method 5: From Source (Development)

1. **Clone the Repository**
   ```bash
   git clone https://github.com/privatus-chat/privatus-chat.git
   cd privatus-chat
   ```

2. **Install Dependencies**
   ```bash
   pip3 install -r requirements.txt
   ```

3. **Run Privatus-chat**
   ```bash
   python3 launch_gui.py
   ```

## Post-Installation Setup

### First Launch
1. **Initial Configuration**
   - Privatus-chat will launch with a setup wizard
   - Choose your preferred language
   - Configure basic settings

2. **Desktop Integration**
   - Desktop file is installed for menu integration
   - Icon is available in application menus
   - MIME types are registered

3. **Privacy Settings**
   - Review and adjust privacy settings as needed
   - Enable or disable optional features

### Desktop Integration

#### Application Menu
- Privatus-chat appears in your desktop's application menu
- Usually found under "Internet" or "Network" category
- Can be added to favorites or dock

#### Desktop File
- Desktop file installed to `/usr/share/applications/`
- Contains proper categories and MIME type associations
- Can be customized by editing the desktop file

#### Icon Integration
- Application icon installed to `/usr/share/pixmaps/`
- Available in various sizes for different uses
- Follows system icon theme standards

## Package Management

### Update Packages

#### DEB-based Systems
```bash
sudo apt-get update
sudo apt-get upgrade privatus-chat
```

#### RPM-based Systems
```bash
sudo dnf update privatus-chat
# or
sudo yum update privatus-chat
```

#### AppImage
- Download new AppImage file
- Replace old AppImage file
- No package manager update needed

### Remove Packages

#### DEB-based Systems
```bash
sudo apt-get remove privatus-chat
```

#### RPM-based Systems
```bash
sudo dnf remove privatus-chat
# or
sudo yum remove privatus-chat
```

#### AppImage
```bash
rm ~/privatus-chat-3.0.0-x86_64.AppImage
```

## Troubleshooting

### Installation Issues

#### Dependency Errors (DEB)
```bash
sudo apt-get install -f
# or manually install missing dependencies
sudo apt-get install python3-pyqt6 python3-cryptography
```

#### Dependency Errors (RPM)
```bash
sudo dnf install python3-pyqt6 python3-cryptography
# or
sudo yum install python3-pyqt6 python3-cryptography
```

#### Permission Denied
- Ensure you have sudo privileges
- Check available disk space
- Verify package integrity

### Runtime Issues

#### Application Won't Start
- Check if all dependencies are installed
- Verify Python version compatibility
- Check system logs: `journalctl -u privatus-chat`

#### GUI Issues
- Ensure desktop environment is supported
- Check graphics drivers
- Try running with software rendering: `QT_QUICK_BACKEND=software privatus-chat`

#### Network Issues
- Check firewall settings
- Ensure ports 8000-9000 are not blocked
- Check network configuration

#### Performance Issues
- Monitor system resources: `htop` or `top`
- Check disk space and memory usage
- Consider increasing ulimits for network connections

### Getting Help

If you encounter issues not covered here:

1. **Check the FAQ**: [Frequently Asked Questions](faq.md)
2. **Search GitHub Issues**: [GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)
3. **Create New Issue**: Report bugs or request features

## Advanced Configuration

### Environment Variables

Privatus-chat respects the following environment variables:

- `PRIVATUS_DATA_DIR`: Custom data directory path
- `PRIVATUS_CONFIG_DIR`: Custom configuration directory path
- `PRIVATUS_LOG_LEVEL`: Set logging level (DEBUG, INFO, WARNING, ERROR)
- `QT_QPA_PLATFORM`: Force GUI backend (xcb, wayland)

### Command Line Options

Launch Privatus-chat from terminal with options:

```bash
privatus-chat --help
privatus-chat --version
privatus-chat --reset-config
privatus-chat --debug
privatus-chat --log-level DEBUG
```

### Data Locations

- **System Data**: `/var/lib/privatus-chat`
- **Configuration**: `/etc/privatus-chat`
- **Logs**: `/var/log/privatus-chat`
- **User Data**: `~/.config/privatus-chat`
- **Cache**: `~/.cache/privatus-chat`

### System Service (Optional)

Create a system service for automatic startup:

```ini
# /etc/systemd/system/privatus-chat.service
[Unit]
Description=Privatus-chat Service
After=network.target

[Service]
Type=simple
User=privatus
ExecStart=/usr/bin/privatus-chat --daemon
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

Enable the service:
```bash
sudo systemctl enable privatus-chat
sudo systemctl start privatus-chat
```

## Security Considerations

### Linux Security Features
- Privatus-chat runs with user privileges by default
- Network access is required for P2P communication
- AppArmor/SELinux profiles can be applied

### Firewall Configuration
- Automatic firewall rules can be created during installation
- Manual firewall configuration may be needed for some distributions

### Privacy Protection
- All data is encrypted locally before transmission
- No personal information is collected
- P2P connections are end-to-end encrypted

## Container Deployment

### Docker Installation

1. **Pull Docker Image**
   ```bash
   docker pull privatus-chat/privatus-chat:latest
   ```

2. **Run Container**
   ```bash
   docker run -d \
     --name privatus-chat \
     -p 8000-9000:8000-9000 \
     -v privatus_data:/app/data \
     privatus-chat/privatus-chat:latest
   ```

3. **Access Application**
   - Application is available at `http://localhost:8000`
   - Configure networking as needed

### Docker Compose

```yaml
version: '3.8'
services:
  privatus-chat:
    image: privatus-chat/privatus-chat:latest
    ports:
      - "8000-9000:8000-9000"
    volumes:
      - privatus_data:/app/data
```

## Advanced Installation Scenarios

### Development Environment Setup

#### Complete Development Stack
```bash
# Install development dependencies
sudo apt-get install build-essential python3-dev libssl-dev libffi-dev
sudo apt-get install postgresql postgresql-contrib redis-server
sudo apt-get install nodejs npm  # For web assets
sudo apt-get install docker.io docker-compose  # For containerized testing

# Set up PostgreSQL for development
sudo -u postgres createuser --interactive --pwprompt devuser
sudo -u postgres createdb privatus_dev
sudo -u postgres psql -c "ALTER USER devuser CREATEDB;"

# Set up Redis for development
sudo systemctl enable redis-server
sudo systemctl start redis-server

# Clone and setup Privatus-chat
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat
python3 -m venv venv-dev
source venv-dev/bin/activate
pip install -r requirements-dev.txt

# Run development server
python launch_gui.py --debug --reload
```

#### IDE Configuration
```bash
# VS Code extensions for Python development
code --install-extension ms-python.python
code --install-extension ms-python.black-formatter
code --install-extension ms-python.isort
code --install-extension ms-python.pylint
code --install-extension ms-vscode.vscode-json

# Create VS Code workspace settings
mkdir -p .vscode
cat > .vscode/settings.json << 'EOF'
{
    "python.defaultInterpreterPath": "./venv-dev/bin/python",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black",
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests"],
    "files.associations": {
        "*.py": "python"
    }
}
EOF
```

### CI/CD Pipeline Integration

#### GitHub Actions Workflow
```yaml
# .github/workflows/ci-cd.yml
name: Privatus-chat CI/CD

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.9, 3.10, 3.11]

    steps:
    - uses: actions/checkout@v3

    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements-dev.txt

    - name: Run linting
      run: |
        flake8 src tests --count --select=E9,F63,F7,F82 --show-source --statistics
        black --check src tests
        isort --check-only src tests

    - name: Run tests
      run: |
        pytest tests/ -v --cov=src --cov-report=xml

    - name: Upload coverage to Codecov
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.xml

  build:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'

    steps:
    - uses: actions/checkout@v3

    - name: Build application
      run: |
        python deployment/build.py --platform linux --enable-feature all

    - name: Create Release
      uses: actions/create-release@v1
      env:
        GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
      with:
        tag_name: v${{ github.run_number }}
        release_name: Release v${{ github.run_number }}
```

#### Docker Build Integration
```dockerfile
# Dockerfile.ci
FROM python:3.11-slim

WORKDIR /app
COPY requirements*.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
RUN python setup.py build_ext --inplace

# Run tests
RUN pytest tests/ -v

# Build application
RUN python deployment/build.py --platform linux
```

### Multi-Server Deployment

#### Distributed Architecture Setup
```bash
#!/bin/bash
# deploy_multi_server.sh

# Configuration
SERVERS=("app1.example.com" "app2.example.com" "app3.example.com")
DB_SERVER="db.example.com"
REDIS_SERVERS=("redis1.example.com" "redis2.example.com")

# Deploy database server
echo "Deploying database server on $DB_SERVER"
ssh $DB_SERVER << 'EOF'
sudo apt-get update
sudo apt-get install postgresql-13 postgresql-contrib
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Configure PostgreSQL for replication
sudo -u postgres psql -c "ALTER SYSTEM SET listen_addresses = '*';"
sudo -u postgres psql -c "ALTER SYSTEM SET wal_level = replica;"
sudo -u postgres psql -c "ALTER SYSTEM SET max_wal_senders = 3;"
EOF

# Deploy Redis cluster
for redis_server in "${REDIS_SERVERS[@]}"; do
    echo "Deploying Redis on $redis_server"
    ssh $redis_server << 'EOF'
    sudo apt-get install redis-server
    sudo systemctl enable redis-server
    sudo systemctl start redis-server
    EOF
done

# Deploy application servers
for server in "${SERVERS[@]}"; do
    echo "Deploying application on $server"
    ssh $server << 'EOF'
    sudo apt-get update
    sudo apt-get install python3.11 python3.11-pip nginx

    # Setup application
    sudo useradd -r -s /bin/false privatus
    sudo mkdir -p /opt/privatus-chat/{app,data,config,logs}
    sudo chown -R privatus:privatus /opt/privatus-chat

    # Clone and install
    git clone https://github.com/privatus-chat/privatus-chat.git /opt/privatus-chat/app
    cd /opt/privatus-chat/app
    pip3 install -r requirements.txt
    EOF
done
```

#### Load Balancer Configuration
```nginx
# /etc/nginx/sites-available/privatus-chat
upstream privatus_backend {
    least_conn;
    server app1.example.com:8080 max_fails=3 fail_timeout=30s;
    server app2.example.com:8080 max_fails=3 fail_timeout=30s;
    server app3.example.com:8080 max_fails=3 fail_timeout=30s;
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

### High Availability Configuration

#### Database Clustering
```bash
#!/bin/bash
# setup_db_cluster.sh

MASTER_DB="db1.example.com"
REPLICA_DBS=("db2.example.com" "db3.example.com")

# Setup master database
ssh $MASTER_DB << 'EOF'
sudo -u postgres psql -c "ALTER SYSTEM SET listen_addresses = '*';"
sudo -u postgres psql -c "ALTER SYSTEM SET wal_level = replica;"
sudo -u postgres psql -c "ALTER SYSTEM SET max_wal_senders = 5;"
sudo -u postgres psql -c "ALTER SYSTEM SET wal_keep_size = 1GB;"
sudo systemctl restart postgresql
EOF

# Setup replica databases
for replica in "${REPLICA_DBS[@]}"; do
    echo "Setting up replica on $replica"
    ssh $replica << 'EOF'
    sudo apt-get install postgresql-13 postgresql-contrib

    # Configure replica
    sudo -u postgres psql -c "ALTER SYSTEM SET listen_addresses = '*';"
    sudo -u postgres psql -c "ALTER SYSTEM SET hot_standby = on;"
    sudo -u postgres psql -c "ALTER SYSTEM SET wal_level = replica;"

    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    EOF
done
```

#### Application Clustering
```ini
# /etc/systemd/system/privatus-chat@.service
[Unit]
Description=Privatus-chat Application Server %i
After=network.target postgresql.service redis.service
Requires=postgresql.service redis.service

[Service]
Type=simple
User=privatus
WorkingDirectory=/opt/privatus-chat/app
EnvironmentFile=/opt/privatus-chat/config/.env

# Cluster configuration
Environment=CLUSTER_NODE_ID=%i
Environment=CLUSTER_NODES=app1,app2,app3

ExecStart=/usr/bin/python3 -m gunicorn app:app \
    --bind 0.0.0.0:8080 \
    --workers 4 \
    --worker-class eventlet \
    --max-requests 1000 \
    --keep-alive 2 \
    --log-level info \
    --access-logfile /opt/privatus-chat/logs/access.log \
    --error-logfile /opt/privatus-chat/logs/error.log

ExecReload=/bin/kill -s HUP $MAINPID
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### Enhanced Troubleshooting

#### Debug Mode Operation
```bash
# Run with comprehensive debugging
PRIVATUS_LOG_LEVEL=DEBUG python launch_gui.py \
    --debug \
    --verbose \
    --trace-sql \
    --profile-memory

# Monitor system resources during debugging
htop -p $(pgrep -f privatus-chat)

# Check network connections
ss -tuln | grep :8080
ss -tuln | grep :6881

# Monitor logs in real-time
tail -f /var/log/privatus-chat/*.log
```

#### Performance Analysis
```bash
#!/bin/bash
# performance_analysis.sh

# CPU and Memory profiling
python -m cProfile -o profile.out launch_gui.py
python -m pstats profile.out | sort -k 3

# Network performance testing
iperf3 -c app2.example.com -p 8080

# Database performance analysis
sudo -u postgres psql -d privatus_dev -c "EXPLAIN ANALYZE SELECT * FROM messages WHERE timestamp > NOW() - INTERVAL '1 hour';"

# Memory leak detection
valgrind --tool=memcheck --leak-check=full python launch_gui.py
```

#### Network Diagnostics
```bash
#!/bin/bash
# network_diagnostics.sh

# Test DHT connectivity
echo "Testing DHT connectivity..."
timeout 10s python -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b'test', ('dht.libtorrent.org', 6881))
print('DHT test packet sent')
"

# Check firewall rules
sudo ufw status verbose
sudo iptables -L -n -v

# Test port accessibility
nmap -p 8080,6881 localhost

# Monitor network traffic
sudo tcpdump -i any -n port 8080 or port 6881
```

#### Log Analysis Tools
```bash
#!/bin/bash
# log_analysis.sh

# Extract error patterns
grep -r "ERROR" /var/log/privatus-chat/ | head -20

# Find authentication failures
grep -r "authentication failed" /var/log/privatus-chat/

# Monitor connection patterns
grep -r "connection established" /var/log/privatus-chat/ | wc -l

# Generate log summary
journalctl -u privatus-chat --since "1 hour ago" --no-pager -o json | \
    jq -r '.MESSAGE' | sort | uniq -c | sort -nr
```

### Configuration Examples

#### Production Configuration
```bash
# /opt/privatus-chat/config/production.env
# Database Configuration
DATABASE_URL=postgresql://privatus:secure_password@db1.example.com:5432/privatus_prod
REDIS_URL=redis://redis-cluster.example.com:6379/0

# Security Configuration
SECRET_KEY=your-256-bit-secret-key-here
ENCRYPTION_MASTER_KEY=your-master-key-here
SSL_CERT_FILE=/etc/ssl/certs/privatus-chat.crt
SSL_KEY_FILE=/etc/ssl/private/privatus-chat.key

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
PROMETHEUS_GATEWAY=http://monitoring.example.com:9091

# Cluster Configuration
CLUSTER_ENABLED=true
CLUSTER_NODE_ID=app1
CLUSTER_NODES=app1.example.com,app2.example.com,app3.example.com
```

#### Development Configuration
```bash
# /opt/privatus-chat/config/development.env
# Database Configuration
DATABASE_URL=postgresql://devuser:dev_password@localhost:5432/privatus_dev
REDIS_URL=redis://localhost:6379/1

# Security Configuration (less strict for development)
SECRET_KEY=dev-secret-key-change-in-production
ENCRYPTION_MASTER_KEY=dev-master-key-change-in-production
DEBUG=true

# Network Configuration
BIND_ADDRESS=127.0.0.1
PORT=8080
DHT_PORT=6881

# Performance Configuration
MAX_WORKERS=2
CACHE_SIZE=512MB
MAX_MESSAGE_SIZE=50MB

# Development Configuration
LOG_LEVEL=DEBUG
RELOAD_CODE=true
PROFILE_MEMORY=true
TRACE_SQL=true
```

## Support

For additional support:

- **User Guide**: [Complete User Guide](user-guide.md)
- **FAQ**: [Frequently Asked Questions](faq.md)
- **GitHub Issues**: [Report Issues](https://github.com/privatus-chat/privatus-chat/issues)
- **Discussions**: [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)
- **Production Deployment Guide**: [Production Deployment](production-deployment.md)

---

*Last updated: January 2025*
*Privatus-chat v3.0.0 - Enhanced Deployment Edition*