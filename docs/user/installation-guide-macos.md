# macOS Installation Guide

This guide provides detailed instructions for installing Privatus-chat on macOS systems.

## System Requirements

### Minimum Requirements
- **Operating System**: macOS 10.15 (Catalina) or later
- **Processor**: Intel 64-bit or Apple Silicon (ARM64)
- **Memory**: 512 MB RAM
- **Storage**: 200 MB available disk space
- **Network**: Internet connection for initial setup

### Recommended Requirements
- **Operating System**: macOS 12.0 (Monterey) or later
- **Memory**: 1 GB RAM or more
- **Storage**: 500 MB available disk space
- **Network**: Broadband internet connection

## Installation Methods

### Method 1: DMG Installation (Recommended)

1. **Download the DMG**
   - Visit the [GitHub Releases](https://github.com/privatus-chat/privatus-chat/releases) page
   - Download the latest `.dmg` file for macOS

2. **Mount the DMG**
   - Double-click the downloaded `.dmg` file
   - This will mount the disk image and open a Finder window

3. **Install the Application**
   - Drag the "Privatus-chat" application from the DMG window
   - Drop it into your "Applications" folder
   - macOS may prompt for authentication

4. **Eject the DMG**
   - Close the DMG window
   - Eject the mounted disk image from Finder or Desktop

5. **Launch Privatus-chat**
   - Open the Applications folder
   - Double-click "Privatus-chat" to launch
   - Follow the first-time setup wizard

### Method 2: Homebrew Installation (Alternative)

1. **Install Homebrew** (if not already installed)
   ```bash
   /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
   ```

2. **Add Privatus-chat Tap** (when available)
   ```bash
   brew tap privatus-chat/privatus-chat
   brew install privatus-chat
   ```

3. **Launch Privatus-chat**
   ```bash
   open /Applications/Privatus-chat.app
   ```

### Method 3: Portable Installation

1. **Download Portable Package**
   - Download the `.tar.gz` file from GitHub Releases

2. **Extract Files**
   ```bash
   tar -xzf privatus-chat-3.0.0-macos.tar.gz
   ```

3. **Run Privatus-chat**
   ```bash
   cd privatus-chat-3.0.0-macos
   ./Privatus-chat.app/Contents/MacOS/Privatus-chat
   ```

## Post-Installation Setup

### First Launch
1. **Initial Configuration**
   - Privatus-chat will launch with a setup wizard
   - Choose your preferred language
   - Configure basic settings

2. **macOS Integration**
   - The application integrates with macOS security features
   - Privacy permissions will be requested as needed
   - Dock icon and menu bar integration

3. **Privacy Settings**
   - Review and adjust privacy settings as needed
   - Enable or disable optional features

### macOS Integration

#### Dock Integration
- Privatus-chat appears in the Dock when running
- Right-click the Dock icon for quick actions
- Can be configured to launch at startup

#### Menu Bar
- Privatus-chat can show status in the menu bar
- Access preferences and quit from menu bar icon

#### Finder Integration
- Application appears in Applications folder
- Can be added to Spotlight for quick launching

#### Gatekeeper and Security
- macOS Gatekeeper may show security warnings
- Allow the application in System Preferences → Security & Privacy
- Application is code-signed for security

## Privacy Permissions

Privatus-chat requests the following permissions on macOS:

### Required Permissions
- **Local Network**: For peer-to-peer communication
- **File Access**: For sharing and receiving files

### Optional Permissions
- **Microphone**: For voice calls (when using voice features)
- **Camera**: For video calls (when using video features)
- **Contacts**: For easier contact management (optional)

### Managing Permissions
1. Go to System Preferences → Security & Privacy → Privacy
2. Select the permission type from the sidebar
3. Check or uncheck Privatus-chat as needed

## Uninstallation

### Using Finder
1. Open the Applications folder
2. Drag "Privatus-chat" to the Trash
3. Empty the Trash to complete removal

### Using Terminal
```bash
sudo rm -rf /Applications/Privatus-chat.app
rm -rf ~/Library/Application\ Support/Privatus-chat
rm -rf ~/Library/Caches/com.privatus.chat
rm -rf ~/Library/Logs/Privatus-chat
```

### Remove User Data
```bash
rm -rf ~/Library/Application\ Support/Privatus-chat
rm -rf ~/Library/Caches/com.privatus.chat
rm -rf ~/Library/Logs/Privatus-chat
```

## Troubleshooting

### Installation Issues

#### Gatekeeper Blocks Installation
1. Open System Preferences → Security & Privacy
2. Click "Open Anyway" for the blocked application
3. Alternatively, allow apps from "App Store and identified developers"

#### "Application is Damaged" Error
- This occurs with unsigned applications
- Remove quarantine attribute:
  ```bash
  xattr -rd com.apple.quarantine /Applications/Privatus-chat.app
  ```

#### Permission Denied Errors
- Ensure you have administrator privileges
- Check available disk space
- Verify macOS version compatibility

### Runtime Issues

#### Application Won't Start
- Check Console.app for error messages
- Ensure macOS version meets requirements
- Try removing and reinstalling

#### Network Connectivity Issues
- Check macOS Firewall settings
- Ensure ports 8000-9000 are not blocked
- Check network configuration

#### Performance Issues
- Close other applications to free up memory
- Check Activity Monitor for resource usage
- Restart the application

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

### Command Line Options

Launch Privatus-chat from Terminal with options:

```bash
/Applications/Privatus-chat.app/Contents/MacOS/Privatus-chat --help
/Applications/Privatus-chat.app/Contents/MacOS/Privatus-chat --version
/Applications/Privatus-chat.app/Contents/MacOS/Privatus-chat --reset-config
```

### Data Locations

- **Application Data**: `~/Library/Application Support/Privatus-chat`
- **Configuration**: `~/Library/Application Support/Privatus-chat/config`
- **Logs**: `~/Library/Logs/Privatus-chat`
- **Cache**: `~/Library/Caches/com.privatus.chat`

## Security Considerations

### macOS Security Features
- Privatus-chat requests minimal permissions
- Network access is required for P2P communication
- Microphone/camera access only when using voice/video features

### Antivirus Compatibility
- Privatus-chat is compatible with major macOS antivirus software
- Add the application to antivirus exclusions if needed
- Report false positives to the antivirus vendor

### Privacy Protection
- All data is encrypted locally before transmission
- No personal information is collected
- P2P connections are end-to-end encrypted

## Updates

### Automatic Updates
- Privatus-chat can check for updates automatically
- Updates are downloaded and installed with user approval
- Previous versions are backed up before updating

### Manual Updates
1. Download the latest DMG from GitHub Releases
2. Mount the new DMG
3. Drag the new version to Applications (replaces old version)
4. User data and settings are preserved

## Apple Silicon (M1/M2) Support

Privatus-chat provides native support for Apple Silicon Macs:

- **Universal Binary**: Runs natively on both Intel and Apple Silicon
- **Performance**: Optimized for Apple Silicon performance
- **Compatibility**: Full feature compatibility on all Macs

## Advanced Installation Scenarios

### Development Environment Setup

#### Complete Development Stack
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not already installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install development dependencies
brew install python@3.11 postgresql redis node@18 docker docker-compose

# Start services
brew services start postgresql
brew services start redis

# Create development database
createdb privatus_dev

# Clone and setup Privatus-chat
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat
python3 -m venv venv-dev
source venv-dev/bin/activate
pip install -r requirements-dev.txt

# Install web dependencies for development
npm install -g webpack webpack-cli

# Run development server
python launch_gui.py --debug --reload
```

#### Xcode Development Setup
```bash
# Create Xcode project for native development
mkdir -p xcode-project
cd xcode-project

# Generate Xcode project files
python setup.py xcode-project

# Open in Xcode
open Privatus-chat.xcodeproj
```

#### Visual Studio Code Configuration
```bash
# Install VS Code extensions
code --install-extension ms-python.python
code --install-extension ms-python.black-formatter
code --install-extension ms-python.isort
code --install-extension ms-python.pylint

# Create workspace settings
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

#### GitHub Actions for macOS
```yaml
# .github/workflows/macos-build.yml
name: macOS Build and Test

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: macos-latest
    steps:
    - uses: actions/checkout@v3

    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'

    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements-dev.txt

    - name: Run tests
      run: |
        pytest tests/ -v --cov=src

    - name: Build application
      run: |
        python deployment/build.py --platform macos

    - name: Create DMG
      run: |
        python deployment/macos_dmg_builder.py --version 3.0.0

    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: privatus-chat-macos
        path: dist/privatus-chat*.dmg
```

#### Xcode Cloud Integration
```yaml
# .xcode-cloud.yml
version: 1
workflows:
  build_and_test:
    name: Build and Test
    environment: macos.xcode14
    scripts:
      - name: Install dependencies
        script: |
          pip3 install -r requirements-dev.txt
      - name: Run tests
        script: |
          pytest tests/ -v
      - name: Build application
        script: |
          python deployment/build.py --platform macos
    artifacts:
      - path: dist/privatus-chat*.dmg
```

### Multi-Server Deployment

#### macOS Server Farm Setup
```bash
#!/bin/bash
# deploy_macos_servers.sh

# Configuration
SERVERS=("mac-mini-1.local" "mac-mini-2.local" "mac-mini-3.local")
DB_SERVER="mac-pro.local"

# Deploy database server
echo "Deploying database server on $DB_SERVER"
ssh $DB_SERVER << 'EOF'
brew install postgresql redis

# Configure PostgreSQL
brew services start postgresql
createdb privatus_prod

# Configure Redis
brew services start redis
EOF

# Deploy application servers
for server in "${SERVERS[@]}"; do
    echo "Deploying application on $server"
    ssh $server << 'EOF'
    # Install dependencies
    brew install python@3.11 nginx

    # Setup application user and directories
    sudo dscl . -create /Users/privatus
    sudo dscl . -create /Users/privatus UserShell /bin/bash
    sudo dscl . -create /Users/privatus RealName "Privatus-chat User"
    sudo dscl . -passwd /Users/privatus secure_password

    sudo mkdir -p /Applications/Privatus-chat
    sudo chown -R privatus /Applications/Privatus-chat

    # Clone and install application
    git clone https://github.com/privatus-chat/privatus-chat.git /Applications/Privatus-chat/app
    cd /Applications/Privatus-chat/app
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    EOF
done
```

#### Load Balancer Configuration (macOS)
```bash
#!/bin/bash
# setup_load_balancer.sh

# Install and configure nginx
brew install nginx

# Create load balancer configuration
sudo tee /usr/local/etc/nginx/nginx.conf << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream privatus_backend {
        least_conn;
        server mac-mini-1.local:8080 max_fails=3 fail_timeout=30s;
        server mac-mini-2.local:8080 max_fails=3 fail_timeout=30s;
        server mac-mini-3.local:8080 max_fails=3 fail_timeout=30s;
    }

    server {
        listen 80;
        server_name chat.example.com;

        location /health {
            proxy_pass http://privatus_backend/health;
        }

        location /api/ {
            proxy_pass http://privatus_backend;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }

        location /ws/ {
            proxy_pass http://privatus_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
EOF

# Start nginx
sudo brew services start nginx
```

### High Availability Configuration

#### Database Clustering with PostgreSQL
```bash
#!/bin/bash
# setup_db_cluster_macos.sh

MASTER_DB="mac-pro-1.local"
REPLICA_DBS=("mac-pro-2.local" "mac-pro-3.local")

# Setup master database
ssh $MASTER_DB << 'EOF'
brew install postgresql

# Configure PostgreSQL for replication
echo "wal_level = replica" >> /usr/local/var/postgres/postgresql.conf
echo "max_wal_senders = 3" >> /usr/local/var/postgres/postgresql.conf

brew services restart postgresql

# Create replication user
psql -c "CREATE USER replicator REPLICATION LOGIN ENCRYPTED PASSWORD 'replica_password';"
EOF

# Setup replica databases
for replica in "${REPLICA_DBS[@]}"; do
    echo "Setting up replica on $replica"
    ssh $replica << 'EOF'
    brew install postgresql

    # Configure as replica
    echo "hot_standby = on" >> /usr/local/var/postgres/postgresql.conf

    brew services start postgresql
    EOF
done
```

#### Application LaunchDaemon Configuration
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.privatus.chat.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/Privatus-chat/venv/bin/python</string>
        <string>/Applications/Privatus-chat/app/launch_gui.py</string>
        <string>--daemon</string>
        <string>--config</string>
        <string>/Applications/Privatus-chat/config/production.env</string>
    </array>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PRIVATUS_LOG_LEVEL</key>
        <string>INFO</string>
        <key>PRIVATUS_DATA_DIR</key>
        <string>/Applications/Privatus-chat/data</string>
    </dict>
    <key>WorkingDirectory</key>
    <string>/Applications/Privatus-chat/app</string>
    <key>StandardOutPath</key>
    <string>/Applications/Privatus-chat/logs/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/Applications/Privatus-chat/logs/stderr.log</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>UserName</key>
    <string>privatus</string>
</dict>
</plist>
```

### Enhanced Troubleshooting

#### Debug Mode Operation
```bash
# Run with comprehensive debugging
PRIVATUS_LOG_LEVEL=DEBUG python launch_gui.py \
    --debug \
    --verbose \
    --trace-sql \
    --profile-memory \
    --development

# Monitor system resources
top -pid $(pgrep -f privatus-chat)

# Check network connections
lsof -i :8080
lsof -i :6881

# Monitor logs in real-time
tail -f /Applications/Privatus-chat/logs/*.log
```

#### Console.app Log Analysis
```bash
# View application logs in Console
/Applications/Console.app/Contents/MacOS/Console ~/Library/Logs/Privatus-chat/

# Search for specific errors
grep -r "ERROR" ~/Library/Logs/Privatus-chat/

# Monitor system logs
log stream --predicate 'process == "Privatus-chat"'
```

#### Network Diagnostics
```bash
#!/bin/bash
# network_diagnostics_macos.sh

# Test DHT connectivity
echo "Testing DHT connectivity..."
timeout 10s python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(b'test', ('dht.libtorrent.org', 6881))
print('DHT test packet sent')
"

# Check firewall settings
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --list

# Test port accessibility
nc -zv localhost 8080
nc -zv localhost 6881

# Monitor network traffic
sudo tcpdump -i en0 -n port 8080 or port 6881
```

#### Performance Profiling
```bash
#!/bin/bash
# performance_profiling_macos.sh

# CPU profiling with Instruments
xcrun xctrace record --template 'CPU Profiler' --output profile.trace --launch /Applications/Privatus-chat/venv/bin/python -- /Applications/Privatus-chat/app/launch_gui.py

# Memory profiling
xcrun xctrace record --template 'Memory' --output memory.trace --launch /Applications/Privatus-chat/venv/bin/python -- /Applications/Privatus-chat/app/launch_gui.py

# Network profiling
xcrun xctrace record --template 'Network' --output network.trace --launch /Applications/Privatus-chat/venv/bin/python -- /Applications/Privatus-chat/app/launch_gui.py

# Convert traces to view in Instruments
xcrun xctrace export --input profile.trace --output profile.json
```

### Configuration Examples

#### Production Configuration
```bash
# /Applications/Privatus-chat/config/production.env
# Database Configuration
DATABASE_URL=postgresql://privatus:secure_password@mac-pro.local:5432/privatus_prod
REDIS_URL=redis://redis-cluster.local:6379/0

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

# macOS-specific Configuration
LAUNCHD_ENABLED=true
KEYCHAIN_ENABLED=true
NOTIFICATIONS_ENABLED=true
```

#### Development Configuration
```bash
# /Applications/Privatus-chat/config/development.env
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
XCODE_DEBUG=true
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