# Windows Installation Guide

This guide provides detailed instructions for installing Privatus-chat on Windows systems.

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10 version 19041 or later, Windows 11
- **Processor**: 64-bit (x86-64) or ARM64 processor
- **Memory**: 512 MB RAM
- **Storage**: 200 MB available disk space
- **Network**: Internet connection for initial setup

### Recommended Requirements
- **Memory**: 1 GB RAM or more
- **Storage**: 500 MB available disk space
- **Network**: Broadband internet connection

## Installation Methods

### Method 1: MSI Installer (Recommended)

1. **Download the Installer**
   - Visit the [GitHub Releases](https://github.com/privatus-chat/privatus-chat/releases) page
   - Download the latest `.msi` file for Windows

2. **Run the Installer**
   - Double-click the downloaded `.msi` file
   - If prompted by Windows Defender, click "More info" → "Run anyway"

3. **Follow Installation Wizard**
   - Click "Next" to proceed with installation
   - Read and accept the License Agreement
   - Choose installation location (default is recommended)
   - Select components to install:
     - ✅ Privatus-chat Application
     - ✅ Desktop Shortcut
     - ✅ Start Menu Entries
     - ✅ Windows Firewall Exception
   - Click "Install" to begin installation

4. **Complete Installation**
   - Wait for installation to complete
   - Click "Finish" when done

5. **Launch Privatus-chat**
   - Use the desktop shortcut or Start Menu entry
   - Follow the first-time setup wizard

### Method 2: Portable Installation

1. **Download Portable Package**
   - Download the `.zip` file from GitHub Releases

2. **Extract Files**
   - Right-click the `.zip` file and select "Extract All"
   - Choose a destination folder
   - Click "Extract"

3. **Run Privatus-chat**
   - Navigate to the extracted folder
   - Double-click `privatus-chat.exe` to launch

## Post-Installation Setup

### First Launch
1. **Initial Configuration**
   - Privatus-chat will launch with a setup wizard
   - Choose your preferred language
   - Configure basic settings

2. **Network Configuration**
   - The application will automatically configure P2P networking
   - Windows Firewall will be automatically configured
   - No manual port forwarding required

3. **Privacy Settings**
   - Review and adjust privacy settings as needed
   - Enable or disable optional features

### Windows Integration

#### Desktop Shortcut
- A desktop shortcut is created during installation
- Right-click the shortcut to access properties and customization options

#### Start Menu
- Privatus-chat appears in the Start Menu under "P"
- Can be pinned to Start Menu or Taskbar for quick access

#### Windows Firewall
- Automatic firewall exception is created during installation
- Allows P2P communication on ports 8000-9000
- Can be manually configured in Windows Defender Firewall settings

## Uninstallation

### Using Windows Settings
1. Open Windows Settings (Win + I)
2. Go to "Apps" → "Apps & features"
3. Search for "Privatus-chat"
4. Click "Uninstall"
5. Follow the uninstallation wizard

### Using Control Panel
1. Open Control Panel
2. Go to "Programs" → "Programs and Features"
3. Find "Privatus-chat" in the list
4. Right-click and select "Uninstall"
5. Follow the uninstallation wizard

### Manual Uninstallation (Portable)
1. Delete the installation folder
2. Remove desktop shortcut (if created)
3. Remove Start Menu entries (if created)
4. Remove data folder: `%APPDATA%\\Privatus-chat`

## Troubleshooting

### Installation Issues

#### "Windows protected your PC" Warning
- Click "More info" → "Run anyway"
- This is normal for unsigned installers

#### "Installation Failed" Error
- Ensure you have administrator privileges
- Close any running Privatus-chat instances
- Check available disk space
- Temporarily disable antivirus software

#### Missing Dependencies
- The MSI installer includes all required dependencies
- Portable version may require Visual C++ Redistributables
- Download from Microsoft if prompted

### Runtime Issues

#### Application Won't Start
- Check if antivirus is blocking the application
- Ensure Windows version meets minimum requirements
- Try running as administrator

#### Network Connectivity Issues
- Check Windows Firewall settings
- Ensure ports 8000-9000 are not blocked
- Try disabling VPN temporarily for testing

#### Performance Issues
- Close other applications to free up memory
- Check internet connection speed
- Restart the application

### Getting Help

If you encounter issues not covered here:

1. **Check the FAQ**: [Frequently Asked Questions](faq.md)
2. **Search GitHub Issues**: [GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)
3. **Create New Issue**: Report bugs or request features

## Advanced Configuration

### Environment Variables

Privatus-chat respects the following Windows environment variables:

- `PRIVATUS_DATA_DIR`: Custom data directory path
- `PRIVATUS_CONFIG_DIR`: Custom configuration directory path
- `PRIVATUS_LOG_LEVEL`: Set logging level (DEBUG, INFO, WARNING, ERROR)

### Command Line Options

Launch Privatus-chat from Command Prompt with options:

```cmd
privatus-chat.exe --help
privatus-chat.exe --version
privatus-chat.exe --reset-config
privatus-chat.exe --debug
```

### Data Locations

- **Application Data**: `%APPDATA%\\Privatus-chat`
- **Configuration**: `%APPDATA%\\Privatus-chat\\config`
- **Logs**: `%APPDATA%\\Privatus-chat\\logs`
- **Cache**: `%APPDATA%\\Privatus-chat\\cache`

## Security Considerations

### Windows Security Features
- Privatus-chat requests minimal permissions
- Network access is required for P2P communication
- Microphone/camera access only when using voice/video features

### Antivirus Compatibility
- Privatus-chat is compatible with major antivirus software
- Add the installation directory to antivirus exclusions if needed
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
1. Download the latest version from GitHub Releases
2. Run the new installer
3. The installer will update the existing installation
4. User data and settings are preserved

## Advanced Installation Scenarios

### Development Environment Setup

#### Complete Development Stack
```powershell
# Install Chocolatey (if not already installed)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

# Install development dependencies
choco install python311 postgresql redis git visualstudio2022community nodejs

# Install web development tools
npm install -g webpack webpack-cli

# Set up PostgreSQL
& "C:\Program Files\PostgreSQL\13\bin\psql.exe" -c "CREATE USER devuser WITH PASSWORD 'dev_password' CREATEDB;"
& "C:\Program Files\PostgreSQL\13\bin\createdb.exe" -O devuser privatus_dev

# Start Redis
redis-server --service-install
redis-server --service-start

# Clone and setup Privatus-chat
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat
python -m venv venv-dev
venv-dev\Scripts\activate
pip install -r requirements-dev.txt

# Run development server
python launch_gui.py --debug --reload
```

#### Visual Studio Development Setup
```powershell
# Create Visual Studio solution
python deployment/windows_visual_studio.py --create-solution

# Open in Visual Studio
& "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\devenv.exe" Privatus-chat.sln

# Configure for debugging
# Set breakpoints in key files
# Configure debug environment variables
```

#### VS Code Configuration
```powershell
# Install VS Code extensions
code --install-extension ms-python.python
code --install-extension ms-python.black-formatter
code --install-extension ms-python.isort
code --install-extension ms-python.pylint

# Create workspace settings
New-Item -ItemType Directory -Path .vscode -Force
@"
{
    "python.defaultInterpreterPath": "./venv-dev/Scripts/python.exe",
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black",
    "python.testing.pytestEnabled": true,
    "python.testing.pytestArgs": ["tests"],
    "files.associations": {
        "*.py": "python"
    }
}
"@ | Out-File -FilePath .vscode\settings.json -Encoding UTF8
```

### CI/CD Pipeline Integration

#### GitHub Actions for Windows
```yaml
# .github/workflows/windows-build.yml
name: Windows Build and Test

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: windows-latest
    strategy:
      matrix:
        python-version: ['3.9', '3.10', '3.11']

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

    - name: Run tests
      run: |
        pytest tests/ -v --cov=src

    - name: Build MSI installer
      run: |
        python deployment/windows_installer.py --version 3.0.0

    - name: Upload artifacts
      uses: actions/upload-artifact@v3
      with:
        name: privatus-chat-windows
        path: dist/privatus-chat*.msi
```

#### Azure DevOps Pipeline
```yaml
# azure-pipelines.yml
jobs:
- job: Windows
  pool:
    vmImage: 'windows-latest'
  strategy:
    matrix:
      Python39:
        python.version: '3.9'
      Python310:
        python.version: '3.10'
      Python311:
        python.version: '3.11'

  steps:
  - script: |
      python -m pip install --upgrade pip
      pip install -r requirements-dev.txt

  - script: |
      pytest tests/ -v --cov=src --cov-report=xml

  - task: PublishCodeCoverageResults@1
    inputs:
      codeCoverageTool: 'Cobertura'
      summaryFileLocation: '$(System.DefaultWorkingDirectory)/coverage.xml'

  - script: |
      python deployment/build.py --platform windows

  - task: PublishBuildArtifacts@1
    inputs:
      pathToPublish: 'dist'
      artifactName: 'privatus-chat-windows'
```

### Multi-Server Deployment

#### Windows Server Farm Setup
```powershell
# deploy_windows_servers.ps1

# Configuration
$Servers = @("win-server-1", "win-server-2", "win-server-3")
$DatabaseServer = "win-db-server"

# Deploy database server
Write-Host "Deploying database server on $DatabaseServer"
Invoke-Command -ComputerName $DatabaseServer -ScriptBlock {
    # Install SQL Server Express
    choco install sql-server-express

    # Configure database
    & "C:\Program Files\Microsoft SQL Server\140\Tools\Binn\sqlcmd.exe" -Q "CREATE DATABASE privatus_prod;"

    # Install Redis
    choco install redis-64
}

# Deploy application servers
foreach ($Server in $Servers) {
    Write-Host "Deploying application on $Server"
    Invoke-Command -ComputerName $Server -ScriptBlock {
        # Install IIS for load balancing
        Install-WindowsFeature -Name Web-Server, Web-Mgmt-Console

        # Install Python
        choco install python311

        # Create application user
        New-LocalUser -Name "privatus" -Description "Privatus-chat Service User" -NoPassword

        # Create directories
        New-Item -ItemType Directory -Path "C:\Program Files\Privatus-chat" -Force
        New-Item -ItemType Directory -Path "C:\Program Files\Privatus-chat\app" -Force
        New-Item -ItemType Directory -Path "C:\Program Files\Privatus-chat\data" -Force
        New-Item -ItemType Directory -Path "C:\Program Files\Privatus-chat\config" -Force
        New-Item -ItemType Directory -Path "C:\Program Files\Privatus-chat\logs" -Force

        # Set permissions
        $Acl = Get-Acl "C:\Program Files\Privatus-chat"
        $Rule = New-Object System.Security.AccessControl.FileSystemAccessRule("privatus","FullControl","ContainerInherit,ObjectInherit","None","Allow")
        $Acl.SetAccessRule($Rule)
        Set-Acl "C:\Program Files\Privatus-chat" $Acl

        # Clone and install application
        git clone https://github.com/privatus-chat/privatus-chat.git "C:\Program Files\Privatus-chat\app"
        cd "C:\Program Files\Privatus-chat\app"
        python -m venv venv
        venv\Scripts\activate
        pip install -r requirements.txt
    }
}
```

#### IIS Load Balancer Configuration
```powershell
# setup_iis_loadbalancer.ps1

# Install ARR (Application Request Routing)
choco install urlrewrite arr

# Configure load balancing
Import-Module WebAdministration

# Create server farm
New-IISServerFarm -Name "PrivatusFarm" -FarmURL "http://localhost:8080"

# Add servers to farm
Add-IISServerFarmMember -Name "PrivatusFarm" -ComputerName "win-server-1:8080"
Add-IISServerFarmMember -Name "PrivatusFarm" -ComputerName "win-server-2:8080"
Add-IISServerFarmMember -Name "PrivatusFarm" -ComputerName "win-server-3:8080"

# Configure health check
Set-IISServerFarmHealthCheck -Name "PrivatusFarm" -Path "/health" -Interval "00:00:30" -Timeout "00:00:10"
```

### High Availability Configuration

#### Windows Clustering
```powershell
# setup_windows_cluster.ps1

# Install Failover Clustering
Install-WindowsFeature -Name Failover-Clustering -IncludeManagementTools

# Create cluster
New-Cluster -Name "PrivatusCluster" -Node @("win-server-1", "win-server-2", "win-server-3") -AdministrativeAccessPoint ActiveDirectoryAndDns

# Configure cluster resources
Add-ClusterGenericApplicationRole -Name "PrivatusApp" -CommandLine "powershell.exe -File C:\Program Files\Privatus-chat\app\start-app.ps1" -StartupParameters "" -ErrorAction Stop

# Configure cluster storage
New-StoragePool -FriendlyName "PrivatusStorage" -StorageSubsystemFriendlyName "Storage Spaces*" -PhysicalDisks (Get-PhysicalDisk -CanPool $true)
New-VirtualDisk -FriendlyName "PrivatusData" -StoragePoolFriendlyName "PrivatusStorage" -Size 100GB -ProvisioningType Thin
```

#### Windows Service Configuration
```xml
<!-- Privatus-chat Windows Service Configuration -->
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="DATABASE_URL" value="Server=db-server;Database=privatus_prod;Integrated Security=true;" />
    <add key="REDIS_URL" value="redis-server:6379" />
    <add key="SECRET_KEY" value="your-secret-key-here" />
    <add key="ENCRYPTION_MASTER_KEY" value="your-master-key-here" />
    <add key="BIND_ADDRESS" value="0.0.0.0" />
    <add key="PORT" value="8080" />
    <add key="DHT_PORT" value="6881" />
    <add key="LOG_LEVEL" value="INFO" />
    <add key="MAX_WORKERS" value="8" />
    <add key="CACHE_SIZE" value="2GB" />
  </appSettings>
</configuration>
```

### Enhanced Troubleshooting

#### Debug Mode Operation
```cmd
REM Run with comprehensive debugging
set PRIVATUS_LOG_LEVEL=DEBUG
python launch_gui.py --debug --verbose --trace-sql --profile-memory

REM Monitor system resources
taskmgr

REM Check network connections
netstat -an | findstr :8080
netstat -an | findstr :6881

REM Monitor logs in real-time
powershell "Get-Content C:\Program Files\Privatus-chat\logs\*.log -Wait"
```

#### Windows Event Viewer Analysis
```powershell
# View application events
Get-EventLog -LogName Application -Newest 50 | Where-Object {$_.Source -like "*Privatus*"}

# Search for specific errors
Get-EventLog -LogName Application | Where-Object {$_.Message -like "*ERROR*"}

# Monitor real-time events
Get-EventLog -LogName Application -Newest 10 | ForEach-Object {
    Register-ObjectEvent -InputObject $_.Source -EventName "EntryWritten" -Action {
        Write-Host $event.SourceEventArgs.Entry.Message
    }
}
```

#### Network Diagnostics
```powershell
# Test DHT connectivity
$udpClient = New-Object System.Net.Sockets.UdpClient
$udpClient.Connect("dht.libtorrent.org", 6881)
$byteArray = [Text.Encoding]::ASCII.GetBytes("test")
$udpClient.Send($byteArray, $byteArray.Length)

# Check Windows Firewall
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Privatus*"}

# Test port accessibility
Test-NetConnection -ComputerName localhost -Port 8080
Test-NetConnection -ComputerName localhost -Port 6881

# Monitor network traffic
netsh trace start capture=yes tracefile=privatus-trace.etl
# ... run application ...
netsh trace stop
```

#### Performance Profiling
```powershell
# CPU profiling with Windows Performance Toolkit
wpr.exe -start CPU -start DotNet

# Run application
python launch_gui.py

# Stop profiling
wpr.exe -stop profile.etl

# View results
wpa.exe profile.etl

# Memory profiling
# Install DebugDiag or use built-in tools
```

### Configuration Examples

#### Production Configuration
```powershell
# C:\Program Files\Privatus-chat\config\production.env
# Database Configuration
DATABASE_URL=Server=win-db-server;Database=privatus_prod;Integrated Security=true;Connection Timeout=30;
REDIS_URL=redis-server:6379,allowAdmin=true,password=secure_redis_password

# Security Configuration
SECRET_KEY=your-256-bit-secret-key-here
ENCRYPTION_MASTER_KEY=your-master-key-here
SSL_CERT_FILE=C:\ssl\privatus-chat.crt
SSL_KEY_FILE=C:\ssl\privatus-chat.key

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

# Windows-specific Configuration
SERVICE_ENABLED=true
EVENT_LOG_ENABLED=true
PERFORMANCE_COUNTERS_ENABLED=true
```

#### Development Configuration
```powershell
# C:\Program Files\Privatus-chat\config\development.env
# Database Configuration
DATABASE_URL=Server=localhost;Database=privatus_dev;Integrated Security=true;
REDIS_URL=localhost:6379

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
VISUAL_STUDIO_DEBUG=true
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