# Privatus-chat Installation Guide

Welcome to Privatus-chat, the secure and anonymous messaging platform that prioritizes your privacy. This comprehensive guide covers installation across all supported platforms with enhanced deployment options.

## Table of Contents
- [System Requirements](#system-requirements)
- [Quick Install](#quick-install)
- [Platform-Specific Installation](#platform-specific-installation)
- [Advanced Installation Options](#advanced-installation-options)
- [First-Time Setup](#first-time-setup)
- [Troubleshooting](#troubleshooting)
- [Verifying Installation](#verifying-installation)
- [Deployment Information](#deployment-information)

## System Requirements

### Minimum Requirements
- **Operating System**:
  - Windows 10 version 19041+ / Windows 11
  - macOS 10.15 (Catalina) or later
  - Linux: Ubuntu 20.04+, Fedora 37+, Debian 11+, or compatible distributions
- **Processor**: 64-bit (x86-64) or ARM64 processor
- **RAM**: 512 MB (1 GB recommended for enhanced features)
- **Storage**: 200 MB available space (500 MB recommended)
- **Network**: Internet connection for initial setup and P2P communication
- **Python**: 3.11 or higher (automatically included in packages)

### Recommended Requirements
- **RAM**: 1 GB or more for optimal performance
- **Storage**: 500 MB available space for full feature set
- **Network**: Broadband internet for voice/video calls and file transfer
- **Display**: 1280x720 resolution or higher
- **Audio**: Microphone and speakers for voice communication
- **Camera**: Webcam for video calls (optional)

### Enhanced Features Requirements
- **File Transfer**: Additional storage for cached files
- **Voice Calls**: Microphone and audio drivers
- **Video Calls**: Webcam and compatible video drivers
- **Performance Monitoring**: Additional RAM for detailed metrics
- **Security Testing**: Compatible security frameworks

## Quick Install

### For Most Users (Pre-built Packages)

Choose your platform for detailed installation instructions:

**🪟 Windows**: [MSI Installer Guide](installation-guide-windows.md)
- Download and run `privatus-chat-setup.msi`
- Includes automatic Windows integration and firewall configuration
- Supports both x64 and ARM64 architectures

**🍎 macOS**: [DMG Installer Guide](installation-guide-macos.md)
- Download and open `privatus-chat.dmg`, drag to Applications
- Universal binary supporting Intel and Apple Silicon Macs
- Includes proper macOS security entitlements and privacy permissions

**🐧 Linux**: [Multi-Distribution Guide](installation-guide-linux.md)
- **DEB Package**: `sudo dpkg -i privatus-chat.deb` (Ubuntu/Debian)
- **RPM Package**: `sudo rpm -i privatus-chat.rpm` (Fedora/RHEL)
- **AppImage**: Portable, no installation needed
- **Snap Package**: Available for modern distributions

### Advanced Installation Options

**🐳 Docker Deployment**:
```bash
# Pull the latest image
docker pull privatus-chat/privatus-chat:latest

# Run with Docker Compose
docker-compose -f deployment/docker-compose.yml up
```

**🔧 From Source**:
```bash
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat
pip install -r requirements.txt
python launch_gui.py
```

**📦 Development Build**:
```bash
# Enhanced build with all features
python deployment/build.py --enable-feature file_transfer voice_calls performance_monitoring

# Cross-platform deployment
python deployment/deploy.py --cross-platform --version 3.0.0
```

## Windows Installation

### Method 1: MSI Installer (Recommended)

1. **Download the Installer**
   - Visit the [Privatus-chat releases page](https://github.com/privatus-chat/releases)
   - Download `privatus-chat-setup.msi`

2. **Run the Installer**
   - Double-click the downloaded MSI file
   - If Windows SmartScreen appears, click "More info" then "Run anyway"
   - Follow the installation wizard:
     - Accept the license agreement
     - Choose installation directory (default: `C:\Program Files\Privatus-chat`)
     - Select start menu folder
     - Choose whether to create desktop shortcut

3. **Complete Installation**
   - Click "Install" to begin
   - Wait for installation to complete
   - Click "Finish" to exit the wizard

### Method 2: Portable ZIP

1. **Download Portable Version**
   - Download `privatus-chat-windows-portable.zip`
   - Extract to your desired location

2. **Run Privatus-chat**
   - Navigate to the extracted folder
   - Double-click `privatus-chat.exe`

### Method 3: Install from Source

```powershell
# Prerequisites
# Install Python 3.8+ from python.org
# Install Git from git-scm.com

# Clone repository
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat

# Create virtual environment
python -m venv venv
.\venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run application
python src/main.py
```

## macOS Installation

### Method 1: DMG Package (Recommended)

1. **Download the DMG**
   - Visit the [Privatus-chat releases page](https://github.com/privatus-chat/releases)
   - Download `privatus-chat.dmg`

2. **Install the Application**
   - Double-click the downloaded DMG file
   - Drag the Privatus-chat icon to the Applications folder
   - Eject the DMG when done

3. **First Launch**
   - Open Applications folder
   - Double-click Privatus-chat
   - If macOS security warning appears:
     - Go to System Preferences → Security & Privacy
     - Click "Open Anyway" next to the Privatus-chat message

### Method 2: Homebrew (Coming Soon)

```bash
# Install via Homebrew Cask
brew install --cask privatus-chat
```

### Method 3: Install from Source

```bash
# Prerequisites
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python 3.8+
brew install python@3.11

# Clone repository
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python src/main.py
```

## Linux Installation

### Method 1: Debian/Ubuntu (DEB Package)

```bash
# Download the DEB package
wget https://github.com/privatus-chat/releases/download/latest/privatus-chat.deb

# Install the package
sudo dpkg -i privatus-chat.deb

# Fix any dependency issues
sudo apt-get install -f

# Launch from terminal or applications menu
privatus-chat
```

### Method 2: Fedora/RHEL (RPM Package)

```bash
# Download the RPM package
wget https://github.com/privatus-chat/releases/download/latest/privatus-chat.rpm

# Install the package
sudo rpm -i privatus-chat.rpm

# Or using dnf
sudo dnf install privatus-chat.rpm

# Launch from terminal or applications menu
privatus-chat
```

### Method 3: AppImage (Universal)

```bash
# Download AppImage
wget https://github.com/privatus-chat/releases/download/latest/privatus-chat.AppImage

# Make executable
chmod +x privatus-chat.AppImage

# Run directly (no installation needed)
./privatus-chat.AppImage
```

### Method 4: Install from Source

```bash
# Install prerequisites
# For Ubuntu/Debian:
sudo apt-get update
sudo apt-get install python3 python3-pip python3-venv git

# For Fedora:
sudo dnf install python3 python3-pip git

# Clone repository
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run application
python src/main.py
```

## First-Time Setup

When you launch Privatus-chat for the first time:

1. **Welcome Screen**
   - Read the privacy introduction
   - Click "Get Started"

2. **Identity Creation**
   - Choose a display name (can be anonymous)
   - The app will generate secure encryption keys
   - Save your recovery phrase in a safe place

3. **Privacy Settings**
   - Select your desired privacy level:
     - **Minimal**: Basic encryption, faster performance
     - **Standard**: Balanced privacy and usability (recommended)
     - **High**: Enhanced anonymity features
     - **Maximum**: Full anonymity with all privacy features

4. **Network Configuration**
   - Most users can use default settings
   - Advanced users can configure:
     - Custom ports
     - Proxy settings
     - Bridge relays for censorship circumvention

5. **Complete Setup**
   - Review your settings
   - Click "Start Using Privatus-chat"

## Platform-Specific Installation

For detailed installation instructions for each platform, please refer to the dedicated guides:

### Windows Installation
- **[Complete Windows Guide](installation-guide-windows.md)**
- MSI installer with Windows integration
- Portable ZIP option available
- Automatic firewall and security configuration
- Desktop and Start Menu integration

### macOS Installation
- **[Complete macOS Guide](installation-guide-macos.md)**
- DMG installer with drag-and-drop installation
- Universal binary for Intel and Apple Silicon
- Proper macOS security entitlements
- Privacy permissions and Gatekeeper support

### Linux Installation
- **[Complete Linux Guide](installation-guide-linux.md)**
- Multi-distribution support (DEB, RPM, AppImage, Snap)
- Desktop environment integration
- Package manager integration
- System service support

## Advanced Installation Options

### Docker Deployment
Privatus-chat provides enhanced Docker support with multi-stage builds:

```bash
# Basic deployment
docker run -d --name privatus-chat \
  -p 8000-9000:8000-9000 \
  -v privatus_data:/app/data \
  privatus-chat/privatus-chat:latest

# Development environment
docker run -d --name privatus-dev \
  -p 8001:8000 \
  -v $(pwd):/app \
  privatus-chat/privatus-chat:development

# Production with Docker Compose
docker-compose -f deployment/docker-compose.yml up -d
```

### Development Build
For developers and advanced users:

```bash
# Enhanced build with all features
python deployment/build.py \
  --enable-feature file_transfer voice_calls performance_monitoring security_testing \
  --platform all

# Cross-platform deployment
python deployment/deploy.py \
  --cross-platform \
  --version 3.0.0 \
  --github --docker --local

# Release management
python deployment/release_manager.py \
  --full-release \
  --version-type minor
```

## Troubleshooting

For comprehensive troubleshooting information, see the **[Deployment Troubleshooting Guide](deployment-troubleshooting.md)**.

### Common Issues

**Application Won't Start**
- Ensure system requirements are met
- Check antivirus/security software isn't blocking
- Verify all dependencies are installed
- Check application logs for error details

**Network Connection Issues**
- Verify firewall settings and port accessibility (8000-9000)
- Check network configuration and proxy settings
- Test with VPN disabled temporarily
- Verify P2P connectivity

**Installation Errors**
- Run installer with administrator/root privileges
- Temporarily disable antivirus during installation
- Check system logs for detailed error information
- Ensure sufficient disk space is available

### Getting Help

If you encounter issues:

1. **[Deployment Troubleshooting Guide](deployment-troubleshooting.md)**
2. **[FAQ](faq.md)**
3. Search [existing GitHub issues](https://github.com/privatus-chat/privatus-chat/issues)
4. [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)
5. Create a [new issue](https://github.com/privatus-chat/privatus-chat/issues/new)

## Verifying Installation

### Security Verification

All Privatus-chat releases are cryptographically signed. To verify:

**Windows:**
- Right-click the installer → Properties → Digital Signatures
- Verify the signature is valid and from "Privatus-chat Team"

**macOS:**
```bash
# Verify code signature
codesign -v /Applications/Privatus-chat.app
```

**Linux:**
```bash
# Verify GPG signature
gpg --verify privatus-chat.deb.sig privatus-chat.deb
```

### Checking Installation

After installation, verify everything is working:

1. Launch Privatus-chat
2. Check Help → About for version information
3. Run connection test: Settings → Network → Test Connection
4. Verify encryption: Settings → Security → Run Self-Test

## Deployment Information

### Enhanced Deployment Features

Privatus-chat v3.0.0 includes comprehensive deployment infrastructure:

#### Cross-Platform Packages
- **Windows**: MSI installer with Windows integration
- **macOS**: DMG installer with universal binary support
- **Linux**: DEB, RPM, AppImage, and Snap packages
- **Docker**: Multi-stage builds with development/production variants

#### Advanced Build System
- **Feature Support**: File transfer, voice calls, performance monitoring, security testing
- **Environment-Based Configuration**: Development, testing, and production environments
- **Automated Testing**: Comprehensive CI/CD pipeline with quality gates
- **Security Hardening**: Code signing, dependency verification, and security scanning

#### Deployment Automation
- **GitHub Actions**: Complete CI/CD workflows
- **Release Management**: Automated versioning and changelog generation
- **Multi-Platform Deployment**: Simultaneous deployment to all platforms
- **Rollback Support**: Automated rollback capabilities

### For Developers

#### Building from Source
```bash
# Clone repository
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat

# Enhanced build with features
python deployment/build.py \
  --enable-feature file_transfer voice_calls performance_monitoring \
  --platform all

# Cross-platform deployment
python deployment/deploy.py \
  --cross-platform \
  --github --docker --local
```

#### Development Environment
```bash
# Set up development environment
python deployment/build.py --platform linux --skip-tests

# Run with debug features
PRIVATUS_LOG_LEVEL=DEBUG python launch_gui.py
```

#### Contributing
- See [Developer Guide](docs/developer/developer-guide.md)
- Check [Contributing Guidelines](CONTRIBUTING.md)
- Review [Development Plan](docs/DEVELOPMENT_PLAN.md)

## Next Steps

- **[User Guide](user-guide.md)**: Learn about Privatus-chat features
- **[Security Best Practices](security-best-practices.md)**: Secure your installation
- **[Performance Monitoring Guide](feature-performance-monitoring.md)**: Optimize performance
- **[Security Testing Guide](feature-security-testing.md)**: Use security features
- **[Community Resources](https://github.com/privatus-chat/privatus-chat/discussions)**: Get help and contribute

### Enhanced Features Documentation
- **[File Transfer](feature-file-transfer.md)**: Secure file sharing capabilities
- **[Voice Communication](feature-voice-communication.md)**: Voice and video calls
- **[Performance Monitoring](feature-performance-monitoring.md)**: Monitor and optimize performance
- **[Security Testing](feature-security-testing.md)**: Built-in security testing tools

---

## Support and Community

### Getting Help
- **[FAQ](faq.md)**: Frequently asked questions
- **[GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)**: Report bugs and request features
- **[GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)**: Community discussions
- **[Security Issues](SECURITY.md)**: Report security vulnerabilities

### Development Resources
- **[API Reference](docs/developer/api-reference.md)**: Developer API documentation
- **[Architecture Guide](docs/developer/architecture.md)**: System architecture overview
- **[Development Plan](docs/DEVELOPMENT_PLAN.md)**: Current and future development roadmap

*Last updated: September 2024*
*Privatus-chat v3.0.0 - Enhanced Deployment Edition*