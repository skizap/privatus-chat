# Privatus-chat Installation Guide

Welcome to Privatus-chat, the secure and anonymous messaging platform that prioritizes your privacy. This guide will walk you through the installation process on Windows, macOS, and Linux.

## Table of Contents
- [System Requirements](#system-requirements)
- [Quick Install](#quick-install)
- [Windows Installation](#windows-installation)
- [macOS Installation](#macos-installation)
- [Linux Installation](#linux-installation)
- [First-Time Setup](#first-time-setup)
- [Troubleshooting](#troubleshooting)
- [Verifying Installation](#verifying-installation)

## System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11, macOS 10.14+, or Linux (Ubuntu 20.04+, Fedora 34+, Debian 11+)
- **RAM**: 4 GB (8 GB recommended)
- **Storage**: 500 MB available space
- **Network**: Broadband internet connection
- **Python**: 3.8 or higher (if installing from source)

### Recommended Requirements
- **RAM**: 8 GB or more
- **Storage**: 2 GB available space
- **Network**: High-speed broadband for optimal performance
- **Display**: 1280x720 resolution or higher

## Quick Install

### For Most Users (Pre-built Packages)

**Windows**: Download and run `privatus-chat-setup.msi`

**macOS**: Download and open `privatus-chat.dmg`, drag to Applications

**Linux**: Download and install the appropriate package:
- Ubuntu/Debian: `sudo dpkg -i privatus-chat.deb`
- Fedora: `sudo rpm -i privatus-chat.rpm`
- Any Linux: Use the AppImage (portable, no installation needed)

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

## Troubleshooting

### Common Issues

**Application Won't Start**
- Ensure system requirements are met
- Check antivirus isn't blocking the application
- Try running as administrator (Windows) or with sudo (Linux)

**Network Connection Issues**
- Check firewall settings
- Ensure ports 9001-9003 are not blocked
- Try disabling VPN temporarily
- Check proxy settings if applicable

**Installation Errors**

*Windows:*
- Run installer as Administrator
- Disable antivirus temporarily during installation
- Check Windows Event Viewer for detailed errors

*macOS:*
- Ensure macOS version is 10.14 or higher
- Check Security & Privacy settings
- Try installing from Terminal with verbose logging

*Linux:*
- Ensure all dependencies are installed
- Check system logs: `journalctl -xe`
- Try installing with `--verbose` flag

### Getting Help

If you encounter issues:

1. Check the [FAQ](faq.md)
2. Search [existing issues](https://github.com/privatus-chat/issues)
3. Join our [community chat](https://privatus-chat.org/community)
4. Create a [new issue](https://github.com/privatus-chat/issues/new)

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

## Next Steps

- Read the [User Guide](user-guide.md) to learn about features
- Review [Security Best Practices](security-best-practices.md)
- Join the [Privatus-chat community](https://privatus-chat.org/community)

---

*Last updated: December 2024*
*Version: 1.0.0* 