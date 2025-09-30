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

## Support

For additional support:

- **User Guide**: [Complete User Guide](user-guide.md)
- **FAQ**: [Frequently Asked Questions](faq.md)
- **GitHub Issues**: [Report Issues](https://github.com/privatus-chat/privatus-chat/issues)
- **Discussions**: [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)

---

*Last updated: September 2024*
*Privatus-chat v3.0.0*