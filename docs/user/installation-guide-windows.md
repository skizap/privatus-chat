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

## Support

For additional support:

- **User Guide**: [Complete User Guide](user-guide.md)
- **FAQ**: [Frequently Asked Questions](faq.md)
- **GitHub Issues**: [Report Issues](https://github.com/privatus-chat/privatus-chat/issues)
- **Discussions**: [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)

---

*Last updated: September 2024*
*Privatus-chat v3.0.0*