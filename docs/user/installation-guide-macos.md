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

## Support

For additional support:

- **User Guide**: [Complete User Guide](user-guide.md)
- **FAQ**: [Frequently Asked Questions](faq.md)
- **GitHub Issues**: [Report Issues](https://github.com/privatus-chat/privatus-chat/issues)
- **Discussions**: [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)

---

*Last updated: September 2024*
*Privatus-chat v3.0.0*