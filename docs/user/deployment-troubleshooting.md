# Deployment Troubleshooting Guide

This guide provides solutions for common deployment and installation issues with Privatus-chat.

## Build Issues

### PyInstaller Build Failures

#### "Module not found" Errors
**Problem**: PyInstaller cannot find certain modules during build.

**Solutions**:
1. **Check hidden imports**:
   ```bash
   python deployment/build.py --enable-feature file_transfer voice_calls
   ```

2. **Add missing hidden imports**:
   ```python
   # In build.py, add to hidden imports list:
   "--hidden-import", "src.messaging.file_transfer",
   "--hidden-import", "src.communication.voice_calls",
   ```

3. **Clean build environment**:
   ```bash
   python deployment/build.py --clean
   rm -rf build/ dist/
   ```

#### Platform-specific Build Issues

**Windows**:
- Ensure Visual Studio Build Tools are installed
- Install Windows SDK if missing
- Check for sufficient disk space

**macOS**:
- Install Xcode command line tools: `xcode-select --install`
- Ensure PyQt6 is properly installed
- Check Gatekeeper settings

**Linux**:
- Install system dependencies: `sudo apt-get install libssl-dev libffi-dev`
- Ensure Python development headers are installed
- Check for compatible GLIBC version

### Package Creation Failures

#### MSI Installer Issues (Windows)
**Problem**: WiX Toolset not found or installation fails.

**Solutions**:
1. **Install WiX Toolset**:
   - Download from official WiX website
   - Add to system PATH
   - Restart command prompt

2. **Use fallback method**:
   ```bash
   python deployment/windows_installer.py
   ```

#### DMG Creation Issues (macOS)
**Problem**: hdiutil or create-dmg fails.

**Solutions**:
1. **Install create-dmg**:
   ```bash
   brew install create-dmg
   ```

2. **Check disk space**:
   ```bash
   df -h
   ```

3. **Use fallback tarball**:
   ```bash
   python deployment/macos_dmg_builder.py
   ```

#### DEB/RPM Package Issues (Linux)
**Problem**: dpkg-buildpackage or rpmbuild fails.

**Solutions**:
1. **Install packaging tools**:
   ```bash
   sudo apt-get install build-essential devscripts debhelper
   ```

2. **Check package structure**:
   ```bash
   ls -la deployment/config/
   ```

3. **Use fallback method**:
   ```bash
   python deployment/linux_packages.py
   ```

## Deployment Issues

### GitHub Release Deployment

#### Authentication Issues
**Problem**: GitHub CLI authentication fails.

**Solutions**:
1. **Set up GitHub CLI**:
   ```bash
   gh auth login
   ```

2. **Check token permissions**:
   - Ensure token has `repo` scope
   - Check token expiration

3. **Use environment variable**:
   ```bash
   export GITHUB_TOKEN=your_token_here
   ```

#### Asset Upload Failures
**Problem**: Release assets fail to upload.

**Solutions**:
1. **Check file paths**:
   ```bash
   ls -la dist/
   ```

2. **Verify file sizes**:
   - Ensure files are not too large (>2GB limit)
   - Check available disk space

3. **Retry upload**:
   ```bash
   python deployment/deploy.py --github --version 3.0.0
   ```

### Docker Deployment Issues

#### Build Failures
**Problem**: Docker build fails during multi-stage build.

**Solutions**:
1. **Check Dockerfile syntax**:
   ```bash
   docker build --dry-run -f deployment/Dockerfile.multistage .
   ```

2. **Clean Docker cache**:
   ```bash
   docker system prune -f
   docker builder prune
   ```

3. **Check base image availability**:
   ```bash
   docker pull python:3.11-slim
   ```

#### Registry Push Failures
**Problem**: Cannot push to Docker registry.

**Solutions**:
1. **Check authentication**:
   ```bash
   docker login
   ```

2. **Verify repository permissions**:
   - Ensure you have write access to the repository
   - Check repository exists and is not archived

3. **Check network connectivity**:
   ```bash
   docker push --dry-run your-registry/image:tag
   ```

### Cross-Platform Deployment

#### Platform Detection Issues
**Problem**: Build system detects wrong platform.

**Solutions**:
1. **Force platform**:
   ```bash
   python deployment/build.py --platform linux
   ```

2. **Check platform info**:
   ```python
   import platform
   print(platform.system(), platform.machine())
   ```

#### Architecture Mismatch
**Problem**: Built packages don't match target architecture.

**Solutions**:
1. **Use Docker buildx for multi-arch**:
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64
   ```

2. **Check architecture compatibility**:
   - Ensure PyInstaller supports target architecture
   - Use appropriate base images for Docker

## Runtime Issues

### Application Startup Failures

#### Import Errors
**Problem**: Module import fails at runtime.

**Solutions**:
1. **Check Python path**:
   ```bash
   python -c "import sys; print('\n'.join(sys.path))"
   ```

2. **Verify dependencies**:
   ```bash
   python -c "import PyQt6; print('PyQt6 OK')"
   ```

3. **Check for conflicts**:
   ```bash
   pip list | grep -i conflict
   ```

#### Permission Issues
**Problem**: Application cannot access required directories.

**Solutions**:
1. **Check file permissions**:
   ```bash
   ls -la ~/.config/privatus-chat/
   ```

2. **Fix ownership**:
   ```bash
   chown -R $USER:$USER ~/.config/privatus-chat/
   ```

3. **Check system limits**:
   ```bash
   ulimit -n  # Check file descriptor limit
   ```

### Network Issues

#### P2P Connection Problems
**Problem**: Cannot establish peer connections.

**Solutions**:
1. **Check firewall settings**:
   ```bash
   sudo ufw status  # Ubuntu/Debian
   sudo firewall-cmd --list-all  # CentOS/RHEL
   ```

2. **Test port accessibility**:
   ```bash
   netstat -tuln | grep :8000
   ```

3. **Check NAT configuration**:
   - Enable UPnP if available
   - Configure port forwarding manually if needed

#### DNS Resolution Issues
**Problem**: Cannot resolve hostnames.

**Solutions**:
1. **Check DNS configuration**:
   ```bash
   nslookup github.com
   cat /etc/resolv.conf
   ```

2. **Test connectivity**:
   ```bash
   ping -c 3 8.8.8.8
   ```

### Performance Issues

#### High Memory Usage
**Problem**: Application consumes excessive memory.

**Solutions**:
1. **Monitor memory usage**:
   ```bash
   python -m memory_profiler your_script.py
   ```

2. **Check for memory leaks**:
   - Monitor garbage collection
   - Check for circular references

3. **Optimize configuration**:
   ```bash
   # Reduce cache sizes in config
   # Enable memory optimization features
   ```

#### Slow Startup
**Problem**: Application takes long time to start.

**Solutions**:
1. **Profile startup process**:
   ```bash
   python -m cProfile launch_gui.py
   ```

2. **Check import times**:
   ```bash
   python -c "import time; start=time.time(); import PyQt6; print(time.time()-start)"
   ```

3. **Optimize imports**:
   - Use lazy imports where possible
   - Check for import cycles

## Environment-Specific Issues

### Windows Issues

#### Antivirus Interference
**Problem**: Antivirus software blocks or removes files.

**Solutions**:
1. **Add exclusions**:
   - Add installation directory to antivirus exclusions
   - Report false positive to antivirus vendor

2. **Check Windows Defender**:
   ```powershell
   Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
   Add-MpPreference -ExclusionPath "C:\Program Files\Privatus-chat"
   ```

#### Path Issues
**Problem**: Long path names cause issues on Windows.

**Solutions**:
1. **Enable long paths**:
   ```powershell
   Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem' -Name 'LongPathsEnabled' -Value 1
   ```

2. **Use shorter installation path**:
   - Install to `C:\Privatus` instead of `C:\Program Files\Privatus-chat`

### macOS Issues

#### Gatekeeper Blocks Execution
**Problem**: Gatekeeper prevents application from running.

**Solutions**:
1. **Allow in Security settings**:
   - Go to System Preferences → Security & Privacy
   - Click "Open Anyway"

2. **Remove quarantine attribute**:
   ```bash
   xattr -rd com.apple.quarantine /Applications/Privatus-chat.app
   ```

#### Permission Issues
**Problem**: Application cannot access protected directories.

**Solutions**:
1. **Grant Full Disk Access**:
   - Go to System Preferences → Security & Privacy → Privacy
   - Add Privatus-chat to Full Disk Access

2. **Check sandboxing**:
   - Review entitlement settings in Info.plist
   - Temporarily disable sandboxing for troubleshooting

### Linux Issues

#### Desktop Integration Problems
**Problem**: Application doesn't appear in menus or dock.

**Solutions**:
1. **Update desktop database**:
   ```bash
   sudo update-desktop-database -v
   ```

2. **Refresh MIME types**:
   ```bash
   sudo update-mime-database /usr/share/mime
   ```

3. **Restart desktop environment**:
   ```bash
   # For GNOME
   gnome-shell --replace &
   ```

#### Package Conflicts
**Problem**: Package conflicts with system packages.

**Solutions**:
1. **Check for conflicts**:
   ```bash
   apt-cache search privatus-chat
   ```

2. **Force installation**:
   ```bash
   sudo dpkg -i --force-conflicts privatus-chat.deb
   ```

## Debugging Tools

### Enable Debug Mode

#### Command Line
```bash
privatus-chat --debug --log-level DEBUG
```

#### Environment Variable
```bash
export PRIVATUS_LOG_LEVEL=DEBUG
export PYTHONPATH=/path/to/privatus-chat
python launch_gui.py
```

#### Configuration File
```json
{
  "logging": {
    "level": "DEBUG",
    "format": "detailed",
    "output": ["console", "file"]
  }
}
```

### Collect Debug Information

#### System Information
```bash
# Linux/macOS
uname -a
python --version
pip list | grep -E "(PyQt|crypto|ssl)"

# Windows
systeminfo
python --version
pip list | findstr "PyQt crypto ssl"
```

#### Application Logs
- Check log files in data directory
- Enable debug logging
- Check system logs for crashes

#### Network Diagnostics
```bash
# Test connectivity
ping github.com
traceroute github.com

# Check open ports
netstat -tuln | grep :8000
ss -tuln | grep :8000

# Test P2P connectivity
telnet localhost 8000
```

## Getting Help

### Self-Service Resources
1. **Documentation**: Check installation guides for your platform
2. **FAQ**: [Frequently Asked Questions](faq.md)
3. **GitHub Issues**: Search existing issues for similar problems
4. **Discussions**: [GitHub Discussions](https://github.com/privatus-chat/privatus-chat/discussions)

### Reporting Issues

When reporting issues, please include:

1. **Platform information**:
   - Operating system and version
   - Architecture (32-bit/64-bit/ARM)
   - Desktop environment (Linux)

2. **Privatus-chat version**:
   - Version number
   - Installation method used

3. **Error details**:
   - Complete error messages
   - Steps to reproduce
   - Log files (with sensitive information removed)

4. **System configuration**:
   - Relevant environment variables
   - Configuration file settings
   - Network setup

### Community Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/privatus-chat/privatus-chat/issues)
- **Discussions**: [Ask questions and get help](https://github.com/privatus-chat/privatus-chat/discussions)
- **Wiki**: [User-contributed documentation](https://github.com/privatus-chat/privatus-chat/wiki)

## Emergency Procedures

### Rollback Deployment

#### Using Git
```bash
git log --oneline -10  # Find previous commit
git revert <commit-hash>  # Revert to previous state
```

#### Using Backup
```bash
# Restore from backup
cp -r backup/privatus-chat-data ~/.config/privatus-chat/
```

#### Using Deployment Script
```bash
python deployment/deploy.py --rollback --version 3.0.0
```

### Data Recovery

#### Locate Data Files
- **Windows**: `%APPDATA%\Privatus-chat`
- **macOS**: `~/Library/Application Support/Privatus-chat`
- **Linux**: `~/.config/privatus-chat`

#### Recover from Backup
```bash
# Restore configuration
cp backup/config.json ~/.config/privatus-chat/

# Restore data
cp -r backup/data/ ~/.config/privatus-chat/
```

### Emergency Contacts

For critical security issues or urgent problems:

- **Security Issues**: security@privatus-chat.org
- **Critical Bugs**: Create GitHub issue with "critical" label
- **Emergency Support**: Check community resources

## Prevention

### Best Practices

1. **Regular Backups**:
   - Backup user data before updates
   - Test backup restoration procedures
   - Keep multiple backup versions

2. **Testing**:
   - Test deployments in staging environment first
   - Use automated testing in CI/CD pipeline
   - Perform manual testing before production deployment

3. **Monitoring**:
   - Monitor application health and performance
   - Set up alerting for critical issues
   - Track deployment metrics

4. **Documentation**:
   - Keep deployment documentation up to date
   - Document troubleshooting procedures
   - Maintain change logs

### Maintenance

1. **Regular Updates**:
   - Keep dependencies updated
   - Apply security patches promptly
   - Update documentation regularly

2. **Health Checks**:
   - Monitor system resources
   - Check application logs regularly
   - Verify backup integrity

3. **Security**:
   - Regular security audits
   - Update certificates and keys
   - Review access permissions

---

*Last updated: September 2024*
*Privatus-chat v3.0.0*