# Network Connectivity and P2P Troubleshooting Guide

This guide provides comprehensive solutions for network connectivity issues, P2P connection problems, and NAT traversal challenges in Privatus-chat.

## Table of Contents

1. [Connection Establishment Issues](#connection-establishment-issues)
2. [NAT and Firewall Problems](#nat-and-firewall-problems)
3. [P2P Communication Issues](#p2p-communication-issues)
4. [Rate Limiting Problems](#rate-limiting-problems)
5. [Message Protocol Issues](#message-protocol-issues)
6. [Performance and Reliability](#performance-and-reliability)
7. [Diagnostic Tools and Commands](#diagnostic-tools-and-commands)
8. [Platform-Specific Issues](#platform-specific-issues)

## Connection Establishment Issues

### Cannot Connect to Peers

**Problem**: Unable to establish connections to other Privatus-chat users.

**Symptoms**:
- Connection attempts timeout
- "Connection failed" errors
- Peers show as offline when they should be online

**Solutions**:

1. **Check Network Basics**:
   ```bash
   # Test internet connectivity
   ping -c 3 8.8.8.8

   # Check DNS resolution
   nslookup github.com

   # Verify local network interface
   ip addr show
   ```

2. **Verify Port Availability**:
   ```bash
   # Check if port 8000 is in use
   netstat -tuln | grep :8000
   ss -tuln | grep :8000

   # Test port binding
   python3 -c "
   import socket
   sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   try:
       sock.bind(('0.0.0.0', 8000))
       print('Port 8000 is available')
   except OSError as e:
       print(f'Port 8000 is in use: {e}')
   finally:
       sock.close()
   "
   ```

3. **Check Firewall Settings**:
   ```bash
   # Linux (UFW)
   sudo ufw status
   sudo ufw allow 8000

   # Linux (firewalld)
   sudo firewall-cmd --list-all
   sudo firewall-cmd --permanent --add-port=8000/tcp

   # Windows PowerShell
   netsh advfirewall firewall add rule name="Privatus-chat" dir=in action=allow protocol=TCP localport=8000
   ```

4. **Test STUN Connectivity**:
   ```python
   # Test STUN servers used by Privatus-chat
   from src.network.nat_traversal import STUNClient
   import asyncio

   async def test_stun():
       client = STUNClient()
       response = await client.get_public_address()
       if response and response.success:
           print(f"Public IP: {response.public_ip}:{response.public_port}")
       else:
           print("STUN test failed")

   asyncio.run(test_stun())
   ```

### Connection Refused Errors

**Problem**: Peers actively refuse connection attempts.

**Solutions**:

1. **Verify Peer Status**:
   - Confirm peer is actually online
   - Check if peer has blocked you
   - Verify peer's network configuration

2. **Check Rate Limiting**:
   ```python
   # Check if you're being rate limited
   from src.network.connection_manager import ConnectionManager
   manager = ConnectionManager()
   stats = manager.get_rate_limit_stats("peer_ip_address")
   print(f"Rate limit stats: {stats}")
   ```

3. **Adjust Security Level**:
   ```python
   # Lower security level if too restrictive
   from src.network.connection_manager import SecurityLevel
   manager.set_security_level(SecurityLevel.LOW)
   ```

### Timeout Issues

**Problem**: Connection attempts timeout after 30 seconds.

**Solutions**:

1. **Check Network Latency**:
   ```bash
   # Test latency to peer
   ping -c 5 peer_ip_address

   # Traceroute to identify network hops
   traceroute peer_ip_address
   ```

2. **Adjust Timeout Settings**:
   ```python
   # Increase connection timeout in configuration
   connection_timeout = 60.0  # Increase from default 30 seconds
   ```

3. **Enable Connection Retry**:
   ```python
   # Implement retry logic for failed connections
   max_retries = 3
   retry_delay = 5.0
   ```

## NAT and Firewall Problems

### Behind Symmetric NAT

**Problem**: Cannot establish direct connections due to symmetric NAT.

**Symptoms**:
- STUN shows different ports for each connection
- Direct P2P connections fail consistently
- Only relay connections work

**Solutions**:

1. **Enable UPnP/IGD**:
   ```python
   # Enable UPnP in router settings if available
   # Or configure manual port forwarding
   ```

2. **Use Manual Port Forwarding**:
   ```
   Router Configuration:
   - Forward TCP port 8000 to your local IP
   - Forward UDP port 8000 for hole punching
   - Set up both incoming and outgoing rules
   ```

3. **Configure Static NAT Mapping**:
   ```bash
   # Request static port mapping from ISP
   # Or use DMZ (less secure, not recommended)
   ```

4. **Test NAT Type**:
   ```python
   from src.network.nat_traversal import NATTraversal
   import asyncio

   async def check_nat():
       nat = NATTraversal()
       nat_type = await nat.discover_nat_type()
       print(f"Your NAT type: {nat_type}")

       # Check compatibility with peer
       can_connect = nat.can_connect_directly("peer_nat_type")
       print(f"Can connect directly: {can_connect}")

   asyncio.run(check_nat())
   ```

### Firewall Blocking Connections

**Problem**: Firewall prevents Privatus-chat connections.

**Platform-Specific Solutions**:

**Windows**:
```powershell
# Add firewall exception
netsh advfirewall firewall add rule name="Privatus-chat" dir=in action=allow program="C:\Path\To\privatus-chat.exe" enable=yes

# Check Windows Defender
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
Add-MpPreference -ExclusionPath "C:\Path\To\Privatus-chat"
```

**macOS**:
```bash
# Check Application Firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --list

# Allow signed applications
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /Applications/Privatus-chat.app/Contents/MacOS/privatus-chat
```

**Linux**:
```bash
# Check iptables rules
sudo iptables -L -n

# Add exception for Privatus-chat
sudo iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
sudo iptables -I OUTPUT -p tcp --sport 8000 -j ACCEPT
```

## P2P Communication Issues

### Message Delivery Failures

**Problem**: Messages sent but not received by peers.

**Solutions**:

1. **Check Message Protocol**:
   ```python
   # Verify message serialization/deserialization
   from src.network.message_protocol import MessageSerializer, P2PMessage, MessageHeader, MessageType

   serializer = MessageSerializer()
   message = serializer.create_chat_message(sender_id, recipient_id, "test")
   serialized = serializer.serialize(message)
   deserialized = serializer.deserialize(serialized)

   print(f"Message round-trip successful: {deserialized.payload['content'] == 'test'}")
   ```

2. **Test Connection Health**:
   ```python
   # Check if connection is alive
   connection = manager.get_connection_info(peer_id)
   if connection:
       print(f"Connection alive: {connection.is_alive()}")
       print(f"Last activity: {time.time() - connection.last_activity:.1f}s ago")
   ```

3. **Verify Message Acknowledgments**:
   ```python
   # Check pending acknowledgments
   protocol = MessageProtocol(node_id)
   timed_out = protocol.check_pending_acks(timeout=30.0)
   if timed_out:
       print(f"Timed out messages: {timed_out}")
   ```

### Handshake Failures

**Problem**: Initial connection handshake fails.

**Solutions**:

1. **Check Protocol Version Compatibility**:
   ```python
   # Ensure both peers use same protocol version
   expected_version = 1
   peer_version = message.payload.get('protocol_version', 0)
   if peer_version != expected_version:
       print(f"Protocol version mismatch: {peer_version} != {expected_version}")
   ```

2. **Verify Cryptographic Keys**:
   ```python
   # Check if key manager is properly initialized
   if not key_manager.identity_key:
       print("Identity key not available - generate keys first")
   ```

3. **Test Network Path**:
   ```bash
   # Test if peer is reachable
   telnet peer_ip 8000

   # Check for packet loss
   ping -c 10 peer_ip
   ```

### File Transfer Issues

**Problem**: File transfers fail or timeout.

**Solutions**:

1. **Check File Size Limits**:
   ```python
   # Verify file size is within limits
   max_file_size = 100 * 1024 * 1024  # 100MB
   if file_size > max_file_size:
       print(f"File too large: {file_size} > {max_file_size}")
   ```

2. **Test Chunked Transfer**:
   ```python
   # Verify message chunking works
   chunk_size = 8192
   total_chunks = (file_size + chunk_size - 1) // chunk_size
   print(f"File will be split into {total_chunks} chunks")
   ```

## Rate Limiting Problems

### Too Many Connection Attempts

**Problem**: Rate limiter blocks legitimate connection attempts.

**Symptoms**:
- "Rate limit exceeded" errors
- Legitimate peers cannot connect
- Long backoff periods

**Solutions**:

1. **Check Current Rate Limit Status**:
   ```python
   # Get rate limiting statistics
   stats = manager.get_rate_limit_stats()
   print(f"Current stats: {stats}")

   # Check specific IP stats
   ip_stats = manager.get_rate_limit_stats("peer_ip")
   print(f"IP stats: {ip_stats}")
   ```

2. **Adjust Security Level**:
   ```python
   # Lower security level for testing
   from src.network.connection_manager import SecurityLevel
   manager.set_security_level(SecurityLevel.LOW)
   ```

3. **Reset Rate Limiting**:
   ```python
   # Clear rate limit data for specific IP
   if manager.rate_limiter:
       # This would require adding a reset method to RateLimiter
       pass
   ```

### Insufficient Rate Limiting

**Problem**: System not protecting against abuse.

**Solutions**:

1. **Increase Security Level**:
   ```python
   from src.network.connection_manager import SecurityLevel
   manager.set_security_level(SecurityLevel.HIGH)
   ```

2. **Configure Custom Rate Limits**:
   ```python
   # Create custom rate limit configuration
   from src.network.connection_manager import RateLimitConfig

   config = RateLimitConfig(
       security_level=SecurityLevel.HIGH,
       max_attempts_per_minute=10,
       backoff_multipliers={SecurityLevel.HIGH: 5.0}
   )
   manager.rate_limit_config = config
   ```

## Message Protocol Issues

### Message Serialization Errors

**Problem**: Messages fail to serialize/deserialize properly.

**Solutions**:

1. **Check Message Format**:
   ```python
   # Validate message structure
   try:
       message = P2PMessage.from_dict(message_dict)
       print("Message structure valid")
   except Exception as e:
       print(f"Message structure invalid: {e}")
   ```

2. **Verify JSON Compatibility**:
   ```python
   # Check for non-serializable data
   import json
   try:
       json.dumps(message_dict)
       print("Message JSON serializable")
   except Exception as e:
       print(f"JSON serialization error: {e}")
   ```

3. **Test Compression**:
   ```python
   # Check compression/decompression
   import zlib
   try:
       compressed = zlib.compress(json_data)
       decompressed = zlib.decompress(compressed)
       print("Compression works correctly")
   except Exception as e:
       print(f"Compression error: {e}")
   ```

### Signature Verification Failures

**Problem**: Cryptographic signatures fail verification.

**Solutions**:

1. **Check Key Availability**:
   ```python
   # Verify identity key exists
   if not key_manager.identity_key:
       print("No identity key available")
       return

   # Check key validity
   try:
       test_data = b"test"
       signature = key_manager.identity_key.sign(test_data)
       is_valid = key_manager.identity_key.verify(test_data, signature)
       print(f"Key signature test: {is_valid}")
   except Exception as e:
       print(f"Key test failed: {e}")
   ```

2. **Verify Signature Data**:
   ```python
   # Check signature data creation
   signature_data = serializer._create_signature_data(message)
   print(f"Signature data length: {len(signature_data)}")

   # Verify signature
   try:
       is_valid = key_manager.identity_key.verify(signature_data, message.signature)
       print(f"Signature valid: {is_valid}")
   except Exception as e:
       print(f"Signature verification failed: {e}")
   ```

## Performance and Reliability

### High Latency Issues

**Problem**: Messages take too long to deliver.

**Solutions**:

1. **Optimize Connection Pool**:
   ```python
   # Adjust connection pool settings
   manager.pool_size = 10  # Reduce from default 20
   manager.keepalive_interval = 30.0  # Reduce from default 60
   ```

2. **Enable Message Compression**:
   ```python
   # Lower compression threshold
   serializer = MessageSerializer(compress_threshold=512)  # From default 1024
   ```

3. **Implement Connection Reuse**:
   ```python
   # Reuse connections when possible
   connection = await manager._get_pooled_connection(peer_id)
   if connection:
       print("Reusing pooled connection")
   ```

### Connection Drops

**Problem**: Connections drop unexpectedly.

**Solutions**:

1. **Check Network Stability**:
   ```bash
   # Monitor connection stability
   ping -i 1 peer_ip | while read line; do echo "$(date): $line"; done
   ```

2. **Adjust Keepalive Settings**:
   ```python
   # Increase keepalive frequency
   manager.keepalive_interval = 30.0  # Send keepalive every 30 seconds
   ```

3. **Implement Reconnection Logic**:
   ```python
   # Add automatic reconnection
   max_reconnect_attempts = 5
   reconnect_delay = 5.0

   for attempt in range(max_reconnect_attempts):
       if await manager.connect_to_peer(peer_info):
           break
       await asyncio.sleep(reconnect_delay)
   ```

## Diagnostic Tools and Commands

### Network Diagnostics Script

```python
#!/usr/bin/env python3
"""
Privatus-chat Network Diagnostics Tool
"""

import asyncio
import socket
import time
from src.network.nat_traversal import STUNClient, NATTraversal
from src.network.connection_manager import ConnectionManager

async def run_diagnostics():
    print("=== Privatus-chat Network Diagnostics ===\n")

    # 1. Basic connectivity
    print("1. Testing basic connectivity...")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("8.8.8.8", 53),
            timeout=5.0
        )
        writer.close()
        await writer.wait_closed()
        print("✓ Internet connectivity OK")
    except Exception as e:
        print(f"✗ Internet connectivity failed: {e}")

    # 2. STUN test
    print("\n2. Testing STUN servers...")
    stun_client = STUNClient()
    stun_response = await stun_client.get_public_address()
    if stun_response and stun_response.success:
        print(f"✓ Public address: {stun_response.public_ip}:{stun_response.public_port}")
    else:
        print("✗ STUN test failed")

    # 3. NAT type detection
    print("\n3. Detecting NAT type...")
    nat = NATTraversal()
    nat_type = await nat.discover_nat_type()
    print(f"✓ NAT type: {nat_type}")

    # 4. Port test
    print("\n4. Testing port availability...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(('0.0.0.0', 8000))
        print("✓ Port 8000 is available")
        sock.close()
    except OSError:
        print("✗ Port 8000 is in use or blocked")

    # 5. Connection manager test
    print("\n5. Testing connection manager...")
    manager = ConnectionManager(max_connections=5)
    await manager.start()

    stats = manager.get_connection_stats()
    print(f"✓ Connection manager ready: {stats}")

    await manager.stop()

    print("\n=== Diagnostics Complete ===")

if __name__ == "__main__":
    asyncio.run(run_diagnostics())
```

### Log Analysis Commands

```bash
# Check Privatus-chat logs for network errors
tail -f ~/.config/privatus-chat/logs/network.log | grep -i error

# Monitor connection attempts
tail -f ~/.config/privatus-chat/logs/network.log | grep -E "(connect|disconnect|timeout)"

# Check rate limiting logs
tail -f ~/.config/privatus-chat/logs/network.log | grep -i "rate.limit"

# Extract connection statistics
grep "Connection established" ~/.config/privatus-chat/logs/network.log | wc -l
```

### Performance Monitoring

```python
# Monitor connection performance
import time
import asyncio

async def monitor_performance():
    manager = ConnectionManager()
    await manager.start()

    while True:
        stats = manager.get_connection_stats()
        print(f"Active connections: {stats['active_connections']}")
        print(f"Total bytes sent: {stats['total_bytes_sent']}")
        print(f"Total bytes received: {stats['total_bytes_received']}")

        # Check rate limiting stats
        rate_stats = manager.get_rate_limit_stats()
        print(f"Rate limit stats: {rate_stats}")

        await asyncio.sleep(10)
```

## Platform-Specific Issues

### Windows Issues

**Problem**: Windows Defender or firewall blocking connections.

**Solutions**:

1. **Disable Windows Defender Temporarily** (for testing):
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $true
   ```

2. **Add Exclusions**:
   ```powershell
   Add-MpPreference -ExclusionPath "C:\Path\To\Privatus-chat"
   Add-MpPreference -ExclusionProcess "privatus-chat.exe"
   ```

3. **Check Network Profile**:
   ```powershell
   Get-NetConnectionProfile
   Set-NetConnectionProfile -Name "NetworkName" -NetworkCategory Private
   ```

### macOS Issues

**Problem**: macOS firewall or security settings blocking connections.

**Solutions**:

1. **Check Application Firewall**:
   ```bash
   sudo /usr/libexec/ApplicationFirewall/socketfilterfw --list
   sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /Applications/Privatus-chat.app/Contents/MacOS/privatus-chat
   ```

2. **Grant Permissions**:
   ```bash
   # Add to Full Disk Access if needed
   System Preferences → Security & Privacy → Privacy → Full Disk Access
   ```

3. **Check Gatekeeper**:
   ```bash
   spctl --assess --verbose /Applications/Privatus-chat.app
   ```

### Linux Issues

**Problem**: iptables or systemd blocking connections.

**Solutions**:

1. **Check iptables**:
   ```bash
   sudo iptables -L -n -v
   sudo iptables -I INPUT -p tcp --dport 8000 -j ACCEPT
   ```

2. **Check systemd**:
   ```bash
   systemctl status firewalld
   systemctl status ufw
   ```

3. **Check AppArmor/SELinux**:
   ```bash
   # AppArmor
   sudo aa-status
   sudo aa-complain /usr/bin/python3

   # SELinux
   sestatus
   sudo setenforce 0  # Permissive mode for testing
   ```

## Emergency Procedures

### Reset Network Configuration

```python
# Complete network reset
async def reset_network():
    # Stop connection manager
    await manager.stop()

    # Clear all connections
    await manager._close_all_connections()

    # Clear rate limiting data
    if manager.rate_limiter:
        manager.rate_limiter.ip_data.clear()

    # Restart with fresh configuration
    await manager.start()

    print("Network configuration reset complete")
```

### Manual Connection Test

```python
# Test direct connection to peer
async def test_direct_connection(peer_address, peer_port):
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(peer_address, peer_port),
            timeout=10.0
        )

        # Send test message
        test_message = b"TEST_CONNECTION"
        writer.write(test_message)
        await writer.drain()

        # Wait for response
        response = await asyncio.wait_for(reader.read(1024), timeout=5.0)

        writer.close()
        await writer.wait_closed()

        print(f"Direct connection test successful: {response}")
        return True

    except Exception as e:
        print(f"Direct connection test failed: {e}")
        return False
```

## Prevention and Best Practices

### Network Configuration Best Practices

1. **Port Forwarding Setup**:
   - Forward both TCP and UDP ports
   - Use port 8000 consistently
   - Configure on all network interfaces

2. **Firewall Rules**:
   - Allow inbound connections on port 8000
   - Allow outbound connections to any port
   - Create specific rules for Privatus-chat

3. **Network Monitoring**:
   - Monitor connection logs regularly
   - Set up alerts for connection failures
   - Track rate limiting statistics

4. **Performance Optimization**:
   - Use connection pooling for frequent peers
   - Enable message compression for large transfers
   - Implement proper keepalive mechanisms

### Security Considerations

1. **Rate Limiting**:
   - Use appropriate security level for your threat model
   - Monitor for abuse patterns
   - Adjust limits based on usage patterns

2. **Connection Validation**:
   - Verify peer identities before establishing connections
   - Use proper authentication mechanisms
   - Implement connection encryption

3. **Network Hardening**:
   - Use VPN for additional privacy
   - Avoid public WiFi for sensitive communications
   - Implement proper certificate validation

## Getting Help

### Self-Service Resources

1. **Documentation**:
   - [Installation Guide](installation-guide.md)
   - [Security Best Practices](security-best-practices.md)
   - [Performance Tuning Guide](performance-tuning-guide.md)

2. **Community Support**:
   - [GitHub Issues](https://github.com/privatus-chat/privatus-chat/issues)
   - [Discussions](https://github.com/privatus-chat/privatus-chat/discussions)

### Reporting Network Issues

When reporting network issues, please include:

1. **System Information**:
   - Operating system and version
   - Network configuration (NAT type, firewall settings)
   - Privatus-chat version

2. **Problem Details**:
   - Exact error messages
   - Steps to reproduce
   - Network diagnostic output

3. **Network Environment**:
   - ISP information
   - Router model and configuration
   - Network topology

4. **Log Files**:
   - Network logs with sensitive information removed
   - Diagnostic tool output
   - Connection statistics

---

*Remember: Network issues are often environmental. Always check your local network configuration, firewall settings, and ISP limitations before assuming the issue is with Privatus-chat.*

*Last updated: January 2025*
*Version: 1.0.0*