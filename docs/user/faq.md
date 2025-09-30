# Privatus-chat Frequently Asked Questions (FAQ)

## Table of Contents

1. [General Questions](#general-questions)
2. [Installation & Setup](#installation--setup)
3. [Security & Privacy](#security--privacy)
4. [Features & Usage](#features--usage)
5. [Troubleshooting](#troubleshooting)
6. [Technical Questions](#technical-questions)
7. [Performance & Monitoring](#performance--monitoring)
8. [Community & Support](#community--support)

## General Questions

### What is Privatus-chat?

Privatus-chat is a decentralized, end-to-end encrypted messaging application that prioritizes user privacy and security. It combines state-of-the-art cryptography with anonymous routing to provide truly private communications.

### How is Privatus-chat different from other messaging apps?

**Key differences:**
- **No central servers**: Fully peer-to-peer architecture
- **Anonymous routing**: Onion routing hides metadata
- **Open source**: Complete code transparency
- **No phone number required**: True anonymity possible
- **Self-hostable**: Run your own infrastructure
- **Multiple privacy levels**: Adjust based on needs

### Is Privatus-chat free?

Yes! Privatus-chat is:
- Free to download and use
- Open source (MIT license)
- No ads or tracking
- No premium tiers
- Community-driven development

### What platforms does Privatus-chat support?

Currently supported:
- Windows 10/11
- macOS 10.14+
- Linux (Ubuntu, Debian, Fedora, + AppImage)

Coming soon:
- Android
- iOS
- Web version

### Who is Privatus-chat for?

Privatus-chat is designed for:
- Privacy-conscious individuals
- Journalists and sources
- Activists and dissidents
- Business communications
- Anyone valuing digital privacy

## Installation & Setup

### How do I install Privatus-chat?

**Quick install:**
1. Download from [official website](https://privatus-chat.org)
2. Run installer for your platform
3. Follow setup wizard
4. Generate your keys
5. Start chatting!

See our [Installation Guide](installation-guide.md) for detailed instructions.

### Do I need technical knowledge to use Privatus-chat?

No! Privatus-chat is designed for:
- Easy installation with graphical installers
- Intuitive user interface
- Automatic security configuration
- Built-in help system
- Safe defaults for all users

### Can I use Privatus-chat on multiple devices?

Yes, with some considerations:
- Each device has unique keys
- Sync messages between devices
- Maintain separate identities
- Link devices securely

### How do I backup my data?

**Backup procedure:**
1. Settings → Backup & Restore
2. Choose encrypted backup
3. Set strong password
4. Save to secure location
5. Test restore periodically

### What happens if I lose my device?

**If device is lost:**
1. Use another device with backup
2. Revoke old device keys
3. Notify contacts of key change
4. Generate new identity if needed
5. Review security settings

## Security & Privacy

### How secure is Privatus-chat?

**Security features:**
- End-to-end encryption (Signal Protocol)
- Perfect forward secrecy
- Post-compromise security
- Anonymous routing (onion)
- Metadata protection
- Open source auditable code

### What encryption does Privatus-chat use?

**Cryptographic primitives:**
- **Key Exchange**: X3DH (Extended Triple Diffie-Hellman)
- **Message Encryption**: AES-256-GCM
- **Digital Signatures**: Ed25519
- **Key Derivation**: HKDF-SHA256
- **Random Generation**: OS secure random

### Can anyone see my messages?

**No! Messages are protected by:**
- End-to-end encryption
- Only recipients can decrypt
- No server storage
- Perfect forward secrecy
- Encrypted local storage

### Does Privatus-chat collect any data?

**Zero data collection:**
- No personal information
- No message content
- No metadata logging
- No analytics/tracking
- No phone numbers
- No email required

### Can I be anonymous on Privatus-chat?

**Yes! Anonymous features:**
- No phone/email required
- Tor integration available
- Anonymous identities
- Onion routing
- Metadata protection
- Disposable identities

### How does onion routing work?

**Onion routing process:**
1. Message wrapped in multiple encryption layers
2. Routed through 3+ relay nodes
3. Each node removes one layer
4. Final node delivers to recipient
5. Origin hidden from destination

### Is Privatus-chat legal?

**Legal status:**
- Legal in most countries
- Some restrictions may apply:
  - Check local encryption laws
  - Some countries ban encryption
  - Corporate policies may differ
- User responsibility to comply

## Features & Usage

### How do I add contacts?

**Adding contacts:**
1. Click File → Add Contact
2. Exchange identity codes securely
3. Enter contact's code
4. Verify fingerprint
5. Start messaging

### Can I make voice/video calls?

**Yes! Advanced call features:**
- **End-to-end encrypted calls** with perfect forward secrecy
- **Voice calls** with multiple quality levels (Low to Ultra)
- **Multiple codecs**: OPUS, Speex, G.711 for compatibility
- **Voice privacy features**: Fingerprint obfuscation, echo cancellation
- **Adaptive quality**: Automatic adjustment based on network conditions
- **Call statistics**: Real-time latency, packet loss, and bitrate monitoring
- **Video calls** (coming soon)
- **Screen sharing** available
- **No IP address leakage** through onion routing

### How do group chats work?

**Group chat features:**
- Create private groups
- Invite members securely
- Admin controls
- Encrypted group messages
- Anonymous participation option

### Can I share files?

**Advanced file sharing:**
- **Drag and drop files** into chat window
- **Automatic encryption** with per-transfer keys
- **Progress tracking** with real-time statistics
- **Resume interrupted transfers** with checkpoint system
- **Any file type supported** with size limits
- **Chunked transfer**: Large files split into 64KB chunks
- **Integrity verification**: SHA-256 checksums for each chunk
- **Anonymous routing**: Optional transfer through onion circuits
- **Metadata protection**: Automatic removal of identifying information

### What are privacy levels?

**Four privacy levels:**
1. **Minimal**: Basic encryption, fast
2. **Standard**: Balanced privacy/speed
3. **High**: Onion routing enabled
4. **Maximum**: All privacy features

### How do disappearing messages work?

**Auto-delete features:**
- Set timer per conversation
- Messages delete after reading
- Custom time periods
- Synced across devices
- No recovery possible

## Troubleshooting

### Privatus-chat won't connect

**Try these steps:**
1. Check internet connection
2. Verify firewall settings
3. Try different privacy level
4. Use bridge relays
5. Check for updates

### Messages aren't sending

**Common solutions:**
- Ensure recipient is online
- Check your connection
- Verify contact keys
- Lower privacy level temporarily
- Restart application

### App crashes on startup

**Troubleshooting steps:**
1. Update to latest version
2. Clear cache/config
3. Reinstall application
4. Check system requirements
5. Contact support

### Verification keeps failing

**Verification issues:**
- Ensure latest version
- Compare fingerprints carefully
- Try QR code method
- Verify through secure channel
- Re-exchange keys if needed

### Performance is slow

**Speed improvements:**
- Lower privacy level
- Close unused groups
- Clear old messages
- Check network speed
- Upgrade hardware

## Performance & Monitoring

### Does Privatus-chat monitor performance?

**Yes! Comprehensive monitoring:**
- **Real-time metrics**: CPU, memory, disk, network usage
- **Application metrics**: Message throughput, connection counts
- **Performance dashboard**: Live monitoring interface
- **Benchmark suite**: Comprehensive performance testing
- **Automatic optimization**: Adaptive quality and resource management

### How can I monitor my system's performance?

**Performance monitoring:**
- Access via **Settings → Performance**
- View **real-time system metrics**
- Monitor **network performance**
- Track **application resource usage**
- Export **metrics for analysis**

### Can I run performance benchmarks?

**Yes! Built-in benchmark suite:**
- **Cryptographic benchmarks**: Test encryption/decryption speeds
- **Network benchmarks**: Message serialization and transfer performance
- **Memory benchmarks**: Allocation and access pattern testing
- **System benchmarks**: Overall platform performance assessment
- **Detailed reporting**: Results with statistical analysis

### How does Privatus-chat optimize performance?

**Automatic optimizations:**
- **Connection pooling**: Efficient network resource usage
- **Message batching**: Improved throughput for multiple messages
- **Caching strategies**: Fast access to frequently used data
- **Adaptive quality**: Automatic adjustment based on conditions
- **Resource management**: Intelligent memory and CPU usage

### What performance metrics are tracked?

**Comprehensive metrics:**
- **System**: CPU usage, memory consumption, disk I/O, network I/O
- **Application**: Messages/second, active connections, encryption performance
- **Network**: Latency, packet loss, throughput, connection stability
- **Storage**: Database performance, cache hit rates, I/O patterns

## Technical Questions

### What protocols does Privatus-chat use?

**Core protocols:**
- Signal Protocol (messaging)
- Kademlia DHT (peer discovery)
- Custom onion routing
- STUN/TURN (NAT traversal)
- WebRTC (calls)

### Can I run my own relay?

**Yes! Relay setup:**
1. Download relay software
2. Configure network settings
3. Open required ports
4. Register with network
5. Contribute bandwidth

### Is the code audited?

**Security audits:**
- Open source for review
- Community audits ongoing
- Bug bounty program
- Academic research
- Planned professional audits

### What ports does Privatus-chat use?

**Default ports:**
- 9001: P2P communication
- 9002: DHT protocol
- 9003: Relay traffic
- All configurable

### Can I integrate Privatus-chat with other apps?

**Integration options:**
- REST API available
- Webhook support
- Command-line interface
- Plugin system (coming)
- Custom clients possible

## Community & Support

### How can I get help?

**Support channels:**
- In-app help system
- [Documentation](https://docs.privatus-chat.org)
- [Community forum](https://forum.privatus-chat.org)
- [GitHub issues](https://github.com/privatus-chat/issues)
- IRC: #privatus-chat

### How can I contribute?

**Ways to contribute:**
- Code contributions
- Documentation
- Translations
- Bug reports
- Feature requests
- Run relay nodes
- Spread the word

### Is there a bug bounty program?

**Yes! Bug bounty details:**
- Security vulnerabilities only
- Responsible disclosure required
- Rewards based on severity
- Hall of fame recognition
- Details at security@privatus-chat.org

### How do I report bugs?

**Bug reporting:**
1. Check existing issues
2. Gather reproduction steps
3. Include system details
4. Submit on GitHub
5. Follow up as needed

### Can I donate to the project?

**Donation options:**
- Cryptocurrency accepted
- GitHub Sponsors
- Open Collective
- Hardware donations
- Contribute code/time

### Where can I learn more?

**Resources:**
- [Official website](https://privatus-chat.org)
- [Documentation](https://docs.privatus-chat.org)
- [Blog](https://blog.privatus-chat.org)
- [Research papers](https://privatus-chat.org/research)
- Security workshops

**Feature-Specific Documentation:**
- **[Voice Communication Guide](feature-voice-communication.md)**: Detailed calling features
- **[File Transfer Guide](feature-file-transfer.md)**: Advanced file sharing capabilities
- **[Performance Monitoring Guide](feature-performance-monitoring.md)**: System optimization tools
- **[Security Testing Guide](feature-security-testing.md)**: Vulnerability scanning features

---

*Can't find your answer? Ask on our [community forum](https://forum.privatus-chat.org) or create an [issue](https://github.com/privatus-chat/issues).*

*Last updated: January 2025*
*Version: 1.0.0*