# Privatus-chat

A decentralized, encrypted, and anonymous peer-to-peer chat application built with privacy and security as core principles.

## 🚀 Project Status

**Phase 1: Foundation Complete (Weeks 1-3)**

✅ **Week 1: Project Foundation** - Complete project structure and development environment  
✅ **Week 2: Cryptographic Foundation** - Secure random generation, key management, AES-256-GCM encryption, X3DH protocol  
✅ **Week 3: Networking Infrastructure** - Kademlia DHT, P2P connections, NAT traversal, message protocols  

**Current Status:** Ready for Week 4 - Anonymous messaging and onion routing implementation

## 🔒 Security Features

### Implemented (Weeks 1-3)
- **Cryptographically Secure Random Generation** - OS entropy sources with secure memory handling
- **Advanced Key Management** - Ed25519/X25519 keys with encrypted storage and automatic rotation
- **AES-256-GCM Authenticated Encryption** - Message encryption with authentication and associated data
- **X3DH Key Agreement Protocol** - Signal Protocol-based key exchange for forward secrecy
- **Decentralized Peer Discovery** - Kademlia DHT for serverless peer finding
- **NAT Traversal** - STUN-based connectivity with UDP hole punching
- **Secure Message Protocol** - Comprehensive P2P messaging with acknowledgments

### Planned (Upcoming Weeks)
- **Onion Routing** - Multi-hop anonymous communication
- **Double Ratchet** - Forward secrecy and post-compromise security
- **Traffic Analysis Resistance** - Timing and size obfuscation
- **Group Chat Encryption** - Multi-party secure messaging
- **File Sharing** - Secure and anonymous file transfer

## 🏗️ Architecture

### Core Components

#### Cryptographic Layer (`src/crypto/`)
- **SecureRandom**: Cryptographically secure random number generation
- **KeyManager**: Ed25519/X25519 key lifecycle management with encrypted storage
- **MessageEncryption**: AES-256-GCM authenticated encryption with key derivation
- **X3DH Protocol**: Signal Protocol key agreement for initial key exchange

#### Networking Layer (`src/network/`)
- **KademliaDHT**: Distributed hash table for decentralized peer discovery
- **ConnectionManager**: Multi-peer connection handling with throttling and cleanup
- **NATTraversal**: STUN client and UDP hole punching for connectivity
- **MessageProtocol**: Comprehensive P2P messaging with serialization
- **PeerDiscovery**: Multi-strategy peer finding (DHT, bootstrap, peer exchange)
- **P2PNode**: Main coordinator integrating all networking components

#### Additional Modules (In Development)
- **GUI Layer** (`src/gui/`) - User interface components
- **Storage Layer** (`src/storage/`) - Encrypted local data persistence
- **Anonymity Layer** (`src/anonymity/`) - Onion routing and traffic obfuscation

## 🛠️ Installation & Setup

### Prerequisites
- Python 3.11 or higher
- pip package manager
- Git for version control

### Development Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd privatus-chat
   ```

2. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # For development
   ```

4. **Verify installation**
   ```bash
   python -c "from src.crypto import *; from src.network import *; print('All modules imported successfully')"
   ```

## 🧪 Testing & Verification

### Run Comprehensive Tests
```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test suites
python -m pytest tests/test_crypto.py -v      # Cryptographic tests
python -m pytest tests/test_networking.py -v  # Networking tests

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html
```

### Live Demonstrations
```bash
# Week 2: Cryptographic system demo
python examples/crypto_demo.py

# Week 3: Networking infrastructure demo
python examples/week3_networking_demo.py
```

## 📊 Current Capabilities

### Networking Infrastructure
- **Decentralized Architecture**: No central servers required
- **Peer Discovery**: Automatic peer finding through multiple strategies
- **NAT Traversal**: Works behind most firewall/NAT configurations
- **Connection Management**: Handles multiple simultaneous peer connections
- **Message Protocol**: Comprehensive messaging with reliability guarantees

### Cryptographic Foundation
- **Key Management**: Complete Ed25519/X25519 key lifecycle
- **Encryption**: AES-256-GCM with secure key derivation
- **Key Exchange**: X3DH protocol for initial key agreement
- **Security**: Forward secrecy foundation and secure memory handling

### Performance Metrics
- **Message Throughput**: 1000+ messages/second serialization
- **Network Latency**: Real-time communication optimized
- **Memory Usage**: Efficient resource management with cleanup
- **Connection Limits**: Configurable peer limits (default: 50 peers)

## 🔧 Configuration

### Environment Configuration
```bash
# Development mode
export PRIVATUS_ENV=development

# Production mode  
export PRIVATUS_ENV=production
```

### Network Configuration
- **Default Ports**: Automatically assigned available ports
- **NAT Traversal**: Automatic STUN server discovery
- **Connection Limits**: 50 peers maximum (configurable)
- **Discovery Interval**: 30 seconds (configurable)

## 📚 Documentation

- **[Development Plan](Document/Privatus-chat%20Development%20Plan.md)** - Complete 28-week roadmap
- **[Quick Start Guide](Document/Privatus-chat%20Quick%20Start%20Guide%20for%20Cursor%20Agents.md)** - Development team guide
- **[Signal Protocol Research](Document/Signal%20Protocol%20Research%20Notes.md)** - Cryptographic protocol research
- **[Changelog](CHANGELOG.md)** - Detailed version history

## 🚦 Current Milestone Status

### ✅ Week 1: Project Foundation (Complete)
- Project structure and development environment
- Documentation and configuration setup
- Git repository with security-focused exclusions

### ✅ Week 2: Cryptographic Foundation (Complete)  
- Secure random number generation
- Key management with Ed25519/X25519 support
- AES-256-GCM message encryption
- X3DH key agreement protocol
- 35 test cases with 81% coverage

### ✅ Week 3: Networking Infrastructure (Complete)
- Kademlia DHT for peer discovery
- P2P connection management
- NAT traversal with STUN support
- Message protocol and serialization
- Integrated P2P node architecture
- Complete working demonstration

### 🔄 Week 4: Anonymous Messaging (Next)
- Onion routing implementation
- Traffic analysis resistance
- Anonymous peer communication
- Circuit management and relay selection

## 🤝 Contributing

This project follows security-first development practices:

1. **Security Review**: All cryptographic and networking code requires security review
2. **Test Coverage**: Maintain high test coverage, especially for security-critical components  
3. **Documentation**: Update documentation for all new features
4. **Memory Safety**: Implement secure memory handling for sensitive data

## 📄 License

[License information to be added]

## 🔐 Security Notice

This software is under active development. While the cryptographic implementations follow established protocols and best practices, the software has not yet undergone professional security auditing. Use in production environments is not recommended until security auditing is complete.

## 📞 Contact

[Contact information to be added]

---

**Built with privacy and security as core principles** 🔒 