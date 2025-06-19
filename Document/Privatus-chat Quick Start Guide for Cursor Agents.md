# Privatus-chat Quick Start Guide for Cursor Agents

## Project Overview
Privatus-chat is a decentralized, encrypted chat application with anonymity features, designed for Windows distribution as a standalone executable.

## Key Technologies
- **Language**: Python 3.11+
- **GUI**: PyQt6
- **Encryption**: Signal Protocol (Double Ratchet + X3DH)
- **Anonymity**: Custom onion routing
- **P2P Networking**: Kademlia DHT
- **Packaging**: PyInstaller

## Development Phases (28 weeks)

### Phase 1: Foundation (Weeks 1-4)
- Project setup and environment configuration
- Basic cryptographic implementation using `cryptography` library
- Networking infrastructure with `asyncio`
- Storage system with SQLite + SQLCipher

### Phase 2: Core Messaging (Weeks 5-8)
- Double Ratchet protocol implementation
- Message routing and delivery
- Basic PyQt6 user interface
- Integration and testing

### Phase 3: P2P Network (Weeks 9-12)
- Kademlia DHT implementation
- Advanced NAT traversal (STUN/TURN)
- Network resilience and fault tolerance
- Performance optimization

### Phase 4: Anonymity (Weeks 13-16)
- Onion routing infrastructure
- Traffic analysis resistance
- Anonymous identity management
- Privacy controls and UI

### Phase 5: Advanced Features (Weeks 17-20)
- Secure group chat
- File sharing with encryption
- Advanced UI features
- Cross-platform considerations

### Phase 6: Security Hardening (Weeks 21-24)
- Cryptographic security audit
- Network security assessment
- Application security hardening
- Comprehensive security testing

### Phase 7: Packaging & Distribution (Weeks 25-28)
- Windows executable packaging with PyInstaller
- User documentation and guides
- Developer documentation
- Final testing and release preparation

## Critical Security Requirements

### Cryptographic Standards
- Use Signal Protocol for E2E encryption
- Curve25519/Ed25519 for public key operations
- AES-256-GCM for symmetric encryption
- HKDF for key derivation
- Secure random number generation only

### Implementation Guidelines
- Never implement custom cryptography
- Use constant-time operations for secret data
- Implement secure key deletion
- Follow TOFU (Trust on First Use) for authentication
- Ensure forward secrecy and post-compromise security

### Network Security
- Implement proper peer authentication
- Protect against DHT attacks (Sybil, eclipse)
- Use authenticated encryption for all communications
- Implement rate limiting and DoS protection

### Privacy Protection
- Minimize metadata collection
- Implement traffic padding and timing obfuscation
- Use cover traffic for anonymity
- Protect against traffic analysis

## Project Structure
```
privatus-chat/
├── src/
│   ├── crypto/          # Cryptographic operations
│   ├── network/         # P2P networking and DHT
│   ├── gui/            # PyQt6 user interface
│   ├── storage/        # Data persistence
│   ├── anonymity/      # Onion routing
│   └── main.py         # Application entry point
├── tests/              # Comprehensive test suite
├── docs/               # Documentation
├── config/             # Configuration files
└── requirements.txt    # Dependencies
```

## Key Dependencies
```
cryptography>=41.0.0
PyNaCl>=1.5.0
PyQt6>=6.5.0
aiohttp>=3.8.0
SQLCipher>=3.4.0
```

## Development Environment Setup
1. Create Python 3.11+ virtual environment
2. Install dependencies from requirements.txt
3. Configure Cursor IDE with Python extension
4. Set up Git with security-focused .gitignore
5. Configure linting (Pylint, Flake8) and formatting (Black)

## Testing Strategy
- Unit tests for all cryptographic functions
- Integration tests for component interactions
- Security tests including attack simulations
- Performance tests under realistic load
- Automated CI/CD pipeline with security scanning

## Packaging for Windows
1. Use PyInstaller for executable creation
2. Include all cryptographic library dependencies
3. Implement code signing with EV certificate
4. Create optional NSIS installer
5. Provide SHA-256 checksums and digital signatures

## Security Considerations
- All cryptographic operations must be constant-time
- Implement secure memory management
- Use defense-in-depth security architecture
- Regular security audits and penetration testing
- Comprehensive input validation and sanitization

## User Experience Goals
- Simple installation (single .exe file)
- Intuitive interface with clear security indicators
- Comprehensive documentation and tutorials
- Strong default security settings
- Accessible to non-technical users

This guide provides Cursor agents with the essential information needed to begin development of Privatus-chat following the comprehensive plan outlined in the main documentation.

