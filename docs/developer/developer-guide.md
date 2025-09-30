# Privatus-chat Developer Guide

Welcome to the Privatus-chat developer guide! This document will help you get started with developing for and contributing to Privatus-chat.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Development Environment](#development-environment)
3. [Code Structure](#code-structure)
4. [Building from Source](#building-from-source)
5. [Testing](#testing)
6. [Adding Features](#adding-features)
7. [Security Considerations](#security-considerations)
8. [Performance Guidelines](#performance-guidelines)
9. [Contributing](#contributing)

## Getting Started

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment tool (venv, virtualenv, or conda)
- Basic understanding of:
  - Cryptography concepts
  - P2P networking
  - Asynchronous programming
  - PyQt6 for GUI development

### Quick Start

```bash
# Clone the repository
git clone https://github.com/privatus-chat/privatus-chat.git
cd privatus-chat

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On Unix/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest

# Start the application
python src/main.py
```

## Development Environment

### IDE Setup

#### VS Code

Recommended extensions:
- Python
- Pylance
- Python Test Explorer
- GitLens

`.vscode/settings.json`:
```json
{
    "python.linting.enabled": true,
    "python.linting.pylintEnabled": true,
    "python.formatting.provider": "black",
    "python.testing.pytestEnabled": true,
    "editor.formatOnSave": true
}
```

#### PyCharm

1. Open project directory
2. Configure Python interpreter to use virtual environment
3. Enable pytest as test runner
4. Configure code style to use Black

### Development Tools

```bash
# Code formatting
black src/ tests/

# Linting
pylint src/
flake8 src/

# Type checking
mypy src/

# Security scanning
bandit -r src/

# Test coverage
pytest --cov=src --cov-report=html
```

## Code Structure

### Directory Layout

```
privatus-chat/
├── src/                    # Source code
│   ├── __init__.py
│   ├── main.py            # Application entry point
│   ├── crypto/            # Cryptographic modules
│   ├── network/           # Networking components
│   ├── anonymity/         # Anonymity features
│   ├── gui/               # User interface
│   ├── storage/           # Data persistence
│   └── messaging/         # Message handling
├── tests/                 # Test suite
├── docs/                  # Documentation
├── examples/              # Example code
├── deployment/            # Deployment scripts
└── config/               # Configuration files
```

### Module Responsibilities

- **crypto**: All cryptographic operations, key management
- **network**: P2P networking, DHT, NAT traversal
- **anonymity**: Onion routing, traffic analysis resistance
- **gui**: PyQt6 user interface components
- **storage**: Database operations, configuration
- **messaging**: Message processing, routing

### Design Patterns

#### Dependency Injection

```python
class MessageHandler:
    def __init__(self, crypto: CryptoEngine, network: NetworkManager):
        self.crypto = crypto
        self.network = network
```

#### Observer Pattern

```python
class EventEmitter:
    def __init__(self):
        self._observers = []
    
    def attach(self, observer):
        self._observers.append(observer)
    
    def notify(self, event):
        for observer in self._observers:
            observer.update(event)
```

#### Factory Pattern

```python
class EncryptionFactory:
    @staticmethod
    def create_encryptor(algorithm: str) -> Encryptor:
        if algorithm == "AES-GCM":
            return AESGCMEncryptor()
        # ... other algorithms
```

## Building from Source

### Development Build

```bash
# Install in development mode
pip install -e .

# Run with debug logging
python src/main.py --debug
```

### Production Build

#### Windows

```bash
# Build MSI installer
python deployment/build_windows.py

# Output: dist/privatus-chat-setup.msi
```

#### macOS

```bash
# Build app bundle
python deployment/build_macos.py

# Create DMG
python deployment/create_dmg.py

# Output: dist/privatus-chat.dmg
```

#### Linux

```bash
# Build DEB package
python deployment/build_deb.py

# Build AppImage
python deployment/build_appimage.py

# Output: dist/privatus-chat.deb, dist/privatus-chat.AppImage
```

## Testing

### Unit Tests

```python
# tests/test_crypto.py
import pytest
from src.crypto import MessageEncryption

class TestMessageEncryption:
    def test_encrypt_decrypt(self):
        enc = MessageEncryption()
        plaintext = b"Hello, World!"
        key = enc.generate_key()
        
        ciphertext = enc.encrypt(plaintext, key)
        decrypted = enc.decrypt(ciphertext, key)
        
        assert decrypted == plaintext
```

### Integration Tests

```python
# tests/test_integration.py
@pytest.mark.asyncio
async def test_message_flow():
    # Create two nodes
    node1 = P2PNode(port=9001)
    node2 = P2PNode(port=9002)
    
    await node1.start()
    await node2.start()
    
    # Connect nodes
    await node1.connect_to_peer("localhost:9002")
    
    # Send message
    message = "Test message"
    await node1.send_message(node2.id, message)
    
    # Verify receipt
    received = await node2.receive_message()
    assert received.content == message
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_crypto.py

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run only fast tests
pytest -m "not slow"

# Run with verbose output
pytest -v
```

## Adding Features

### Feature Development Workflow

1. **Create Issue**: Describe the feature
2. **Create Branch**: `feature/feature-name`
3. **Write Tests**: TDD approach recommended
4. **Implement Feature**: Follow coding standards
5. **Update Documentation**: API docs, user guide
6. **Submit PR**: Include tests and docs

### Example: Adding a New Message Type

```python
# 1. Define message type
class MessageType(Enum):
    CHAT = "chat"
    FILE = "file"
    VOICE = "voice"
    REACTION = "reaction"  # New type

# 2. Create handler
class ReactionHandler:
    def process(self, message: Message) -> None:
        # Implementation
        pass

# 3. Register handler
message_router.register(MessageType.REACTION, ReactionHandler())

# 4. Add to GUI
class ChatWidget:
    def add_reaction(self, message_id: str, emoji: str):
        # Implementation
        pass
```

## Security Considerations

### Secure Coding Practices

#### Input Validation

```python
def validate_message(content: str) -> bool:
    """Validate message content."""
    if not content:
        return False
    if len(content) > MAX_MESSAGE_LENGTH:
        return False
    # Check for malicious patterns
    if contains_script_tags(content):
        return False
    return True
```

#### Secure Random

```python
# DO: Use cryptographically secure random
from src.crypto import SecureRandom
nonce = SecureRandom.generate_bytes(16)

# DON'T: Use standard random
import random  # Not secure!
nonce = random.randbytes(16)
```

#### Key Storage

```python
# DO: Encrypt keys at rest
key_manager.store_key(key, password=user_password)

# DON'T: Store keys in plaintext
with open("key.txt", "w") as f:
    f.write(key)  # Insecure!
```

### Security Checklist

- [ ] All user input is validated
- [ ] Cryptographic operations use secure primitives
- [ ] Keys are never stored in plaintext
- [ ] Memory is securely wiped after use
- [ ] No sensitive data in logs
- [ ] Rate limiting implemented
- [ ] Authentication required for all operations

## Performance Guidelines

### Optimization Principles

1. **Profile First**: Don't optimize without data
2. **Cache Wisely**: Cache expensive operations
3. **Async Everything**: Use async/await for I/O
4. **Batch Operations**: Group similar operations
5. **Lazy Loading**: Load only what's needed

### Performance Patterns

#### Connection Pooling

```python
class ConnectionPool:
    def __init__(self, max_size: int = 100):
        self._pool = asyncio.Queue(maxsize=max_size)
        self._all_connections = set()
    
    async def acquire(self) -> Connection:
        try:
            return await self._pool.get_nowait()
        except asyncio.QueueEmpty:
            return await self._create_connection()
```

#### Message Batching

```python
class MessageBatcher:
    def __init__(self, batch_size: int = 10, timeout: float = 0.1):
        self.batch_size = batch_size
        self.timeout = timeout
        self._queue = []
    
    async def add_message(self, message: Message):
        self._queue.append(message)
        if len(self._queue) >= self.batch_size:
            await self._flush()
```

#### Caching

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def expensive_crypto_operation(data: bytes) -> bytes:
    # Cached operation
    return result
```

## Contributing

### Code Style

- Follow PEP 8
- Use Black for formatting
- Type hints required
- Docstrings for all public APIs

### Commit Messages

```
feat: Add emoji reactions to messages

- Implement reaction message type
- Add reaction UI in chat widget
- Store reactions in database
- Update protocol documentation

Closes #123
```

Format:
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation
- `test:` Testing
- `refactor:` Code refactoring
- `perf:` Performance improvement

### Pull Request Process

1. **Fork & Clone**
   ```bash
   git clone https://github.com/yourusername/privatus-chat.git
   ```

2. **Create Branch**
   ```bash
   git checkout -b feature/your-feature
   ```

3. **Make Changes**
   - Write tests
   - Implement feature
   - Update docs

4. **Test Locally**
   ```bash
   pytest
   black src/
   pylint src/
   ```

5. **Submit PR**
   - Clear description
   - Reference issues
   - Include tests
   - Update changelog

### Code Review

Reviewers will check:
- [ ] Tests pass
- [ ] Code style compliance
- [ ] Security implications
- [ ] Performance impact
- [ ] Documentation updates
- [ ] Backward compatibility

## Resources

### Documentation
- [Architecture Overview](architecture.md)
- [API Reference](api-reference.md)
- [Security Model](../security/threat-model.md)

### Feature Documentation
- **[Voice Communication](../user/feature-voice-communication.md)**: Advanced calling system implementation
- **[File Transfer](../user/feature-file-transfer.md)**: Secure file sharing architecture
- **[Performance Monitoring](../user/feature-performance-monitoring.md)**: System optimization features
- **[Security Testing](../user/feature-security-testing.md)**: Vulnerability scanning framework

### External Resources
- [Signal Protocol Docs](https://signal.org/docs/)
- [PyQt6 Documentation](https://doc.qt.io/qtforpython/)
- [Python Asyncio](https://docs.python.org/3/library/asyncio.html)
- [Cryptography.io](https://cryptography.io/)

### Community
- GitHub Issues: Bug reports and features
- Discussions: General questions
- IRC: #privatus-chat on Libera
- Matrix: #privatus-chat:matrix.org

---

*Happy coding! Remember: Security and privacy come first.*

*Last updated: January 2025*
*Version: 1.0.0*