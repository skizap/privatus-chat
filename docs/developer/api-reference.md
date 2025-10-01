# Privatus-chat API Reference

## Overview

This document provides comprehensive API reference and usage guidelines for Privatus-chat, a secure peer-to-peer messaging application with advanced privacy features including end-to-end encryption, onion routing, and anonymous identity management.

## Core Modules

### 1. Cryptographic Module (`src.crypto`)

#### 1.1 Secure Random Number Generation

**Class: `SecureRandom`**

```python
class SecureRandom:
    """Cryptographically secure random number generator."""
    
    @staticmethod
    def generate_bytes(length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
    
    @staticmethod
    def generate_int(bits: int) -> int:
        """Generate cryptographically secure random integer."""
    
    @staticmethod
    def generate_nonce(length: int = 12) -> bytes:
        """Generate secure nonce for encryption."""
    
    @staticmethod
    def estimate_entropy() -> float:
        """Estimate available system entropy."""
```

**Convenience Functions:**

```python
def secure_random_bytes(length: int) -> bytes:
    """Generate secure random bytes."""
    
def secure_random_int(bits: int) -> int:
    """Generate secure random integer."""
```

**Usage Example:**
```python
from src.crypto import SecureRandom, secure_random_bytes

# Generate encryption key
key = SecureRandom.generate_bytes(32)  # 256-bit key

# Generate nonce for AES-GCM
nonce = SecureRandom.generate_nonce(12)

# Generate random integer
random_id = secure_random_int(64)
```

#### 1.2 Key Management

**Class: `KeyManager`**

```python
class KeyManager:
    """Manages cryptographic keys for Privatus-chat."""
    
    def __init__(self, storage_path: Path, password: Optional[str] = None):
        """Initialize key manager with optional password protection."""
    
    def generate_identity_key(self) -> IdentityKey:
        """Generate new Ed25519 identity key pair."""
    
    def generate_signed_prekey(self, key_id: int) -> PreKey:
        """Generate new signed prekey for X3DH."""
    
    def generate_one_time_prekeys(self, count: int) -> Dict[int, PreKey]:
        """Generate multiple one-time prekeys."""
    
    def get_prekey_bundle(self) -> Dict[str, Any]:
        """Get prekey bundle for key agreement."""
    
    def use_one_time_prekey(self, key_id: int) -> Optional[PreKey]:
        """Mark one-time prekey as used."""
    
    def verify_password(self, password: str, stored_key: bytes, salt: bytes) -> bool:
        """Verify password using timing-safe comparison."""
```

**Class: `IdentityKey`**

```python
class IdentityKey:
    """Ed25519 identity key for user authentication."""
    
    def __init__(self, signing_key: ed25519.Ed25519PrivateKey):
        """Initialize with Ed25519 private key."""
    
    def sign(self, message: bytes) -> bytes:
        """Sign message with identity key."""
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify signature with identity key."""
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes."""
```

**Class: `PreKey`**

```python
class PreKey:
    """X25519 prekey for X3DH key agreement."""
    
    def __init__(self, key_id: int, private_key: X25519PrivateKey):
        """Initialize with key ID and private key."""
    
    def mark_used(self) -> None:
        """Mark prekey as used (one-time use)."""
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes."""
    
    def perform_dh(self, other_public_key: bytes) -> bytes:
        """Perform Diffie-Hellman key agreement."""
```

**Usage Example:**
```python
from pathlib import Path
from src.crypto import KeyManager

# Initialize key manager
key_manager = KeyManager(Path("./keys"), password="secure_password")

# Generate identity key
identity_key = key_manager.generate_identity_key()

# Generate signed prekey
signed_prekey = key_manager.generate_signed_prekey(1)

# Generate one-time prekeys
prekeys = key_manager.generate_one_time_prekeys(10)

# Get prekey bundle for X3DH
bundle = key_manager.get_prekey_bundle()
```

#### 1.3 Message Encryption

**Class: `MessageEncryption`**

```python
class MessageEncryption:
    """AES-256-GCM message encryption and decryption."""
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate new 256-bit encryption key."""
    
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, 
                associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Encrypt plaintext with AES-256-GCM."""
    
    @staticmethod
    def decrypt(nonce: bytes, ciphertext: bytes, key: bytes,
                associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt ciphertext with AES-256-GCM."""
    
    @staticmethod
    def encrypt_with_header(plaintext: bytes, key: bytes,
                           header_data: Optional[bytes] = None) -> bytes:
        """Encrypt with nonce prepended."""
    
    @staticmethod
    def decrypt_with_header(encrypted_data: bytes, key: bytes,
                           header_data: Optional[bytes] = None) -> bytes:
        """Decrypt data with prepended nonce."""
```

**Class: `KeyDerivation`**

```python
class KeyDerivation:
    """Key derivation utilities using HKDF."""
    
    @staticmethod
    def derive_keys(shared_secret: bytes, salt: bytes, info: bytes,
                   num_keys: int = 1, key_length: int = 32) -> List[bytes]:
        """Derive multiple keys from shared secret."""
    
    @staticmethod
    def derive_message_key(chain_key: bytes, counter: int) -> Tuple[bytes, bytes]:
        """Derive message key and next chain key."""
```

**Convenience Functions:**

```python
def encrypt_message(message: bytes, key: bytes) -> bytes:
    """Encrypt message with header."""
    
def decrypt_message(encrypted_data: bytes, key: bytes) -> bytes:
    """Decrypt message with header."""
```

**Usage Example:**
```python
from src.crypto import MessageEncryption, encrypt_message, decrypt_message

# Generate encryption key
key = MessageEncryption.generate_key()

# Encrypt message
message = b"Hello, secure world!"
encrypted = encrypt_message(message, key)

# Decrypt message
decrypted = decrypt_message(encrypted, key)
assert decrypted == message
```

**Error Classes:**

```python
class EncryptionError(Exception):
    """Base class for encryption errors."""
    
class DecryptionError(Exception):
    """Base class for decryption errors."""
```

### 2. Network Module (`src.network`)

#### 2.1 P2P Node Management

**Class: `P2PNode`**

```python
class P2PNode:
    """Main P2P node coordinating all networking components."""
    
    def __init__(self, node_id: bytes = None, bind_address: str = "0.0.0.0", 
                 bind_port: int = 0):
        """Initialize P2P node."""
    
    async def start(self, bootstrap_nodes: List[tuple] = None):
        """Start P2P node and all components."""
    
    async def stop(self):
        """Stop P2P node and cleanup resources."""
    
    async def send_message(self, peer_id: bytes, message_type: str, 
                          payload: Dict[str, Any]) -> bool:
        """Send message to specific peer."""
    
    async def connect_to_peer(self, address: str, port: int) -> bool:
        """Connect to specific peer."""
    
    def get_connected_peers(self) -> List[bytes]:
        """Get list of connected peer IDs."""
    
    def get_discovered_peers(self) -> List:
        """Get list of discovered peers."""
    
    def get_node_info(self) -> Dict[str, Any]:
        """Get comprehensive node information."""
```

**Usage Example:**
```python
import asyncio
from src.network import P2PNode

async def main():
    # Create P2P node
    node = P2PNode()
    
    # Start node
    await node.start()
    
    # Connect to bootstrap node
    await node.connect_to_peer("bootstrap.example.com", 6881)
    
    # Send message to peer
    await node.send_message(
        peer_id=some_peer_id,
        message_type="chat",
        payload={"content": "Hello!"}
    )
    
    # Get node info
    info = node.get_node_info()
    print(f"Connected to {info['connected_peers']} peers")

# Run the node
asyncio.run(main())
```

#### 2.2 Message Protocol

**Class: `MessageProtocol`**

```python
class MessageProtocol:
    """P2P message protocol handler."""
    
    def __init__(self, node_id: bytes, key_manager: Optional['KeyManager'] = None,
                 signature_required: bool = False):
        """Initialize message protocol."""
    
    async def handle_message(self, message: P2PMessage, peer_id: bytes) -> Optional[P2PMessage]:
        """Handle incoming message."""
```

**Class: `MessageSerializer`**

```python
class MessageSerializer:
    """Message serialization and cryptographic signing."""
    
    def __init__(self, compress_threshold: int = 1024, 
                 key_manager: Optional['KeyManager'] = None,
                 signature_required: bool = False):
        """Initialize message serializer."""
    
    def serialize(self, message: P2PMessage) -> bytes:
        """Serialize message to bytes."""
    
    def deserialize(self, data: bytes) -> P2PMessage:
        """Deserialize message from bytes."""
    
    def create_chat_message(self, sender_id: bytes, recipient_id: bytes, 
                           content: str, encrypted: bool = True) -> P2PMessage:
        """Create chat message."""
    
    def create_handshake_message(self, sender_id: bytes, public_key: bytes) -> P2PMessage:
        """Create handshake message."""
    
    def create_ping_message(self, sender_id: bytes) -> P2PMessage:
        """Create ping message."""
```

**Message Types:**

```python
class MessageType(Enum):
    """P2P message types."""
    HANDSHAKE = "handshake"
    HANDSHAKE_ACK = "handshake_ack"
    PING = "pong"
    PONG = "pong"
    CHAT_MESSAGE = "chat_message"
    MESSAGE_ACK = "message_ack"
    DISCONNECT = "disconnect"
    FILE_OFFER = "file_offer"
    FILE_CHUNK = "file_chunk"
    GROUP_INVITE = "group_invite"
    GROUP_MESSAGE = "group_message"
    ERROR = "error"
```

**Usage Example:**
```python
from src.network import MessageProtocol, MessageSerializer
from src.crypto import KeyManager

# Initialize components
key_manager = KeyManager(Path("./keys"))
protocol = MessageProtocol(node_id, key_manager, signature_required=True)

# Create chat message
message = protocol.serializer.create_chat_message(
    sender_id=my_node_id,
    recipient_id=peer_id,
    content="Hello, encrypted world!",
    encrypted=True
)

# Serialize for sending
serialized = protocol.serializer.serialize(message)

# Deserialize received message
received_message = protocol.serializer.deserialize(received_data)
```

### 3. Messaging Module (`src.messaging`)

#### 3.1 Group Chat Management

**Class: `GroupChatManager`**

```python
class GroupChatManager:
    """Manager for group chat operations."""
    
    def __init__(self, storage_manager, crypto_manager):
        """Initialize group chat manager."""
    
    def generate_group_id(self) -> str:
        """Generate unique group ID."""
    
    def generate_anonymous_id(self) -> str:
        """Generate anonymous member ID."""
    
    def create_group(self, creator_id: str, name: str, description: str = "", 
                    group_type: GroupType = GroupType.PRIVATE, 
                    is_anonymous: bool = True) -> Optional[str]:
        """Create new group."""
    
    def join_group(self, group_id: str, user_id: str, display_name: str, 
                  public_key: str, invitation_code: Optional[str] = None) -> bool:
        """Join existing group."""
    
    def leave_group(self, group_id: str, user_id: str) -> bool:
        """Leave group."""
    
    def get_group(self, group_id: str) -> Optional[Group]:
        """Get group by ID."""
    
    def get_user_groups(self, user_id: str) -> List[Group]:
        """Get all groups for user."""
    
    def get_group_members(self, group_id: str) -> List[GroupMember]:
        """Get all group members."""
    
    def invite_to_group(self, group_id: str, inviter_id: str, 
                       invitee_public_key: str) -> Optional[str]:
        """Generate group invitation."""
```

**Class: `Group`**

```python
class Group:
    """Group chat representation."""
    
    def __init__(self, group_id: str, name: str, description: str = "", 
                 group_type: GroupType = GroupType.PRIVATE, 
                 created_at: datetime = None, created_by: Optional[str] = None,
                 max_members: int = 100, is_anonymous: bool = True):
        """Initialize group."""
    
    def add_member(self, member: GroupMember) -> bool:
        """Add member to group."""
    
    def remove_member(self, member_id: str) -> bool:
        """Remove member from group."""
    
    def get_member(self, member_id: str) -> Optional[GroupMember]:
        """Get member by ID."""
    
    def update_member_status(self, member_id: str, is_online: bool):
        """Update member online status."""
```

**Usage Example:**
```python
from src.messaging import GroupChatManager, GroupType

# Initialize manager
group_manager = GroupChatManager(storage_manager, crypto_manager)

# Create new group
group_id = group_manager.create_group(
    creator_id="user123",
    name="Secret Project Team",
    description="Private discussion group",
    group_type=GroupType.PRIVATE,
    is_anonymous=True
)

# Join group
success = group_manager.join_group(
    group_id=group_id,
    user_id="user456",
    display_name="Anonymous User",
    public_key=user_public_key
)

# Get group members
members = group_manager.get_group_members(group_id)
```

### 4. Storage Module (`src.storage`)

#### 4.1 Secure Database

**Class: `SecureDatabase`**

```python
class SecureDatabase:
    """Encrypted database for persistent storage."""
    
    def __init__(self, db_path: Path, password: str):
        """Initialize encrypted database."""
    
    def add_contact(self, contact: Contact) -> bool:
        """Add new contact."""
    
    def get_contact(self, contact_id: str) -> Optional[Contact]:
        """Get contact by ID."""
    
    def get_all_contacts(self) -> List[Contact]:
        """Get all contacts."""
    
    def update_contact_status(self, contact_id: str, is_online: bool) -> bool:
        """Update contact online status."""
    
    def remove_contact(self, contact_id: str) -> bool:
        """Remove contact and associated messages."""
    
    def add_message(self, message: Message) -> bool:
        """Add new message."""
    
    def get_messages(self, contact_id: str, limit: int = 100) -> List[Message]:
        """Get messages for contact."""
    
    def set_setting(self, key: str, value: Any) -> bool:
        """Set configuration setting."""
    
    def get_setting(self, key: str, default_value: Any = None) -> Any:
        """Get configuration setting."""
    
    def check_integrity(self) -> bool:
        """Check database integrity."""
    
    def repair_database(self) -> bool:
        """Attempt database repair."""
```

**Data Classes:**

```python
@dataclass
class Contact:
    """Contact data structure."""
    contact_id: str
    display_name: str
    public_key: str
    is_verified: bool = False
    is_online: bool = False
    added_at: datetime = None
    last_seen: datetime = None

@dataclass
class Message:
    """Message data structure."""
    message_id: str
    contact_id: str
    content: str
    is_outgoing: bool
    is_encrypted: bool = True
    timestamp: datetime = None
```

**Usage Example:**
```python
from pathlib import Path
from src.storage import SecureDatabase, Contact, Message

# Initialize database
db = SecureDatabase(Path("./data/privatus.db"), "secure_password")

# Add contact
contact = Contact(
    contact_id="user123",
    display_name="Alice",
    public_key="alice_public_key_bytes"
)
db.add_contact(contact)

# Add message
message = Message(
    message_id="msg456",
    contact_id="user123",
    content="Hello from secure storage!",
    is_outgoing=True,
    is_encrypted=True
)
db.add_message(message)

# Retrieve messages
messages = db.get_messages("user123", limit=50)
```

### 5. GUI Module (`src.gui`)

#### 5.1 Main GUI Application

**Class: `PrivatusChatGUI`**

```python
class PrivatusChatGUI(QObject):
    """Main GUI application class."""
    
    def __init__(self, app_data_dir=None, key_manager=None):
        """Initialize GUI application."""
    
    def initialize(self):
        """Initialize GUI components."""
    
    def show(self):
        """Show main window."""
    
    def shutdown(self):
        """Shutdown GUI application."""
```

**Function: `run_gui_application`**

```python
def run_gui_application(app_data_dir=None, key_manager=None):
    """Run the Privatus-chat GUI application."""
```

**Usage Example:**
```python
from src.gui import run_gui_application
from src.crypto import KeyManager
from pathlib import Path

# Initialize key manager
key_manager = KeyManager(Path("./keys"), "password")

# Run GUI application
exit_code = run_gui_application(
    app_data_dir=Path("./data"),
    key_manager=key_manager
)
```

#### 5.2 GUI Components

**Class: `MainChatWindow`**

```python
class MainChatWindow:
    """Main chat window."""
    
    def load_real_contacts(self):
        """Load contacts from storage."""
    
    def add_message(self, content: str, is_outgoing: bool, is_encrypted: bool):
        """Add message to chat area."""
```

**Security Indicator Classes:**

```python
class SecurityIndicator:
    """Security status indicator widget."""
    
    def update_encryption_status(self, enabled: bool, status: str):
        """Update encryption status display."""
    
    def update_anonymity_status(self, level: str, details: str):
        """Update anonymity status display."""
    
    def update_network_status(self, connected: bool, peer_count: int):
        """Update network status display."""
```

## Usage Guidelines

### Best Practices

#### 1. Cryptographic Operations

- **Key Management**: Always use `KeyManager` for key lifecycle management
- **Password Security**: Use strong passwords (12+ characters) for key encryption
- **Secure Random**: Always use `SecureRandom` for cryptographic operations
- **Memory Safety**: Keys are automatically destroyed when objects are garbage collected

#### 2. Network Operations

- **Node Lifecycle**: Always properly start and stop P2P nodes
- **Error Handling**: Implement proper error handling for network operations
- **Resource Cleanup**: Ensure connections are properly closed

#### 3. Message Handling

- **Encryption**: Always encrypt messages before sending
- **Authentication**: Verify message signatures when required
- **Compression**: Large messages are automatically compressed

#### 4. Storage Operations

- **Password Protection**: Always use strong passwords for database encryption
- **Integrity Checks**: Regularly verify database integrity
- **Backup Strategy**: Implement regular backup procedures

### Security Guidelines

#### Authentication Requirements

1. **Identity Verification**: All nodes must have valid Ed25519 identity keys
2. **Message Signing**: Cryptographic signatures required for authenticated operations
3. **Password Security**: Minimum 12 characters with mixed character types
4. **Key Encryption**: Database and key storage must be encrypted at rest

#### Performance Considerations

1. **Key Derivation**: PBKDF2 iterations are adaptively tuned to system performance
2. **Message Compression**: Messages over 1KB are automatically compressed
3. **Connection Pooling**: Connection manager handles peer connection lifecycle
4. **Database Optimization**: WAL mode enabled for improved concurrency

### Integration Patterns

#### Basic Setup Pattern

```python
import asyncio
from pathlib import Path
from src.crypto import KeyManager
from src.network import P2PNode
from src.storage import SecureDatabase
from src.gui import run_gui_application

async def setup_privatus_chat():
    # Initialize components
    data_dir = Path("./privatus_data")
    key_manager = KeyManager(data_dir / "keys", "secure_password")
    database = SecureDatabase(data_dir / "chat.db", "secure_password")
    
    # Generate keys
    identity_key = key_manager.generate_identity_key()
    signed_prekey = key_manager.generate_signed_prekey(1)
    prekeys = key_manager.generate_one_time_prekeys(10)
    
    # Start P2P node
    node = P2PNode()
    await node.start()
    
    return node, database, key_manager

# Run setup
node, db, keys = asyncio.run(setup_privatus_chat())
```

#### Message Sending Pattern

```python
async def send_secure_message(node, recipient_id, message_content):
    # Create encrypted message
    from src.crypto import MessageEncryption
    key = MessageEncryption.generate_key()
    encrypted_content = MessageEncryption.encrypt_with_header(
        message_content.encode(), key
    )
    
    # Send through network
    success = await node.send_message(
        peer_id=recipient_id,
        message_type="chat_message",
        payload={
            "content": encrypted_content.hex(),
            "key": key.hex(),
            "encrypted": True
        }
    )
    
    return success
```

## Error Handling

### Exception Hierarchy

```
Exception
├── CryptoError
│   ├── EncryptionError
│   ├── DecryptionError
│   └── KeyDerivationError
├── NetworkError
│   ├── ConnectionError
│   └── ProtocolError
├── StorageError
│   ├── DatabaseError
│   └── IntegrityError
└── GUIError
    ├── InitializationError
    └── DisplayError
```

### Error Handling Best Practices

1. **Always catch specific exceptions** rather than using bare `except:`
2. **Log security events** using the secure logger
3. **Provide user feedback** for recoverable errors
4. **Graceful degradation** for non-critical failures

## Troubleshooting

### Common Issues

#### 1. Key Derivation Failures
- **Symptom**: `ValueError: Key derivation failed`
- **Cause**: Weak password or insufficient system entropy
- **Solution**: Use stronger password (12+ chars) and ensure system has adequate entropy

#### 2. Network Connection Issues
- **Symptom**: `ConnectionError: Failed to connect to peer`
- **Cause**: NAT traversal issues or firewall blocking
- **Solution**: Check NAT configuration and firewall settings

#### 3. Database Corruption
- **Symptom**: `IntegrityError: Database integrity check failed`
- **Cause**: Unexpected shutdown or disk corruption
- **Solution**: Run `repair_database()` or restore from backup

### Debugging Tips

1. **Enable debug logging** to troubleshoot issues
2. **Check system entropy** before cryptographic operations
3. **Verify network connectivity** using ping/pong messages
4. **Monitor database integrity** regularly in production

## Security Considerations

### For API Consumers

1. **Key Security**: Never store private keys in plain text
2. **Password Strength**: Enforce strong password requirements
3. **Network Security**: Use encrypted connections and proper authentication
4. **Data Protection**: Encrypt all stored sensitive data

### For Developers

1. **Code Review**: All cryptographic code should be reviewed by security experts
2. **Testing**: Comprehensive testing of security features required
3. **Updates**: Keep cryptographic libraries updated
4. **Audit Trail**: Maintain security audit logs

This API reference provides the foundation for building secure, private messaging applications with Privatus-chat. For additional examples and advanced usage patterns, see the `examples/` directory.