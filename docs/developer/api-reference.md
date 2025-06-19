# Privatus-chat API Reference

## Table of Contents

1. [Core APIs](#core-apis)
2. [Cryptographic APIs](#cryptographic-apis)
3. [Network APIs](#network-apis)
4. [Storage APIs](#storage-apis)
5. [GUI APIs](#gui-apis)
6. [REST API](#rest-api)
7. [WebSocket API](#websocket-api)
8. [Plugin API](#plugin-api)

## Core APIs

### Message Handling

#### `MessageHandler`

Main class for message processing.

```python
class MessageHandler:
    def __init__(self, crypto_engine: CryptoEngine, network: P2PNode):
        """Initialize message handler with crypto and network components."""
        
    async def send_message(self, recipient_id: str, content: str, 
                         message_type: MessageType = MessageType.CHAT) -> Message:
        """
        Send a message to a recipient.
        
        Args:
            recipient_id: Public key or ID of recipient
            content: Message content to send
            message_type: Type of message (CHAT, FILE, etc.)
            
        Returns:
            Message object with send status
            
        Raises:
            RecipientNotFoundError: If recipient cannot be found
            EncryptionError: If message cannot be encrypted
        """
        
    async def receive_message(self, data: bytes, sender_id: str) -> Message:
        """Process received message data."""
        
    def get_conversation(self, contact_id: str) -> List[Message]:
        """Retrieve message history for a contact."""
```

#### `Message`

Message data structure.

```python
@dataclass
class Message:
    id: str
    sender_id: str
    recipient_id: str
    content: str
    timestamp: datetime
    message_type: MessageType
    encryption_status: EncryptionStatus
    delivery_status: DeliveryStatus
    
    def to_dict(self) -> dict:
        """Convert message to dictionary format."""
        
    @classmethod
    def from_dict(cls, data: dict) -> 'Message':
        """Create message from dictionary."""
```

### Contact Management

#### `ContactManager`

Manages user contacts and verification.

```python
class ContactManager:
    def add_contact(self, name: str, public_key: str, 
                   verified: bool = False) -> Contact:
        """Add a new contact."""
        
    def verify_contact(self, contact_id: str, fingerprint: str) -> bool:
        """Verify a contact's identity."""
        
    def get_contacts(self, filter_online: bool = False) -> List[Contact]:
        """Retrieve list of contacts."""
        
    def block_contact(self, contact_id: str) -> None:
        """Block a contact."""
        
    def get_fingerprint(self, contact_id: str) -> str:
        """Get cryptographic fingerprint for verification."""
```

## Cryptographic APIs

### Key Management

#### `KeyManager`

Handles cryptographic key lifecycle.

```python
class KeyManager:
    def __init__(self, storage_path: str):
        """Initialize key manager with secure storage location."""
        
    def generate_identity_keypair(self) -> Tuple[PrivateKey, PublicKey]:
        """Generate new Ed25519 identity keypair."""
        
    def generate_prekey_bundle(self, count: int = 100) -> PreKeyBundle:
        """
        Generate prekey bundle for X3DH.
        
        Args:
            count: Number of one-time prekeys to generate
            
        Returns:
            PreKeyBundle containing signed prekey and one-time prekeys
        """
        
    def rotate_keys(self, key_type: KeyType) -> None:
        """Rotate specified key type."""
        
    def export_public_key(self) -> str:
        """Export public identity key in base64."""
        
    def import_contact_key(self, key_data: str) -> PublicKey:
        """Import a contact's public key."""
```

### Encryption

#### `CryptoEngine`

Main encryption/decryption interface.

```python
class CryptoEngine:
    def encrypt_message(self, plaintext: bytes, recipient_key: PublicKey,
                       session: Optional[Session] = None) -> EncryptedMessage:
        """
        Encrypt message for recipient.
        
        Args:
            plaintext: Message content to encrypt
            recipient_key: Recipient's public key
            session: Existing session (optional)
            
        Returns:
            EncryptedMessage with ciphertext and metadata
        """
        
    def decrypt_message(self, encrypted: EncryptedMessage, 
                       sender_key: PublicKey) -> bytes:
        """Decrypt received message."""
        
    def create_session(self, recipient_key: PublicKey, 
                      prekey_bundle: PreKeyBundle) -> Session:
        """Establish new session using X3DH."""
```

### Double Ratchet

#### `DoubleRatchet`

Signal Protocol implementation.

```python
class DoubleRatchet:
    def __init__(self, shared_secret: bytes, remote_public_key: PublicKey):
        """Initialize Double Ratchet with shared secret."""
        
    def encrypt(self, plaintext: bytes) -> Tuple[Header, bytes]:
        """Encrypt with forward secrecy."""
        
    def decrypt(self, header: Header, ciphertext: bytes) -> bytes:
        """Decrypt and advance ratchet."""
        
    def ratchet_forward(self) -> None:
        """Manually advance the ratchet."""
```

## Network APIs

### P2P Networking

#### `P2PNode`

Main networking coordinator.

```python
class P2PNode:
    def __init__(self, port: int = 9001, identity: Identity = None):
        """Initialize P2P node."""
        
    async def start(self) -> None:
        """Start the P2P node and begin listening."""
        
    async def connect_to_peer(self, peer_address: str) -> Peer:
        """Connect to a specific peer."""
        
    async def broadcast_message(self, message: Message) -> None:
        """Broadcast message to all connected peers."""
        
    def get_peers(self) -> List[Peer]:
        """Get list of connected peers."""
        
    async def shutdown(self) -> None:
        """Gracefully shut down the node."""
```

### DHT Operations

#### `KademliaDHT`

Distributed hash table implementation.

```python
class KademliaDHT:
    async def store(self, key: bytes, value: bytes) -> bool:
        """Store value in DHT."""
        
    async def find_value(self, key: bytes) -> Optional[bytes]:
        """Retrieve value from DHT."""
        
    async def find_node(self, node_id: bytes) -> List[Node]:
        """Find nodes close to given ID."""
        
    def get_routing_table(self) -> RoutingTable:
        """Get current routing table state."""
```

### Onion Routing

#### `OnionRouter`

Anonymous routing implementation.

```python
class OnionRouter:
    def __init__(self, node: P2PNode, min_hops: int = 3):
        """Initialize onion router."""
        
    async def create_circuit(self) -> Circuit:
        """Create new onion circuit."""
        
    async def send_through_circuit(self, circuit: Circuit, 
                                 data: bytes) -> None:
        """Send data through onion circuit."""
        
    def get_active_circuits(self) -> List[Circuit]:
        """Get list of active circuits."""
```

## Storage APIs

### Database Operations

#### `DatabaseManager`

Main database interface.

```python
class DatabaseManager:
    def __init__(self, db_path: str, encryption_key: bytes):
        """Initialize encrypted database."""
        
    def save_message(self, message: Message) -> None:
        """Save message to database."""
        
    def get_messages(self, contact_id: str, limit: int = 100,
                    offset: int = 0) -> List[Message]:
        """Retrieve messages for a contact."""
        
    def delete_messages(self, older_than: datetime) -> int:
        """Delete messages older than specified date."""
        
    def vacuum(self) -> None:
        """Optimize database and securely delete free space."""
```

### Configuration

#### `ConfigManager`

Application configuration management.

```python
class ConfigManager:
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        
    def set(self, key: str, value: Any) -> None:
        """Set configuration value."""
        
    def get_privacy_level(self) -> PrivacyLevel:
        """Get current privacy level setting."""
        
    def export_config(self) -> dict:
        """Export all configuration."""
```

## GUI APIs

### Main Window

#### `MainWindow`

Primary application window.

```python
class MainWindow(QMainWindow):
    # Signals
    message_sent = pyqtSignal(str, str)  # recipient_id, content
    contact_selected = pyqtSignal(str)   # contact_id
    
    def __init__(self, backend: Backend):
        """Initialize main window with backend."""
        
    def display_message(self, message: Message) -> None:
        """Display message in chat area."""
        
    def update_contact_status(self, contact_id: str, 
                            status: ContactStatus) -> None:
        """Update contact online/offline status."""
        
    def show_notification(self, title: str, message: str) -> None:
        """Show system notification."""
```

### Custom Widgets

#### `ChatWidget`

Message display widget.

```python
class ChatWidget(QWidget):
    def add_message(self, message: Message, is_mine: bool = False) -> None:
        """Add message to chat display."""
        
    def clear_messages(self) -> None:
        """Clear all messages from display."""
        
    def scroll_to_bottom(self) -> None:
        """Scroll to most recent message."""
```

## REST API

### Endpoints

#### Authentication

```http
POST /api/v1/auth/login
Content-Type: application/json

{
    "password": "master_password"
}

Response:
{
    "token": "jwt_token",
    "expires_in": 3600
}
```

#### Messages

```http
POST /api/v1/messages
Authorization: Bearer <token>
Content-Type: application/json

{
    "recipient_id": "public_key_base64",
    "content": "Hello, World!",
    "message_type": "CHAT"
}

Response:
{
    "message_id": "uuid",
    "timestamp": "2024-01-01T00:00:00Z",
    "delivery_status": "SENT"
}
```

```http
GET /api/v1/messages?contact_id=<id>&limit=50
Authorization: Bearer <token>

Response:
{
    "messages": [
        {
            "id": "uuid",
            "sender_id": "public_key",
            "content": "encrypted_content",
            "timestamp": "2024-01-01T00:00:00Z"
        }
    ],
    "total": 150,
    "has_more": true
}
```

#### Contacts

```http
GET /api/v1/contacts
Authorization: Bearer <token>

Response:
{
    "contacts": [
        {
            "id": "public_key",
            "name": "Alice",
            "verified": true,
            "online": false,
            "last_seen": "2024-01-01T00:00:00Z"
        }
    ]
}
```

```http
POST /api/v1/contacts
Authorization: Bearer <token>
Content-Type: application/json

{
    "name": "Bob",
    "public_key": "base64_public_key"
}
```

## WebSocket API

### Connection

```javascript
const ws = new WebSocket('ws://localhost:9001/ws');

ws.onopen = () => {
    // Authenticate
    ws.send(JSON.stringify({
        type: 'auth',
        token: 'jwt_token'
    }));
};
```

### Message Events

```javascript
// Incoming message
{
    "type": "message",
    "data": {
        "id": "uuid",
        "sender_id": "public_key",
        "content": "encrypted_content",
        "timestamp": "2024-01-01T00:00:00Z"
    }
}

// Status update
{
    "type": "status_update",
    "data": {
        "contact_id": "public_key",
        "status": "online"
    }
}

// Typing indicator
{
    "type": "typing",
    "data": {
        "contact_id": "public_key",
        "is_typing": true
    }
}
```

## Plugin API

### Plugin Structure

```python
class PrivatusChatPlugin:
    """Base class for all plugins."""
    
    def __init__(self, api: PluginAPI):
        self.api = api
        
    def on_load(self) -> None:
        """Called when plugin is loaded."""
        
    def on_message_received(self, message: Message) -> Optional[Message]:
        """
        Called when message is received.
        Return modified message or None to block.
        """
        
    def on_message_send(self, message: Message) -> Optional[Message]:
        """Called before message is sent."""
        
    def get_menu_items(self) -> List[MenuItem]:
        """Add custom menu items."""
```

### Plugin API Interface

```python
class PluginAPI:
    """API exposed to plugins."""
    
    def send_message(self, recipient_id: str, content: str) -> None:
        """Send a message."""
        
    def get_contacts(self) -> List[Contact]:
        """Get user's contacts."""
        
    def show_notification(self, title: str, message: str) -> None:
        """Show desktop notification."""
        
    def register_command(self, command: str, 
                        handler: Callable) -> None:
        """Register custom command."""
        
    def get_setting(self, key: str) -> Any:
        """Get plugin setting."""
        
    def set_setting(self, key: str, value: Any) -> None:
        """Save plugin setting."""
```

### Example Plugin

```python
class TranslatorPlugin(PrivatusChatPlugin):
    """Auto-translate messages plugin."""
    
    def on_load(self):
        self.api.register_command('/translate', self.translate_command)
        
    def on_message_received(self, message):
        if self.should_translate(message.sender_id):
            message.content = self.translate(message.content)
        return message
        
    def translate_command(self, args):
        # Implementation
        pass
```

---

*For more examples and tutorials, see the [Developer Guide](developer-guide.md).*

*Last updated: December 2024*
*Version: 1.0.0* 