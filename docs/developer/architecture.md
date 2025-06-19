# Privatus-chat Architecture Overview

## Table of Contents

1. [System Architecture](#system-architecture)
2. [Core Components](#core-components)
3. [Cryptographic Architecture](#cryptographic-architecture)
4. [Network Architecture](#network-architecture)
5. [Data Flow](#data-flow)
6. [Security Model](#security-model)
7. [Scalability Design](#scalability-design)
8. [Component Interactions](#component-interactions)

## System Architecture

### High-Level Overview

```
┌─────────────────────────────────────────────────────────────┐
│                      User Interface Layer                    │
│                    (PyQt6 GUI Application)                   │
├─────────────────────────────────────────────────────────────┤
│                     Application Logic Layer                  │
│   ┌─────────────┬──────────────┬──────────────────────┐    │
│   │  Messaging  │   Contact    │    Privacy          │    │
│   │  Handler    │  Management  │    Controller       │    │
│   └─────────────┴──────────────┴──────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                    Security Services Layer                   │
│   ┌─────────────┬──────────────┬──────────────────────┐    │
│   │ Cryptography│    Onion     │    Identity         │    │
│   │   Engine    │   Routing    │    Manager          │    │
│   └─────────────┴──────────────┴──────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                    Network Services Layer                    │
│   ┌─────────────┬──────────────┬──────────────────────┐    │
│   │     P2P     │   Kademlia   │      NAT            │    │
│   │   Network   │     DHT      │    Traversal        │    │
│   └─────────────┴──────────────┴──────────────────────┘    │
├─────────────────────────────────────────────────────────────┤
│                      Storage Layer                           │
│   ┌─────────────┬──────────────┬──────────────────────┐    │
│   │  Encrypted  │     Key      │    Message          │    │
│   │  Database   │   Storage    │     Cache           │    │
│   └─────────────┴──────────────┴──────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Design Principles

1. **Decentralization**: No central servers or single points of failure
2. **Privacy by Default**: Maximum privacy with opt-in reduced privacy for performance
3. **Modularity**: Clean separation of concerns with well-defined interfaces
4. **Security First**: All design decisions prioritize security
5. **Open Standards**: Use established cryptographic protocols where possible

## Core Components

### 1. Cryptographic Module (`src/crypto/`)

**Purpose**: Handles all cryptographic operations

**Key Classes**:
- `SecureRandom`: Cryptographically secure random number generation
- `KeyManager`: Key lifecycle management (generation, storage, rotation)
- `MessageEncryption`: AES-256-GCM message encryption/decryption
- `DoubleRatchet`: Signal Protocol implementation for forward secrecy

**Responsibilities**:
- Key generation and management
- Message encryption/decryption
- Digital signatures
- Key exchange protocols
- Secure deletion

### 2. Network Module (`src/network/`)

**Purpose**: Manages peer-to-peer communications

**Key Classes**:
- `P2PNode`: Main network coordinator
- `KademliaDHT`: Distributed hash table for peer discovery
- `ConnectionManager`: Manages peer connections
- `NATTraversal`: STUN/TURN implementation
- `MessageProtocol`: Wire protocol for messages

**Responsibilities**:
- Peer discovery and routing
- Connection establishment
- Message routing
- NAT traversal
- Network topology management

### 3. Anonymity Module (`src/anonymity/`)

**Purpose**: Provides anonymity and metadata protection

**Key Classes**:
- `OnionRouter`: Multi-hop encrypted routing
- `TrafficAnalyzer`: Traffic analysis resistance
- `AnonymousIdentity`: Pseudonymous identity management
- `PrivacyController`: Privacy level management

**Responsibilities**:
- Onion circuit construction
- Traffic obfuscation
- Anonymous identity creation
- Metadata protection
- Cover traffic generation

### 4. GUI Module (`src/gui/`)

**Purpose**: User interface implementation

**Key Classes**:
- `MainWindow`: Primary application window
- `ChatWidget`: Message display and input
- `ContactList`: Contact management interface
- `PrivacyDashboard`: Privacy controls
- `SettingsDialog`: Configuration interface

**Responsibilities**:
- User interaction handling
- Real-time status updates
- Message rendering
- Contact management UI
- Settings management

### 5. Storage Module (`src/storage/`)

**Purpose**: Persistent data management

**Key Classes**:
- `DatabaseManager`: SQLite database interface
- `MessageStore`: Encrypted message storage
- `KeyStore`: Secure key storage
- `ConfigManager`: Application configuration

**Responsibilities**:
- Encrypted data persistence
- Message history management
- Key storage and retrieval
- Configuration management
- Cache optimization

## Cryptographic Architecture

### Protocol Stack

```
┌──────────────────────────────────────┐
│         Application Layer            │
│        (User Messages)               │
├──────────────────────────────────────┤
│       Double Ratchet Protocol        │
│    (Forward & Future Secrecy)        │
├──────────────────────────────────────┤
│          X3DH Key Exchange           │
│    (Initial Key Agreement)           │
├──────────────────────────────────────┤
│       AES-256-GCM Encryption         │
│    (Message Confidentiality)         │
├──────────────────────────────────────┤
│      Ed25519/X25519 Keys             │
│  (Identity & Key Agreement)          │
└──────────────────────────────────────┘
```

### Key Management

**Key Types**:
1. **Identity Keys**: Long-term Ed25519 keys for identity
2. **Signed Prekeys**: Medium-term keys for initial key exchange
3. **One-Time Prekeys**: Single-use keys for enhanced security
4. **Session Keys**: Ephemeral keys derived per message

**Key Lifecycle**:
```
Generate → Store (Encrypted) → Use → Rotate → Secure Delete
```

### Encryption Flow

```python
# Simplified encryption flow
def encrypt_message(plaintext, recipient):
    # 1. Get or establish session
    session = get_or_create_session(recipient)
    
    # 2. Ratchet forward
    message_key = session.ratchet_forward()
    
    # 3. Encrypt with AES-256-GCM
    ciphertext = aes_encrypt(plaintext, message_key)
    
    # 4. Add authentication tag
    return authenticated_encrypt(ciphertext, session)
```

## Network Architecture

### P2P Network Topology

```
    Node A ←→ Node B
      ↑ ↘     ↗ ↑
      ↓   ↘ ↗   ↓
    Node C ←→ Node D
```

### Peer Discovery

**Methods**:
1. **DHT Lookup**: Query Kademlia DHT for peer information
2. **Bootstrap Nodes**: Initial entry points to the network
3. **Peer Exchange**: Learn about new peers from existing connections
4. **Local Discovery**: Find peers on the same network

### Message Routing

**Direct Routing** (Low Privacy):
```
Sender → Recipient
```

**Onion Routing** (High Privacy):
```
Sender → Entry → Middle → Exit → Recipient
```

### NAT Traversal

**Techniques**:
1. **STUN**: Discover public IP and NAT type
2. **TURN**: Relay traffic when direct connection fails
3. **UDP Hole Punching**: Establish direct connections through NAT
4. **UPnP**: Automatic port forwarding when available

## Data Flow

### Message Send Flow

```
1. User composes message
   ↓
2. GUI passes to MessageHandler
   ↓
3. MessageHandler creates Message object
   ↓
4. CryptoEngine encrypts message
   ↓
5. OnionRouter wraps for anonymity (optional)
   ↓
6. NetworkLayer sends to peer(s)
   ↓
7. Acknowledgment received
   ↓
8. UI updated with status
```

### Message Receive Flow

```
1. NetworkLayer receives data
   ↓
2. OnionRouter unwraps layers (if used)
   ↓
3. CryptoEngine decrypts message
   ↓
4. MessageHandler validates and processes
   ↓
5. Storage saves encrypted copy
   ↓
6. GUI displays to user
   ↓
7. Send acknowledgment
```

## Security Model

### Threat Model

**Adversaries**:
1. **Passive Network Observer**: Can see network traffic
2. **Active Network Attacker**: Can modify/inject traffic
3. **Compromised Nodes**: Some peers may be malicious
4. **Physical Access**: Device may be seized
5. **State-Level**: Advanced persistent threats

**Protections**:
- End-to-end encryption prevents content inspection
- Onion routing hides metadata
- Perfect forward secrecy limits compromise impact
- Secure deletion protects seized devices
- Distributed architecture resists censorship

### Security Properties

1. **Confidentiality**: Only intended recipients can read messages
2. **Integrity**: Messages cannot be tampered with
3. **Authenticity**: Messages are from claimed sender
4. **Forward Secrecy**: Past messages secure if keys compromised
5. **Future Secrecy**: Future messages secure after compromise
6. **Anonymity**: Identity can be hidden when desired
7. **Unlinkability**: Messages cannot be linked to users

## Scalability Design

### Horizontal Scaling

**Techniques**:
- Distributed hash table spreads load
- No central bottlenecks
- Peer resources contribute to network
- Efficient routing algorithms

### Performance Optimizations

1. **Connection Pooling**: Reuse existing connections
2. **Message Batching**: Send multiple messages together
3. **Caching**: Store frequently accessed data
4. **Lazy Loading**: Load data only when needed
5. **Async Operations**: Non-blocking I/O throughout

### Resource Management

```python
# Example resource management pattern
class ResourceManager:
    def __init__(self):
        self.connection_pool = ConnectionPool(max_size=100)
        self.message_cache = LRUCache(max_size=1000)
        self.crypto_cache = KeyCache(max_size=50)
    
    async def get_connection(self, peer_id):
        return await self.connection_pool.acquire(peer_id)
    
    def cleanup(self):
        self.connection_pool.close_all()
        self.message_cache.clear()
        self.crypto_cache.secure_clear()
```

## Component Interactions

### Sequence Diagram: Sending a Message

```
User    GUI    MsgHandler    Crypto    Network    Storage
 │       │          │          │         │          │
 ├──────>│ Send     │          │         │          │
 │       ├─────────>│ Process  │         │          │
 │       │          ├─────────>│ Encrypt │          │
 │       │          │<─────────┤         │          │
 │       │          ├──────────────────>│ Send     │
 │       │          │          │         │          │
 │       │          ├────────────────────────────>│ Store
 │       │<─────────┤ Status   │         │          │
 │<──────┤ Update   │          │         │          │
```

### Class Relationships

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│   P2PNode   │────>│ Connection   │────>│    Peer       │
│             │     │   Manager    │     │               │
└─────────────┘     └──────────────┘     └───────────────┘
       │                    │                     │
       │                    │                     │
       ▼                    ▼                     ▼
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│ Kademlia    │     │   Message    │     │   Crypto      │
│    DHT      │     │   Protocol   │     │   Engine      │
└─────────────┘     └──────────────┘     └───────────────┘
```

### Event Flow

**Event-Driven Architecture**:
- Components communicate via events
- Loose coupling between modules
- Async event handling
- Event queue for reliability

```python
# Event system example
class EventBus:
    def __init__(self):
        self.handlers = defaultdict(list)
    
    def on(self, event_type, handler):
        self.handlers[event_type].append(handler)
    
    async def emit(self, event_type, data):
        for handler in self.handlers[event_type]:
            await handler(data)

# Usage
event_bus.on('message_received', handle_message)
await event_bus.emit('message_received', message_data)
```

---

*This architecture is designed for security, privacy, and scalability. For implementation details, see the [API Documentation](api-reference.md).*

*Last updated: December 2024*
*Version: 1.0.0* 