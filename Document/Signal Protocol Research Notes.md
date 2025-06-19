# Signal Protocol Research Notes

## Double Ratchet Algorithm Specification

Source: https://signal.org/docs/specifications/doubleratchet/

### Key Concepts:

1. **KDF Chains**: Core concept using Key Derivation Functions with properties:
   - Resilience: Output keys appear random without knowledge of KDF keys
   - Forward security: Past output keys appear random even if current KDF key is compromised
   - Break-in recovery: Future output keys appear random after compromise if sufficient entropy is added

2. **Symmetric-key Ratchet**: Each message encrypted with unique message key derived from sending/receiving chains

3. **Diffie-Hellman Ratchet**: Updates chain keys based on DH outputs to prevent future compromise from past key theft

4. **Double Ratchet**: Combines both ratchets for comprehensive forward secrecy and post-compromise security

### Security Properties:
- Forward secrecy for messages
- Post-compromise security through DH ratchet
- Unique message keys for each message
- Protection against key compromise scenarios

### Implementation Requirements:
- Secure deletion of old keys
- Proper handling of out-of-order messages
- Integration with key agreement protocols (X3DH)
- Recommended cryptographic algorithms (HMAC, HKDF, AES-GCM, Curve25519)


## X3DH Key Agreement Protocol

Source: https://signal.org/docs/specifications/x3dh/

### Purpose:
X3DH (Extended Triple Diffie-Hellman) establishes a shared secret key between two parties who mutually authenticate each other based on public keys. Designed for asynchronous settings where one user is offline.

### Key Properties:
- Forward secrecy
- Cryptographic deniability
- Asynchronous operation (works when recipient is offline)
- Mutual authentication

### Protocol Phases:
1. **Publishing keys**: Bob publishes identity key and prekeys to server
2. **Sending initial message**: Alice fetches prekey bundle and sends initial message
3. **Receiving initial message**: Bob processes Alice's message

### Key Types:
- **IKA/IKB**: Identity keys (long-term)
- **EKA**: Alice's ephemeral key (generated per session)
- **SPKB**: Bob's signed prekey (changed periodically)
- **OPKB**: Bob's one-time prekeys (used once)

### Cryptographic Parameters:
- **Curve**: X25519 or X448
- **Hash**: SHA-256 or SHA-512
- **Signatures**: XEdDSA
- **KDF**: HKDF

### Security Considerations:
- Authentication through key verification
- Protection against replay attacks
- Deniability properties
- Key compromise scenarios
- Server trust assumptions


## Onion Routing for Anonymity

Source: https://www.geeksforgeeks.org/onion-routing/

### Core Concept:
Onion routing is a technique for anonymous communication where messages are encapsulated in layers of encryption, analogous to layers of an onion. Each layer is peeled off at different network nodes.

### How It Works:
1. **Multi-hop routing**: Connection hops from one server to another before reaching destination
2. **Layered encryption**: Message encrypted multiple times with different keys for each hop
3. **Key distribution**: Client has all keys, servers only have keys for their specific hop
4. **Sequential decryption**: Each node removes one layer of encryption and forwards to next node

### Anonymity Mechanism:
- **Traffic obfuscation**: Sniffers only see encrypted traffic to/from intermediate nodes
- **Source hiding**: Destination server doesn't know original client
- **Destination hiding**: Network observers don't know final destination
- **Timing correlation resistance**: Multiple concurrent connections make correlation difficult

### Security Features:
- **Encryption**: Multiple layers of encryption protect data
- **Decentralization**: No central authority controls the network
- **Traffic analysis resistance**: Difficult to analyze communication patterns
- **Hidden services**: Can provide anonymous server hosting

### Vulnerabilities:
- **Traffic correlation attacks**: Matching request/response patterns across entry/exit points
- **Timing analysis**: Correlating timestamps of requests and responses
- **Exit node monitoring**: Exit nodes can see unencrypted traffic to destination
- **Global passive adversary**: Monitoring all network traffic can break anonymity

### Implementation Considerations:
- **Circuit construction**: Building paths through multiple relay nodes
- **Node selection**: Choosing diverse, trustworthy relay nodes
- **Performance trade-offs**: Anonymity vs. speed and latency
- **Directory services**: Discovering available relay nodes


## Distributed Hash Tables (DHT) and Kademlia

Source: https://www.geeksforgeeks.org/distributed-hash-tables-with-kademlia/

### Distributed Hash Tables (DHT):
DHTs are decentralized distributed systems that provide key-value storage across a network of participating nodes without centralized coordination.

**Key Characteristics:**
- **Decentralization**: Each node responsible for storing portion of data based on consistent hashing
- **Key-Value Storage**: Data items associated with unique keys, hashed to determine responsible node
- **Routing**: Nodes maintain routing tables for efficient message routing to appropriate nodes
- **Scalability**: Efficiently scales with number of nodes and data amount
- **Consistency**: Provides eventual consistency guarantees across network

### Kademlia Protocol:
Kademlia is a widely-used DHT algorithm for peer-to-peer networks, highly scalable and fault-tolerant.

**Core Components:**
- **Node ID and Key Space**: 160-bit keys generated using hash functions like SHA-1
- **Routing Table**: K-bucket structure storing contacts to other nodes grouped by key distance
- **Peer Discovery**: Nodes join network by contacting bootstrap nodes and building routing tables
- **Store and Retrieve**: Nodes store data items and retrieve them through network queries
- **Iterative Lookup**: Continuous queries to nodes near target key, updating routing tables

**Implementation Steps:**
1. **Node ID Generation**: Generate unique node ID from IP address or identifier
2. **Routing Table Initialization**: Initialize K-bucket structure for contact information
3. **Network Joining**: Contact bootstrap nodes to acquire routing table and announce presence
4. **Data Storage**: Hash data key, find K nearest neighbors, replicate data for redundancy
5. **Data Retrieval**: Use iterative lookup process to find data or confirm unavailability

**Real-World Applications:**
- **Peer-to-Peer File Sharing**: BitTorrent uses DHT for decentralized file tracking
- **Decentralized Storage**: IPFS uses DHT for content addressing and retrieval
- **Blockchain Networks**: Some blockchains use DHT for peer discovery and organization
- **Content Delivery Networks**: DHT enables efficient geographical content caching
- **Decentralized Messaging**: Secure messaging platforms use DHT for peer discovery
- **IoT Networks**: DHT organizes data storage and retrieval in IoT environments

**Advantages:**
- **Fault Tolerance**: Handles node failures and network partitions gracefully
- **Scalability**: Efficiently handles large numbers of nodes and data
- **Decentralization**: No single point of failure or control
- **Efficient Lookup**: Logarithmic lookup time complexity
- **Load Distribution**: Even distribution of data and queries across nodes

