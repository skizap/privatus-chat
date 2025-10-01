# Kademlia DHT and Peer Discovery System

This document describes Privatus-chat's Kademlia Distributed Hash Table (DHT) implementation and peer discovery mechanisms, providing decentralized peer-to-peer networking capabilities.

## Overview

Privatus-chat implements a robust Kademlia DHT for decentralized peer discovery, routing, and data storage. The system enables peers to find each other without centralized servers while maintaining privacy and security.

## Key Features

### Decentralized Peer Discovery
- **Autonomous operation**: No central authority required
- **Self-organizing network**: Automatic peer relationship management
- **Scalable routing**: Efficient message routing in large networks
- **Fault tolerance**: Network continues operating despite node failures

### Kademlia Protocol Implementation
- **XOR-based routing**: Efficient distance-based peer selection
- **K-bucket management**: Optimal peer storage and retrieval
- **Iterative lookups**: Robust multi-hop peer discovery
- **Parallel queries**: Concurrent lookup optimization

### Privacy-Preserving Design
- **Anonymous node IDs**: Cryptographically generated identifiers
- **Metadata protection**: No cleartext peer information exchange
- **Traffic obfuscation**: Resistance to network analysis
- **Sybil attack resistance**: Protection against malicious peers

### Advanced DHT Operations
- **Data storage and retrieval**: Distributed key-value storage
- **Cache management**: Intelligent data caching strategies
- **Replication strategies**: Data redundancy for reliability
- **Consistency management**: Eventual consistency guarantees

## Architecture

### Node Identity and Addressing
- **160-bit node IDs**: SHA-1 hash-based unique identifiers
- **UDP transport**: Efficient connectionless communication
- **Port configuration**: Configurable network port allocation
- **Network binding**: Flexible address and interface binding

### K-Bucket Structure
```
Bucket 0: Distance 2^0 (1 node)
Bucket 1: Distance 2^1 (2 nodes)
...
Bucket 159: Distance 2^159 (up to 20 nodes)
```

### Routing Table Management
- **Automatic population**: Self-organizing routing table
- **Bucket splitting**: Dynamic bucket management
- **Node refresh**: Periodic peer status updates
- **Replacement cache**: Backup nodes for bucket overflow

## Usage Guide

### Starting DHT Node

#### Basic Node Initialization
1. **Generate node ID**: Cryptographically secure unique identifier
2. **Configure network settings**: Bind address and port
3. **Set DHT parameters**: Bucket size, concurrency, timeouts
4. **Start UDP transport**: Initialize network communication
5. **Bootstrap process**: Connect to initial seed nodes

#### Bootstrap Configuration
```python
# Example bootstrap configuration
bootstrap_nodes = [
    ("dht1.privatus-chat.org", 6881),
    ("dht2.privatus-chat.org", 6881),
    ("bootstrap1.privatus-chat.net", 6881)
]

dht = KademliaDHT(node_id=my_node_id, bind_port=6881)
await dht.start(bootstrap_nodes)
```

### Peer Discovery Operations

#### Finding Peers
1. **Target ID calculation**: Determine search target
2. **Alpha parallel queries**: Concurrent peer queries (α=3)
3. **Iterative deepening**: Progressive peer discovery
4. **Result collection**: Gather closest peers to target

#### Peer Lookup Process
```
Start → Query α closest nodes → Analyze responses →
Collect new nodes → Repeat with closest nodes → Converge on target
```

#### Node Announcement
- **Periodic broadcasting**: Announce presence to network
- **Neighbor updates**: Inform nearby nodes of status
- **Routing table maintenance**: Keep peer information current
- **Liveness checking**: Verify peer availability

## DHT Operations

### Data Storage
- **Key-value storage**: Distributed data storage across nodes
- **Replication factor**: Configurable data redundancy
- **Expiration times**: Automatic data cleanup
- **Storage constraints**: Respect node storage limits

### Data Retrieval
- **Lookup algorithms**: Efficient key-based data retrieval
- **Cache strategies**: Intelligent result caching
- **Consistency models**: Eventual consistency guarantees
- **Error handling**: Robust failure recovery

### Advanced DHT Features

#### Caching Strategies
- **Local caching**: Recently accessed data storage
- **Neighbor caching**: Peer routing table optimization
- **Query result caching**: Lookup result preservation
- **Cache invalidation**: Automatic stale data removal

#### Load Balancing
- **Storage distribution**: Even data distribution across nodes
- **Query load balancing**: Distribute lookup requests
- **Hotspot mitigation**: Prevent overloaded nodes
- **Adaptive algorithms**: Dynamic load adjustment

## Configuration

### DHT Settings
Access via **Settings → Network → DHT**:

- **Node ID**: Unique 160-bit identifier (auto-generated)
- **Bind address**: Network interface for DHT communication
- **Bind port**: UDP port for DHT traffic (default: 6881)
- **Bucket size (k)**: Maximum nodes per bucket (default: 20)
- **Concurrency (α)**: Parallel queries per lookup (default: 3)

### Bootstrap Configuration
- **Bootstrap nodes**: Initial seed nodes for network entry
- **Bootstrap timeout**: Timeout for initial peer discovery
- **Retry attempts**: Number of bootstrap retry attempts
- **Network diversity**: Geographic bootstrap node distribution

### Performance Settings
- **Query timeout**: Timeout for individual DHT queries
- **Refresh interval**: Routing table refresh frequency
- **Replication factor**: Data replication level
- **Cache duration**: Result caching time limits

## Security Features

### Sybil Attack Protection
- **Node ID validation**: Cryptographic node ID generation
- **Routing table constraints**: Limited malicious node impact
- **Reputation tracking**: Node behavior monitoring
- **Challenge-response**: Peer authentication mechanisms

### Eclipse Attack Resistance
- **Bucket management**: Secure k-bucket operations
- **Neighbor verification**: Routing table integrity checks
- **Diversity requirements**: Geographic and network diversity
- **Redundancy**: Multiple paths for critical operations

### Privacy Protection
- **Anonymous communication**: No cleartext peer information
- **Traffic analysis resistance**: Query pattern obfuscation
- **Metadata minimization**: Minimal data exposure
- **Correlation resistance**: Prevent peer relationship tracking

## Advanced Features

### Geographic Routing
- **Location awareness**: Geographic peer selection
- **Latency optimization**: Prefer closer peers when possible
- **Jurisdiction avoidance**: Avoid specific geographic regions
- **Network topology**: Topology-aware peer selection

### Quality of Service
- **Performance monitoring**: DHT operation performance tracking
- **Adaptive timeouts**: Dynamic timeout adjustment
- **Error recovery**: Robust failure handling
- **Load shedding**: Overload protection mechanisms

### Network Maintenance
- **Routing table refresh**: Periodic peer status updates
- **Failed node removal**: Automatic cleanup of unreachable peers
- **Network healing**: Self-repairing network topology
- **Statistics collection**: Comprehensive network metrics

## Troubleshooting

### Common Issues

#### Cannot Bootstrap to Network
**Possible causes:**
- Network connectivity issues
- Firewall blocking UDP traffic
- Bootstrap nodes unavailable
- Incorrect port configuration

**Solutions:**
- Check internet connectivity
- Verify UDP port accessibility
- Update bootstrap node list
- Check firewall settings

#### Poor Lookup Performance
**Possible causes:**
- Insufficient network diversity
- High latency connections
- Overloaded bootstrap nodes
- Network congestion

**Solutions:**
- Increase bootstrap node count
- Check network conditions
- Monitor DHT statistics
- Adjust timeout settings

#### Routing Table Issues
**Possible causes:**
- Network partitioning
- Node churn (frequent joins/leaves)
- Malicious node interference
- Configuration problems

**Solutions:**
- Increase refresh frequency
- Monitor node stability
- Check network topology
- Verify configuration settings

## Performance Monitoring

### DHT Metrics
- **Routing table size**: Number of known peers
- **Lookup success rate**: Percentage of successful lookups
- **Average lookup time**: Mean time for peer discovery
- **Network latency**: Round-trip time to peers

### Network Health Indicators
- **Node availability**: Percentage of reachable peers
- **Query throughput**: Queries processed per second
- **Cache hit rate**: Effectiveness of caching strategies
- **Error rates**: Frequency of failed operations

## Best Practices

### Network Configuration
1. **Use multiple bootstrap nodes** for redundancy
2. **Configure appropriate timeouts** for your network conditions
3. **Monitor DHT statistics** for performance optimization
4. **Keep software updated** for latest improvements

### Security Considerations
1. **Use cryptographically secure node IDs** (default behavior)
2. **Monitor for suspicious network activity**
3. **Configure appropriate geographic restrictions** if needed
4. **Regularly update bootstrap node information**

### Performance Optimization
1. **Tune concurrency parameters** based on network size
2. **Monitor and adjust cache settings** for optimal performance
3. **Use appropriate replication factors** for data durability
4. **Balance lookup frequency** with network load

## Technical Details

### Kademlia Protocol Implementation
- **Distance calculation**: XOR-based node distance computation
- **Bucket indexing**: Logarithmic bucket distribution
- **Lookup termination**: Convergence criteria for lookups
- **Node selection**: Closest node selection algorithms

### Message Types
- **PING**: Node liveness verification
- **FIND_NODE**: Peer discovery requests
- **FIND_VALUE**: Data retrieval requests
- **STORE**: Data storage requests

### Concurrency Control
- **Alpha parameter**: Controls parallel query degree
- **Rate limiting**: Prevents query flooding
- **Timeout management**: Adaptive timeout handling
- **Retry logic**: Intelligent retry mechanisms

## API Reference

### Kademlia DHT Manager
```python
class KademliaDHT:
    async def start(self, bootstrap_nodes: List[Tuple[str, int]] = None):
        """Start DHT node and bootstrap to network."""

    async def stop(self):
        """Stop DHT node and cleanup resources."""

    async def find_node(self, target_id: bytes, address: str, port: int) -> List[KademliaNode]:
        """Find nodes closest to target ID."""

    async def store(self, key: bytes, value: bytes):
        """Store key-value pair in DHT."""

    async def find_value(self, key: bytes) -> Optional[bytes]:
        """Retrieve value for key from DHT."""

    def get_routing_table_info(self) -> Dict[str, Any]:
        """Get comprehensive routing table statistics."""
```

### DHT Events
```python
# Register for DHT events
def on_node_discovered(node: KademliaNode):
    """Called when new peer is discovered."""
    pass

def on_lookup_completed(target_id: bytes, results: List[KademliaNode]):
    """Called when peer lookup completes."""
    pass

def on_data_stored(key: bytes, success: bool):
    """Called when data storage operation completes."""
    pass

def on_routing_table_updated():
    """Called when routing table is modified."""
    pass
```

## Support

For DHT and peer discovery issues:
- Check the [Troubleshooting](#troubleshooting) section
- Review [FAQ](faq.md) for common questions
- Search [GitHub Issues](https://github.com/privatus-chat/issues)
- Ask in [Community Forum](https://forum.privatus-chat.org)

---

*Last updated: January 2025*
*Version: 1.0.0*