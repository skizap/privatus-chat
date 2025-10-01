# Onion Routing and Anonymity System

This document details Privatus-chat's advanced onion routing and anonymity features, providing comprehensive protection against network surveillance, traffic analysis, and identity correlation.

## Overview

Privatus-chat implements a sophisticated onion routing system inspired by Tor but optimized for real-time communication. The anonymity system provides multiple layers of protection against various attack vectors including traffic analysis, timing attacks, and correlation attacks.

## Key Features

### Multi-Hop Circuit Construction
- **Configurable hop counts**: 2-6 hops based on threat level
- **Circuit diversity**: Intelligent relay selection algorithms
- **Circuit lifecycle management**: Automatic circuit creation and teardown
- **Load balancing**: Even distribution across available relays

### Advanced Encryption Layers
- **Layered encryption**: Unique keys for each circuit hop
- **Perfect forward secrecy**: Ephemeral keys for each circuit
- **Cryptographic challenges**: Mutual authentication between hops
- **Circuit integrity verification**: End-to-end circuit validation

### Traffic Analysis Resistance
- **Message padding**: Fixed-size message padding
- **Timing obfuscation**: Randomized message timing
- **Circuit rotation**: Optional mid-conversation circuit changes
- **Dummy traffic**: Background noise generation

### Relay Network Architecture
- **Diverse relay types**: Entry, middle, and exit relay specialization
- **Reputation system**: Relay quality and reliability scoring
- **Geographic diversity**: Cross-jurisdictional relay placement
- **Bandwidth management**: Fair relay resource allocation

## Threat Levels and Circuit Configuration

### Low Threat Level (2 hops)
- **Use case**: Basic anonymity for everyday communication
- **Performance**: Minimal latency overhead
- **Protection**: Basic traffic analysis resistance
- **Circuit length**: Entry → Exit

### Medium Threat Level (3 hops) - Default
- **Use case**: Standard privacy protection
- **Performance**: Moderate latency increase
- **Protection**: Strong traffic analysis resistance
- **Circuit length**: Entry → Middle → Exit

### High Threat Level (4 hops)
- **Use case**: Enhanced protection for sensitive communication
- **Performance**: Higher latency overhead
- **Protection**: Advanced correlation resistance
- **Circuit length**: Entry → Middle1 → Middle2 → Exit

### Extreme Threat Level (6 hops)
- **Use case**: Maximum protection against sophisticated attacks
- **Performance**: Significant latency overhead
- **Protection**: Maximum anonymity and correlation resistance
- **Circuit length**: Entry → Middle1 → Middle2 → Middle3 → Middle4 → Exit

## Usage Guide

### Basic Anonymous Communication

#### Enabling Onion Routing
1. **Open privacy settings** in application preferences
2. **Navigate to anonymity section**
3. **Enable onion routing** (enabled by default)
4. **Choose threat level** based on your security needs
5. **Configure circuit preferences** (optional)

#### Automatic Circuit Management
- **Circuit building**: Automatic circuit construction in background
- **Circuit selection**: Intelligent circuit selection for each connection
- **Circuit monitoring**: Real-time circuit health monitoring
- **Circuit failover**: Automatic fallback to working circuits

### Advanced Anonymity Features

#### Circuit Selection Algorithms
1. **Reputation-based selection**: Prefer high-reputation relays
2. **Geographic diversity**: Avoid relays in same jurisdictions
3. **Bandwidth optimization**: Select relays with sufficient capacity
4. **Latency optimization**: Minimize circuit latency

#### Traffic Obfuscation
1. **Message padding**: All messages padded to fixed sizes
2. **Timing randomization**: Random delays between messages
3. **Dummy traffic generation**: Background noise to mask patterns
4. **Circuit rotation**: Periodic circuit changes during long conversations

## Security Architecture

### Circuit Construction Process
```
1. Relay Discovery → 2. Relay Selection → 3. Key Exchange → 4. Circuit Testing → 5. Activation
```

### Encryption Layer Architecture
```
Message → Layer 3 Encryption → Layer 2 Encryption → Layer 1 Encryption → Network
```

### Relay Authentication
- **Cryptographic challenges**: Mutual authentication between nodes
- **Challenge-response protocol**: Prevent relay impersonation
- **Circuit proof generation**: End-to-end circuit integrity verification
- **Replay attack prevention**: Timestamp-based challenge validation

### Key Management
- **Ephemeral circuit keys**: Unique keys for each circuit
- **Hop-specific encryption**: Different keys for each relay
- **Key derivation**: HKDF-based key derivation from shared secrets
- **Key rotation**: Optional mid-circuit key rotation

## Relay Network

### Relay Types and Roles

#### Entry Relays (Guard Nodes)
- **Requirements**: High uptime (24+ hours), excellent reputation
- **Function**: First hop in circuit, handles initial encryption layer
- **Selection criteria**: Long-term stability and reliability
- **Security considerations**: Protected against compromise attempts

#### Middle Relays
- **Requirements**: Good uptime (12+ hours), solid reputation
- **Function**: Intermediate hops providing additional encryption layers
- **Selection criteria**: Balance of performance and security
- **Security considerations**: Traffic analysis resistance

#### Exit Relays
- **Requirements**: Excellent uptime (24+ hours), highest reputation
- **Function**: Final hop, decrypts final layer for destination delivery
- **Selection criteria**: Maximum trustworthiness and capacity
- **Security considerations**: No traffic inspection or logging

### Relay Reputation System
- **Uptime tracking**: Continuous monitoring of relay availability
- **Performance metrics**: Bandwidth, latency, and reliability scoring
- **Security scoring**: Resistance to attacks and proper configuration
- **Community feedback**: User-reported relay quality indicators

## Configuration

### Anonymity Settings
Access via **Settings → Privacy → Anonymity**:

- **Enable onion routing**: Master switch for anonymity features
- **Threat level**: Low/Medium/High/Extreme protection levels
- **Circuit length**: Custom hop count configuration
- **Circuit rotation**: Automatic circuit change intervals
- **Dummy traffic**: Background noise generation settings

### Performance Settings
- **Latency tolerance**: Maximum acceptable latency overhead
- **Bandwidth usage**: Circuit bandwidth consumption limits
- **Circuit count**: Number of active circuits to maintain
- **Relay preferences**: Geographic and performance preferences

### Security Settings
- **Challenge frequency**: How often to verify circuit integrity
- **Key rotation interval**: Circuit key rotation frequency
- **Exit relay restrictions**: Allowed exit relay jurisdictions
- **Entry relay persistence**: Long-term entry relay usage

## Advanced Features

### Adaptive Threat Response
- **Automatic threat level adjustment**: Based on network conditions
- **Circuit quality monitoring**: Real-time circuit performance tracking
- **Attack detection**: Identification of potential correlation attacks
- **Fallback mechanisms**: Graceful degradation under attack

### Geographic Routing
- **Jurisdiction avoidance**: Avoid specific countries or regions
- **Latency optimization**: Prefer geographically closer relays
- **Diversity requirements**: Ensure relays span multiple jurisdictions
- **Legal compliance**: Respect local regulations and restrictions

### Bandwidth Management
- **Circuit prioritization**: Priority queuing for important traffic
- **Bandwidth allocation**: Fair sharing among active circuits
- **Quality of service**: Minimum bandwidth guarantees
- **Congestion control**: Adaptive bandwidth adjustment

## Troubleshooting

### Common Issues

#### High Latency
**Possible causes:**
- Too many circuit hops for threat level
- Poor relay performance or network conditions
- Insufficient relay diversity
- Circuit congestion

**Solutions:**
- Reduce threat level if acceptable
- Wait for circuit optimization
- Check relay status and diversity
- Monitor network conditions

#### Circuit Construction Failures
**Possible causes:**
- Insufficient relay pool size
- Network connectivity issues
- Relay reputation too low
- Geographic restrictions too strict

**Solutions:**
- Wait for relay discovery
- Check internet connectivity
- Adjust relay selection criteria
- Relax geographic restrictions

#### Connection Drops
**Possible causes:**
- Circuit expiration or failure
- Relay going offline
- Network instability
- Attack detection triggering fallback

**Solutions:**
- Enable automatic circuit rebuilding
- Monitor relay stability
- Check network connectivity
- Review threat detection settings

## Performance Optimization

### Latency Optimization
- **Circuit length tuning**: Balance anonymity vs. performance
- **Relay selection**: Prefer low-latency, high-bandwidth relays
- **Geographic optimization**: Choose relays closer to destination
- **Connection pooling**: Reuse circuits when possible

### Bandwidth Optimization
- **Message batching**: Combine small messages
- **Compression**: Enable message compression
- **Dummy traffic control**: Limit background noise generation
- **Circuit sharing**: Share circuits across multiple connections

## Best Practices

### Security Best Practices
1. **Use appropriate threat levels** for your security needs
2. **Enable circuit integrity verification** for high-threat scenarios
3. **Regularly update relay information** for optimal performance
4. **Monitor circuit statistics** for anomaly detection
5. **Use geographic diversity** to avoid single-jurisdiction risks

### Performance Best Practices
1. **Start with medium threat level** and adjust based on needs
2. **Monitor latency and adjust** circuit length accordingly
3. **Use circuit sharing** for multiple simultaneous connections
4. **Enable compression** for low-bandwidth connections
5. **Plan for relay downtime** with redundant circuits

### Privacy Best Practices
1. **Avoid predictable communication patterns** that could aid correlation
2. **Use consistent threat levels** to avoid behavior profiling
3. **Monitor for traffic analysis** indicators
4. **Combine with other privacy tools** for defense in depth
5. **Stay informed** about relay network health and security

## Technical Details

### Circuit Protocol
- **Circuit ID generation**: Cryptographically secure circuit identifiers
- **Hop-by-hop encryption**: Each hop decrypts only its layer
- **Circuit extension**: Dynamic addition of hops to existing circuits
- **Circuit truncation**: Graceful removal of hops from circuits

### Relay Communication
- **Cell-based protocol**: Fixed-size data cells for traffic analysis resistance
- **Flow control**: Backpressure and congestion management
- **Error handling**: Circuit failure detection and recovery
- **Authentication**: Cryptographic mutual authentication

### Cryptographic Primitives
- **X25519 key exchange**: Modern elliptic curve Diffie-Hellman
- **AES-256-GCM encryption**: Authenticated encryption for each layer
- **SHA-256 hashing**: Cryptographic hashing for integrity verification
- **HMAC-SHA256**: Message authentication for challenges

## API Reference

### Onion Routing Manager
```python
class OnionRoutingManager:
    async def build_circuit(self, destination_node_id: Optional[bytes] = None,
                           hop_count: Optional[int] = None) -> Optional[OnionCircuit]:
        """Build new onion routing circuit with specified parameters."""

    async def send_message_through_circuit(self, circuit: OnionCircuit,
                                          destination: bytes,
                                          message: Dict[str, Any]) -> bool:
        """Send message through established circuit."""

    async def build_circuit_by_threat_level(self, threat_level: str = "medium",
                                           destination_node_id: Optional[bytes] = None) -> Optional[OnionCircuit]:
        """Build circuit with hop count based on threat level."""

    def get_circuit_statistics(self) -> Dict[str, Any]:
        """Get comprehensive circuit usage statistics."""
```

### Circuit Events
```python
# Register for circuit events
def on_circuit_established(circuit: OnionCircuit):
    """Called when new circuit is successfully established."""
    pass

def on_circuit_failed(circuit_id: int, reason: str):
    """Called when circuit construction or maintenance fails."""
    pass

def on_circuit_expired(circuit: OnionCircuit):
    """Called when circuit reaches end of lifecycle."""
    pass

def on_relay_discovered(relay: OnionRelay):
    """Called when new relay is discovered and added to pool."""
    pass
```

## Support

For onion routing and anonymity issues:
- Check the [Troubleshooting](#troubleshooting) section
- Review [FAQ](faq.md) for common questions
- Search [GitHub Issues](https://github.com/privatus-chat/issues)
- Ask in [Community Forum](https://forum.privatus-chat.org)

---

*Last updated: January 2025*
*Version: 1.0.0*