#!/usr/bin/env python3
"""
Week 3: Networking Infrastructure Demo
Privatus-chat Development Plan

This demo showcases the networking infrastructure implemented in Week 3:
- Kademlia DHT for peer discovery
- P2P connection management
- NAT traversal capabilities
- Message protocol and serialization
- Peer discovery system
"""

import asyncio
import logging
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from network.kademlia_dht import KademliaDHT, KademliaNode
from network.connection_manager import ConnectionManager, PeerInfo
from network.nat_traversal import NATTraversal
from network.message_protocol import MessageSerializer, MessageType
from network.peer_discovery import PeerDiscovery
from network.p2p_node import P2PNode

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

async def demo_kademlia_dht():
    """Demonstrate Kademlia DHT functionality"""
    print("\n=== Kademlia DHT Demo ===")
    
    # Create DHT node
    dht = KademliaDHT(bind_port=0)
    
    try:
        # Start DHT
        await dht.start()
        print(f"DHT started on port {dht.bind_port}")
        print(f"Node ID: {dht.node_id.hex()}")
        
        # Store some test data
        test_key = b"test_key_123"
        test_value = b"Hello, DHT World!"
        
        print(f"Storing key: {test_key.hex()}")
        await dht.store(test_key, test_value)
        
        # Retrieve the data
        found_value = await dht.find_value(test_key)
        if found_value:
            print(f"Retrieved value: {found_value.decode()}")
        else:
            print("Value not found in DHT")
        
        print("✓ DHT operations completed successfully")
        
    except Exception as e:
        print(f"✗ DHT demo failed: {e}")
    finally:
        await dht.stop()
        print("DHT stopped")

async def demo_nat_traversal():
    """Demonstrate NAT traversal capabilities"""
    print("\n=== NAT Traversal Demo ===")
    
    nat_traversal = NATTraversal()
    
    try:
        # Discover NAT type
        print("Discovering NAT type...")
        nat_type = await nat_traversal.discover_nat_type()
        print(f"NAT Type: {nat_type}")
        
        if nat_traversal.public_address:
            print(f"Public Address: {nat_traversal.public_address.public_ip}:{nat_traversal.public_address.public_port}")
        else:
            print("Could not determine public address")
        
        # Get connection candidates
        candidates = await nat_traversal.get_connection_candidates(8080)
        print(f"Connection candidates: {candidates}")
        
        print("✓ NAT traversal discovery completed successfully")
        
    except Exception as e:
        print(f"✗ NAT traversal demo failed: {e}")

async def demo_message_protocol():
    """Demonstrate message protocol and serialization"""
    print("\n=== Message Protocol Demo ===")
    
    try:
        serializer = MessageSerializer()
        
        # Create different types of messages
        messages = [
            serializer.create_handshake_message(b"node1", b"public_key_data"),
            serializer.create_ping_message(b"node1"),
            serializer.create_chat_message(b"sender", b"recipient", "Hello, P2P World!"),
            serializer.create_ack_message(b"node1", "message_123"),
        ]
        
        for i, message in enumerate(messages):
            print(f"\nMessage {i+1}: {message.header.message_type}")
            
            # Serialize
            serialized = serializer.serialize(message)
            print(f"Serialized size: {len(serialized)} bytes")
            
            # Deserialize
            deserialized = serializer.deserialize(serialized)
            print(f"Deserialized type: {deserialized.header.message_type}")
            
            # Verify integrity
            assert message.header.message_id == deserialized.header.message_id
            assert message.header.message_type == deserialized.header.message_type
        
        print("✓ Message protocol operations completed successfully")
        
    except Exception as e:
        print(f"✗ Message protocol demo failed: {e}")

async def demo_connection_manager():
    """Demonstrate connection management"""
    print("\n=== Connection Manager Demo ===")
    
    connection_manager = ConnectionManager()
    
    try:
        # Start connection manager
        await connection_manager.start()
        print("Connection manager started")
        
        # Create test peer info
        peer_info = PeerInfo(
            peer_id=b"test_peer_123",
            address="127.0.0.1",
            port=8080
        )
        
        print(f"Created peer info: {peer_info.peer_id.hex()}")
        
        # Test connection throttling
        can_connect = connection_manager._can_attempt_connection("127.0.0.1")
        print(f"Can attempt connection: {can_connect}")
        
        # Record connection attempt
        connection_manager._record_connection_attempt("127.0.0.1")
        print("Recorded connection attempt")
        
        # Get statistics
        stats = connection_manager.get_connection_stats()
        print(f"Connection stats: {stats}")
        
        print("✓ Connection manager operations completed successfully")
        
    except Exception as e:
        print(f"✗ Connection manager demo failed: {e}")
    finally:
        await connection_manager.stop()
        print("Connection manager stopped")

async def demo_peer_discovery():
    """Demonstrate peer discovery system"""
    print("\n=== Peer Discovery Demo ===")
    
    # Create DHT for peer discovery
    dht = KademliaDHT(bind_port=0)
    
    try:
        await dht.start()
        
        # Create peer discovery
        peer_discovery = PeerDiscovery(b"discovery_node", dht)
        await peer_discovery.start()
        
        print("Peer discovery started")
        print(f"Max peers: {peer_discovery.max_peers}")
        
        # Add some test peers manually
        from network.peer_discovery import DiscoveredPeer
        import time
        
        test_peers = [
            DiscoveredPeer(b"peer1", [("127.0.0.1", 8001)], time.time(), "test"),
            DiscoveredPeer(b"peer2", [("127.0.0.1", 8002)], time.time(), "test"),
            DiscoveredPeer(b"peer3", [("192.168.1.100", 8003)], time.time(), "dht"),
        ]
        
        for peer in test_peers:
            await peer_discovery._add_discovered_peer(peer)
            print(f"Added peer: {peer.peer_id.hex()} from {peer.source}")
        
        # Get discovered peers
        discovered = peer_discovery.get_discovered_peers()
        print(f"Total discovered peers: {len(discovered)}")
        
        # Get connection candidates
        candidates = peer_discovery.get_peer_candidates_for_connection(5)
        print(f"Connection candidates: {len(candidates)}")
        
        # Get statistics
        stats = peer_discovery.get_discovery_stats()
        print(f"Discovery stats: {stats}")
        
        print("✓ Peer discovery operations completed successfully")
        
    except Exception as e:
        print(f"✗ Peer discovery demo failed: {e}")
    finally:
        await peer_discovery.stop()
        await dht.stop()
        print("Peer discovery stopped")

async def demo_p2p_node():
    """Demonstrate complete P2P node functionality"""
    print("\n=== P2P Node Demo ===")
    
    # Create P2P node
    node = P2PNode(bind_port=0)
    
    try:
        # Start node
        await node.start()
        print("P2P node started")
        
        # Get node info
        info = node.get_node_info()
        print(f"Node info: {info}")
        
        # Test message creation
        success = await node.send_message(
            b"fake_peer",
            "chat",
            {"content": "Hello from P2P node!"}
        )
        print(f"Message send result: {success}")  # Will be False since peer doesn't exist
        
        # Get peer lists
        connected = node.get_connected_peers()
        discovered = node.get_discovered_peers()
        
        print(f"Connected peers: {len(connected)}")
        print(f"Discovered peers: {len(discovered)}")
        
        print("✓ P2P node operations completed successfully")
        
    except Exception as e:
        print(f"✗ P2P node demo failed: {e}")
    finally:
        await node.stop()
        print("P2P node stopped")

async def main():
    """Run all networking demos"""
    print("Privatus-chat Week 3: Networking Infrastructure Demo")
    print("=" * 50)
    
    # Run individual component demos
    await demo_kademlia_dht()
    await demo_nat_traversal()
    await demo_message_protocol()
    await demo_connection_manager()
    await demo_peer_discovery()
    await demo_p2p_node()
    
    print("\n" + "=" * 50)
    print("Week 3 Networking Infrastructure Demo Complete!")
    print("\nKey achievements:")
    print("✓ Kademlia DHT for decentralized peer discovery")
    print("✓ Connection management with throttling and cleanup")
    print("✓ NAT traversal with STUN support")
    print("✓ Comprehensive message protocol and serialization")
    print("✓ Multi-strategy peer discovery system")
    print("✓ Integrated P2P node architecture")
    print("\nNext: Week 4 - Anonymous messaging and onion routing")

if __name__ == "__main__":
    asyncio.run(main()) 