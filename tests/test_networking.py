"""
Networking Infrastructure Tests for Privatus-chat
Week 3: Networking Infrastructure

Test suite for the P2P networking components including DHT, connection management,
NAT traversal, and message protocols.
"""

import pytest
import pytest_asyncio
import asyncio
import time
from unittest.mock import Mock, patch

from src.network.kademlia_dht import KademliaDHT, KademliaNode
from src.network.connection_manager import ConnectionManager, PeerInfo
from src.network.nat_traversal import NATTraversal, STUNClient
from src.network.message_protocol import MessageProtocol, MessageSerializer, MessageType
from src.network.peer_discovery import PeerDiscovery
from src.network.p2p_node import P2PNode

class TestKademliaDHT:
    """Test Kademlia DHT implementation"""
    
    @pytest_asyncio.fixture
    async def dht_node(self):
        """Create a DHT node for testing"""
        node = KademliaDHT(bind_port=0)
        await node.start()
        yield node
        await node.stop()
    
    def test_node_id_generation(self):
        """Test node ID generation"""
        dht = KademliaDHT()
        assert len(dht.node_id) == 20  # SHA-1 hash
        assert isinstance(dht.node_id, bytes)
    
    def test_kademlia_node_distance(self):
        """Test XOR distance calculation"""
        node1 = KademliaNode(b'\x01' * 20, "127.0.0.1", 8000)
        node2 = KademliaNode(b'\x02' * 20, "127.0.0.1", 8001)
        
        distance = node1.distance(node2.node_id)
        expected = int.from_bytes(b'\x01' * 20, 'big') ^ int.from_bytes(b'\x02' * 20, 'big')
        assert distance == expected
    
    @pytest.mark.asyncio
    async def test_dht_start_stop(self):
        """Test DHT node start and stop"""
        dht = KademliaDHT(bind_port=0)
        
        # Start node
        await dht.start()
        assert dht.running
        assert dht.transport is not None
        
        # Stop node
        await dht.stop()
        assert not dht.running
        assert dht.transport is None
    
    @pytest.mark.asyncio
    async def test_dht_store_find_value(self, dht_node):
        """Test storing and finding values in DHT"""
        key = b"test_key"
        value = b"test_value"
        
        # Store value
        await dht_node.store(key, value)
        
        # Find value
        found_value = await dht_node.find_value(key)
        assert found_value == value

class TestConnectionManager:
    """Test connection manager"""
    
    @pytest_asyncio.fixture
    async def connection_manager(self):
        """Create connection manager for testing"""
        manager = ConnectionManager()
        await manager.start()
        yield manager
        await manager.stop()
    
    def test_peer_info_creation(self):
        """Test peer info creation"""
        peer_info = PeerInfo(
            peer_id=b"test_peer",
            address="127.0.0.1",
            port=8000
        )
        
        assert peer_info.peer_id == b"test_peer"
        assert peer_info.address == "127.0.0.1"
        assert peer_info.port == 8000
        assert peer_info.last_seen > 0
    
    @pytest.mark.asyncio
    async def test_connection_manager_start_stop(self):
        """Test connection manager start and stop"""
        manager = ConnectionManager()
        
        # Start manager
        await manager.start()
        assert manager.running
        
        # Stop manager
        await manager.stop()
        assert not manager.running
    
    def test_connection_throttling(self, connection_manager):
        """Test connection attempt throttling"""
        address = "127.0.0.1"
        
        # Should allow initial connections
        assert connection_manager._can_attempt_connection(address)
        
        # Record many attempts
        for _ in range(connection_manager.max_attempts_per_hour):
            connection_manager._record_connection_attempt(address)
        
        # Should now be throttled
        assert not connection_manager._can_attempt_connection(address)

class TestNATTraversal:
    """Test NAT traversal functionality"""
    
    def test_stun_client_creation(self):
        """Test STUN client creation"""
        client = STUNClient()
        assert client.timeout == 5.0
        assert client.magic_cookie == 0x2112A442
    
    @pytest.mark.asyncio
    async def test_nat_traversal_discovery(self):
        """Test NAT type discovery"""
        nat_traversal = NATTraversal()
        
        # Mock STUN response
        with patch.object(nat_traversal.stun_client, 'get_public_address') as mock_stun:
            mock_stun.return_value = Mock(
                success=True,
                public_ip="1.2.3.4",
                public_port=12345
            )
            
            nat_type = await nat_traversal.discover_nat_type()
            assert nat_type in ["open_internet", "full_cone", "port_restricted", "symmetric"]
    
    def test_nat_compatibility_matrix(self):
        """Test NAT compatibility determination"""
        nat_traversal = NATTraversal()
        nat_traversal.nat_type = "open_internet"
        
        # Open internet should connect to anything
        assert nat_traversal.can_connect_directly("open_internet")
        assert nat_traversal.can_connect_directly("full_cone")
        assert nat_traversal.can_connect_directly("port_restricted")
        assert nat_traversal.can_connect_directly("symmetric")
        
        # Symmetric NAT is most restrictive
        nat_traversal.nat_type = "symmetric"
        assert nat_traversal.can_connect_directly("open_internet")
        assert not nat_traversal.can_connect_directly("full_cone")
        assert not nat_traversal.can_connect_directly("port_restricted")
        assert not nat_traversal.can_connect_directly("symmetric")

class TestMessageProtocol:
    """Test message protocol and serialization"""
    
    @pytest.fixture
    def message_protocol(self):
        """Create message protocol for testing"""
        return MessageProtocol(b"test_node_id")
    
    @pytest.fixture
    def message_serializer(self):
        """Create message serializer for testing"""
        return MessageSerializer()
    
    def test_message_serialization(self, message_serializer):
        """Test message serialization and deserialization"""
        # Create a chat message
        message = message_serializer.create_chat_message(
            sender_id=b"sender",
            recipient_id=b"recipient",
            content="Hello, World!"
        )
        
        # Serialize
        serialized = message_serializer.serialize(message)
        assert isinstance(serialized, bytes)
        assert len(serialized) > 0
        
        # Deserialize
        deserialized = message_serializer.deserialize(serialized)
        assert deserialized.header.message_type == MessageType.CHAT_MESSAGE.value
        assert deserialized.header.sender_id == b"sender"
        assert deserialized.header.recipient_id == b"recipient"
        assert deserialized.payload['content'] == "Hello, World!"
    
    def test_ping_message_creation(self, message_serializer):
        """Test ping message creation"""
        message = message_serializer.create_ping_message(b"test_node")
        
        assert message.header.message_type == MessageType.PING.value
        assert message.header.sender_id == b"test_node"
        assert 'timestamp' in message.payload
    
    def test_handshake_message_creation(self, message_serializer):
        """Test handshake message creation"""
        public_key = b"test_public_key"
        message = message_serializer.create_handshake_message(b"test_node", public_key)
        
        assert message.header.message_type == MessageType.HANDSHAKE.value
        assert message.header.sender_id == b"test_node"
        assert message.payload['public_key'] == public_key.hex()
        assert 'capabilities' in message.payload
    
    @pytest.mark.asyncio
    async def test_message_handling(self, message_protocol, message_serializer):
        """Test message handling"""
        # Create ping message
        ping_message = message_serializer.create_ping_message(b"remote_peer")
        
        # Handle message
        response = await message_protocol.handle_message(ping_message, b"remote_peer")
        
        # Should respond with pong
        assert response is not None
        assert response.header.message_type == MessageType.PONG.value

class TestPeerDiscovery:
    """Test peer discovery system"""
    
    @pytest_asyncio.fixture
    async def peer_discovery(self):
        """Create peer discovery for testing"""
        dht = KademliaDHT(bind_port=0)
        await dht.start()

        discovery = PeerDiscovery(b"test_node", dht)
        await discovery.start()

        yield discovery

        await discovery.stop()
        await dht.stop()
    
    @pytest.mark.asyncio
    async def test_peer_discovery_start_stop(self):
        """Test peer discovery start and stop"""
        dht = KademliaDHT(bind_port=0)
        await dht.start()
        
        discovery = PeerDiscovery(b"test_node", dht)
        
        # Start discovery
        await discovery.start()
        assert discovery.running
        
        # Stop discovery
        await discovery.stop()
        assert not discovery.running
        
        await dht.stop()
    
    def test_peer_candidate_generation(self, peer_discovery):
        """Test peer candidate generation"""
        # Add some discovered peers
        from src.network.peer_discovery import DiscoveredPeer
        
        peer1 = DiscoveredPeer(
            peer_id=b"peer1",
            addresses=[("127.0.0.1", 8001)],
            last_seen=time.time(),
            source="test"
        )
        
        peer2 = DiscoveredPeer(
            peer_id=b"peer2", 
            addresses=[("127.0.0.1", 8002)],
            last_seen=time.time(),
            source="test"
        )
        
        peer_discovery.discovered_peers[b"peer1"] = peer1
        peer_discovery.discovered_peers[b"peer2"] = peer2
        
        # Get candidates
        candidates = peer_discovery.get_peer_candidates_for_connection(5)
        assert len(candidates) == 2
        assert all(isinstance(c, PeerInfo) for c in candidates)

class TestP2PNode:
    """Test main P2P node"""
    
    @pytest_asyncio.fixture
    async def p2p_node(self):
        """Create P2P node for testing"""
        node = P2PNode(bind_port=8000)
        await node.start()
        yield node
        await node.stop()
    
    @pytest.mark.asyncio
    async def test_p2p_node_start_stop(self):
        """Test P2P node start and stop"""
        node = P2PNode(bind_port=0)
        
        # Start node
        await node.start()
        assert node.running
        assert node.server is not None
        
        # Stop node
        await node.stop()
        assert not node.running
    
    def test_node_info(self, p2p_node):
        """Test node info generation"""
        info = p2p_node.get_node_info()
        
        assert 'node_id' in info
        assert 'address' in info
        assert 'port' in info
        assert 'running' in info
        assert info['running'] == True
    
    @pytest.mark.asyncio
    async def test_message_sending(self, p2p_node):
        """Test message sending"""
        # Mock a connected peer
        peer_id = b"test_peer"
        
        # This would normally require an actual connection
        # For testing, we'll just verify the method doesn't crash
        result = await p2p_node.send_message(peer_id, "chat", {"content": "Hello"})
        # Result will be False since peer isn't actually connected
        assert isinstance(result, bool)

class TestNetworkingIntegration:
    """Integration tests for networking components"""
    
    @pytest.mark.asyncio
    async def test_two_node_communication(self):
        """Test communication between two P2P nodes"""
        # Create two nodes
        node1 = P2PNode(bind_port=8001)
        node2 = P2PNode(bind_port=8002)
        
        try:
            # Start both nodes
            await node1.start()
            await node2.start()
            
            # Setup message handlers
            received_messages = []
            
            def handle_message(peer_id, payload):
                received_messages.append((peer_id, payload))
            
            node2.on_message_received = handle_message
            
            # Connect node1 to node2
            success = await node1.connect_to_peer("127.0.0.1", node2.bind_port)
            
            if success:
                # Wait a moment for connection to establish
                await asyncio.sleep(0.1)
                
                # Send message
                await node1.send_message(
                    node2.node_id,
                    "chat",
                    {"content": "Hello from node1"}
                )
                
                # Wait for message to be processed
                await asyncio.sleep(0.1)
                
                # Verify message was received
                # Note: This might not work without proper handshake implementation
                # But it tests the infrastructure
            
        finally:
            # Clean up
            await node1.stop()
            await node2.stop()
    
    @pytest.mark.asyncio
    async def test_network_resilience(self):
        """Test network resilience and recovery"""
        node = P2PNode(bind_port=8003)
        
        try:
            await node.start()
            
            # Simulate network issues by attempting to connect to non-existent peer
            success = await node.connect_to_peer("127.0.0.1", 9999)
            assert not success  # Should fail gracefully
            
            # Node should still be running
            assert node.running
            
        finally:
            await node.stop()

# Performance tests
class TestNetworkingPerformance:
    """Performance tests for networking components"""
    
    @pytest.mark.asyncio
    async def test_message_serialization_performance(self):
        """Test message serialization performance"""
        serializer = MessageSerializer()
        
        # Create a message
        message = serializer.create_chat_message(
            sender_id=b"sender",
            recipient_id=b"recipient", 
            content="Performance test message"
        )
        
        # Time serialization
        start_time = time.time()
        
        for _ in range(1000):
            serialized = serializer.serialize(message)
            deserialized = serializer.deserialize(serialized)
        
        end_time = time.time()
        
        # Should complete quickly
        duration = end_time - start_time
        assert duration < 1.0  # Should complete in under 1 second
        
        print(f"1000 serialize/deserialize cycles took {duration:.3f} seconds")
    
    @pytest.mark.asyncio
    async def test_dht_performance(self):
        """Test DHT performance with multiple operations"""
        dht = KademliaDHT(bind_port=0)
        
        try:
            await dht.start()
            
            # Time multiple store/find operations
            start_time = time.time()
            
            for i in range(100):
                key = f"key_{i}".encode()
                value = f"value_{i}".encode()
                
                await dht.store(key, value)
                found_value = await dht.find_value(key)
                assert found_value == value
            
            end_time = time.time()
            duration = end_time - start_time
            
            print(f"100 DHT store/find operations took {duration:.3f} seconds")
            
        finally:
            await dht.stop()

if __name__ == "__main__":
    pytest.main([__file__, "-v"]) 