"""
Kademlia DHT Implementation for Privatus-chat
Week 3: Networking Infrastructure

This module implements a Kademlia Distributed Hash Table for decentralized
peer discovery and routing in the Privatus-chat network.
"""

import asyncio
import hashlib
import random
import struct
import time
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from collections import defaultdict

@dataclass
class KademliaNode:
    """Represents a node in the Kademlia network"""
    node_id: bytes
    address: str
    port: int
    last_seen: float = 0.0
    
    def __post_init__(self):
        if self.last_seen == 0.0:
            self.last_seen = time.time()
    
    def distance(self, other_id: bytes) -> int:
        """Calculate XOR distance between this node and another node ID"""
        return int.from_bytes(self.node_id, 'big') ^ int.from_bytes(other_id, 'big')
    
    def __hash__(self):
        return hash((self.node_id, self.address, self.port))
    
    def __eq__(self, other):
        if not isinstance(other, KademliaNode):
            return False
        return (self.node_id == other.node_id and 
                self.address == other.address and 
                self.port == other.port)

class KBucket:
    """K-bucket for storing nodes in Kademlia routing table"""
    
    def __init__(self, k: int = 20):
        self.k = k
        self.nodes: List[KademliaNode] = []
        self.replacement_cache: List[KademliaNode] = []
    
    def add_node(self, node: KademliaNode) -> bool:
        """Add a node to the bucket. Returns True if added, False if bucket full"""
        # Remove node if it already exists
        self.nodes = [n for n in self.nodes if n.node_id != node.node_id]
        
        if len(self.nodes) < self.k:
            self.nodes.append(node)
            return True
        else:
            # Bucket full, add to replacement cache
            self.replacement_cache = [n for n in self.replacement_cache 
                                    if n.node_id != node.node_id]
            self.replacement_cache.append(node)
            return False
    
    def remove_node(self, node_id: bytes):
        """Remove a node from the bucket"""
        self.nodes = [n for n in self.nodes if n.node_id != node_id]
        
        # Try to replace with node from replacement cache
        if self.replacement_cache:
            replacement = self.replacement_cache.pop(0)
            self.nodes.append(replacement)
    
    def get_nodes(self) -> List[KademliaNode]:
        """Get all nodes in the bucket"""
        return self.nodes.copy()
    
    def is_full(self) -> bool:
        """Check if the bucket is full"""
        return len(self.nodes) >= self.k

class RoutingTable:
    """Kademlia routing table implementation"""
    
    def __init__(self, node_id: bytes, k: int = 20):
        self.node_id = node_id
        self.k = k
        self.buckets: Dict[int, KBucket] = {}
    
    def _get_bucket_index(self, node_id: bytes) -> int:
        """Get the bucket index for a given node ID"""
        distance = int.from_bytes(self.node_id, 'big') ^ int.from_bytes(node_id, 'big')
        if distance == 0:
            return 0
        return distance.bit_length() - 1
    
    def add_node(self, node: KademliaNode):
        """Add a node to the routing table"""
        if node.node_id == self.node_id:
            return  # Don't add ourselves
        
        bucket_index = self._get_bucket_index(node.node_id)
        
        if bucket_index not in self.buckets:
            self.buckets[bucket_index] = KBucket(self.k)
        
        self.buckets[bucket_index].add_node(node)
    
    def remove_node(self, node_id: bytes):
        """Remove a node from the routing table"""
        bucket_index = self._get_bucket_index(node_id)
        
        if bucket_index in self.buckets:
            self.buckets[bucket_index].remove_node(node_id)
    
    def find_closest_nodes(self, target_id: bytes, count: int = 20) -> List[KademliaNode]:
        """Find the closest nodes to a target ID"""
        nodes = []
        
        # Collect all nodes from all buckets
        for bucket in self.buckets.values():
            nodes.extend(bucket.get_nodes())
        
        # Sort by distance to target
        nodes.sort(key=lambda n: n.distance(target_id))
        
        return nodes[:count]
    
    def get_all_nodes(self) -> List[KademliaNode]:
        """Get all nodes in the routing table"""
        nodes = []
        for bucket in self.buckets.values():
            nodes.extend(bucket.get_nodes())
        return nodes

class KademliaDHT:
    """Kademlia DHT implementation for peer discovery"""
    
    def __init__(self, node_id: bytes = None, bind_address: str = "0.0.0.0", 
                 bind_port: int = 0, k: int = 20, alpha: int = 3):
        self.node_id = node_id or self._generate_node_id()
        self.bind_address = bind_address
        self.bind_port = bind_port
        self.k = k  # Bucket size
        self.alpha = alpha  # Concurrency parameter
        
        self.routing_table = RoutingTable(self.node_id, k)
        self.storage: Dict[bytes, bytes] = {}
        
        self.transport = None
        self.running = False
        
        # Bootstrap nodes for initial network discovery
        self.bootstrap_nodes: List[Tuple[str, int]] = []
        
        # Pending requests for RPC timeout handling
        self.pending_requests: Dict[bytes, asyncio.Future] = {}
        
    def _generate_node_id(self) -> bytes:
        """Generate a random 160-bit node ID"""
        return hashlib.sha1(str(random.random()).encode()).digest()
    
    def _generate_request_id(self) -> bytes:
        """Generate a unique request ID"""
        return hashlib.sha1(str(time.time()).encode()).digest()[:8]
    
    async def start(self, bootstrap_nodes: List[Tuple[str, int]] = None):
        """Start the DHT node"""
        if self.running:
            return
        
        # Create UDP transport
        loop = asyncio.get_event_loop()
        self.transport, protocol = await loop.create_datagram_endpoint(
            lambda: KademliaProtocol(self),
            local_addr=(self.bind_address, self.bind_port)
        )
        
        self.bind_port = self.transport.get_extra_info('sockname')[1]
        self.running = True
        
        # Bootstrap with provided nodes
        if bootstrap_nodes:
            self.bootstrap_nodes.extend(bootstrap_nodes)
        
        await self._bootstrap()
    
    async def stop(self):
        """Stop the DHT node"""
        if not self.running:
            return
        
        self.running = False
        
        if self.transport:
            self.transport.close()
            self.transport = None
        
        # Cancel pending requests
        for future in self.pending_requests.values():
            future.cancel()
        self.pending_requests.clear()
    
    async def _bootstrap(self):
        """Bootstrap the node into the network"""
        if not self.bootstrap_nodes:
            return
        
        # Try to connect to bootstrap nodes
        for address, port in self.bootstrap_nodes:
            try:
                await self.ping(address, port)
                # Find nodes close to our own ID
                await self.find_node(self.node_id, address, port)
            except Exception as e:
                print(f"Bootstrap failed for {address}:{port}: {e}")
    
    async def ping(self, address: str, port: int) -> bool:
        """Ping a node to check if it's alive"""
        try:
            request_id = self._generate_request_id()
            message = {
                'type': 'ping',
                'request_id': request_id,
                'node_id': self.node_id,
                'sender': {'address': self.bind_address, 'port': self.bind_port}
            }
            
            future = asyncio.Future()
            self.pending_requests[request_id] = future
            
            await self._send_message(message, address, port)
            
            # Wait for response with timeout
            try:
                await asyncio.wait_for(future, timeout=5.0)
                return True
            except asyncio.TimeoutError:
                return False
            finally:
                self.pending_requests.pop(request_id, None)
                
        except Exception:
            return False
    
    async def find_node(self, target_id: bytes, address: str, port: int) -> List[KademliaNode]:
        """Find nodes closest to target_id"""
        try:
            request_id = self._generate_request_id()
            message = {
                'type': 'find_node',
                'request_id': request_id,
                'node_id': self.node_id,
                'target_id': target_id,
                'sender': {'address': self.bind_address, 'port': self.bind_port}
            }
            
            future = asyncio.Future()
            self.pending_requests[request_id] = future
            
            await self._send_message(message, address, port)
            
            try:
                response = await asyncio.wait_for(future, timeout=5.0)
                nodes = []
                for node_data in response.get('nodes', []):
                    node = KademliaNode(
                        node_id=node_data['node_id'],
                        address=node_data['address'],
                        port=node_data['port']
                    )
                    nodes.append(node)
                return nodes
            except asyncio.TimeoutError:
                return []
            finally:
                self.pending_requests.pop(request_id, None)
                
        except Exception:
            return []
    
    async def store(self, key: bytes, value: bytes):
        """Store a key-value pair in the DHT"""
        # Find closest nodes to the key
        closest_nodes = self.routing_table.find_closest_nodes(key, self.k)
        
        # Store on closest nodes
        for node in closest_nodes:
            try:
                request_id = self._generate_request_id()
                message = {
                    'type': 'store',
                    'request_id': request_id,
                    'node_id': self.node_id,
                    'key': key,
                    'value': value,
                    'sender': {'address': self.bind_address, 'port': self.bind_port}
                }
                
                await self._send_message(message, node.address, node.port)
            except Exception as e:
                print(f"Failed to store on {node.address}:{node.port}: {e}")
    
    async def find_value(self, key: bytes) -> Optional[bytes]:
        """Find a value in the DHT"""
        # Check local storage first
        if key in self.storage:
            return self.storage[key]
        
        # Query closest nodes
        closest_nodes = self.routing_table.find_closest_nodes(key, self.alpha)
        
        for node in closest_nodes:
            try:
                request_id = self._generate_request_id()
                message = {
                    'type': 'find_value',
                    'request_id': request_id,
                    'node_id': self.node_id,
                    'key': key,
                    'sender': {'address': self.bind_address, 'port': self.bind_port}
                }
                
                future = asyncio.Future()
                self.pending_requests[request_id] = future
                
                await self._send_message(message, node.address, node.port)
                
                try:
                    response = await asyncio.wait_for(future, timeout=5.0)
                    if 'value' in response:
                        return response['value']
                except asyncio.TimeoutError:
                    continue
                finally:
                    self.pending_requests.pop(request_id, None)
                    
            except Exception:
                continue
        
        return None
    
    async def _send_message(self, message: dict, address: str, port: int):
        """Send a message to a node"""
        if not self.transport:
            raise RuntimeError("DHT not started")
        
        # Simple serialization (in production, use proper serialization)
        import json
        data = json.dumps(message, default=lambda x: x.hex() if isinstance(x, bytes) else x)
        self.transport.sendto(data.encode(), (address, port))
    
    def _handle_ping(self, message: dict, address: str, port: int):
        """Handle incoming ping request"""
        response = {
            'type': 'ping_response',
            'request_id': message['request_id'],
            'node_id': self.node_id
        }
        asyncio.create_task(self._send_message(response, address, port))
        
        # Add sender to routing table
        sender_node = KademliaNode(
            node_id=message['node_id'],
            address=address,
            port=port
        )
        self.routing_table.add_node(sender_node)
    
    def _handle_find_node(self, message: dict, address: str, port: int):
        """Handle incoming find_node request"""
        target_id = message['target_id']
        closest_nodes = self.routing_table.find_closest_nodes(target_id, self.k)
        
        nodes_data = []
        for node in closest_nodes:
            nodes_data.append({
                'node_id': node.node_id,
                'address': node.address,
                'port': node.port
            })
        
        response = {
            'type': 'find_node_response',
            'request_id': message['request_id'],
            'nodes': nodes_data
        }
        asyncio.create_task(self._send_message(response, address, port))
        
        # Add sender to routing table
        sender_node = KademliaNode(
            node_id=message['node_id'],
            address=address,
            port=port
        )
        self.routing_table.add_node(sender_node)
    
    def _handle_store(self, message: dict, address: str, port: int):
        """Handle incoming store request"""
        key = message['key']
        value = message['value']
        
        # Store the key-value pair
        self.storage[key] = value
        
        response = {
            'type': 'store_response',
            'request_id': message['request_id'],
            'success': True
        }
        asyncio.create_task(self._send_message(response, address, port))
    
    def _handle_find_value(self, message: dict, address: str, port: int):
        """Handle incoming find_value request"""
        key = message['key']
        
        if key in self.storage:
            response = {
                'type': 'find_value_response',
                'request_id': message['request_id'],
                'value': self.storage[key]
            }
        else:
            # Return closest nodes instead
            closest_nodes = self.routing_table.find_closest_nodes(key, self.k)
            nodes_data = []
            for node in closest_nodes:
                nodes_data.append({
                    'node_id': node.node_id,
                    'address': node.address,
                    'port': node.port
                })
            
            response = {
                'type': 'find_value_response',
                'request_id': message['request_id'],
                'nodes': nodes_data
            }
        
        asyncio.create_task(self._send_message(response, address, port))

class KademliaProtocol(asyncio.DatagramProtocol):
    """UDP protocol handler for Kademlia messages"""
    
    def __init__(self, dht: KademliaDHT):
        self.dht = dht
    
    def connection_made(self, transport):
        self.transport = transport
    
    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        """Handle incoming UDP datagram"""
        try:
            import json
            message = json.loads(data.decode())
            
            # Convert hex strings back to bytes
            for key in ['node_id', 'target_id', 'key', 'value', 'request_id']:
                if key in message and isinstance(message[key], str):
                    try:
                        message[key] = bytes.fromhex(message[key])
                    except ValueError:
                        pass
            
            message_type = message['type']
            address, port = addr
            
            if message_type == 'ping':
                self.dht._handle_ping(message, address, port)
            elif message_type == 'find_node':
                self.dht._handle_find_node(message, address, port)
            elif message_type == 'store':
                self.dht._handle_store(message, address, port)
            elif message_type == 'find_value':
                self.dht._handle_find_value(message, address, port)
            elif message_type.endswith('_response'):
                # Handle response messages
                request_id = message.get('request_id')
                if request_id in self.dht.pending_requests:
                    future = self.dht.pending_requests[request_id]
                    if not future.done():
                        future.set_result(message)
                        
        except Exception as e:
            print(f"Error handling datagram from {addr}: {e}")
    
    def error_received(self, exc):
        print(f"Error in Kademlia protocol: {exc}") 