"""
Peer-to-Peer Networking Module

This module implements all networking functionality for Privatus-chat,
including Kademlia DHT for peer discovery, connection management,
NAT traversal, and message routing.

Key Components:
- Kademlia DHT implementation
- Peer discovery and connection management
- NAT traversal (STUN/TURN/ICE)
- Message routing and delivery
- Network security and authentication
"""

# Module will be populated during Week 3: Networking Infrastructure 

# Privatus-chat Network Module
# Week 3: Networking Infrastructure Implementation
# 
# This module implements the peer-to-peer networking infrastructure including:
# - Kademlia DHT for peer discovery
# - P2P connection management
# - NAT traversal mechanisms
# - Message routing and serialization

from .p2p_node import P2PNode
from .kademlia_dht import KademliaDHT, KademliaNode
from .connection_manager import ConnectionManager
from .nat_traversal import NATTraversal, STUNClient
from .message_protocol import MessageProtocol, MessageSerializer
from .peer_discovery import PeerDiscovery

__all__ = [
    'P2PNode',
    'KademliaDHT',
    'KademliaNode', 
    'ConnectionManager',
    'NATTraversal',
    'STUNClient',
    'MessageProtocol',
    'MessageSerializer',
    'PeerDiscovery'
]

__version__ = '0.1.0' 