"""
Peer Discovery System for Privatus-chat
Week 3: Networking Infrastructure

This module implements peer discovery mechanisms using multiple strategies
including DHT lookup, bootstrap servers, and peer exchange.
"""

import asyncio
import time
import random
from typing import Dict, List, Set, Optional, Tuple, Callable
from dataclasses import dataclass
from .kademlia_dht import KademliaDHT, KademliaNode
from .connection_manager import PeerInfo

@dataclass
class DiscoveredPeer:
    """Information about a discovered peer"""
    peer_id: bytes
    addresses: List[Tuple[str, int]]
    last_seen: float
    source: str  # How we discovered this peer
    trust_score: float = 0.0
    capabilities: List[str] = None
    
    def __post_init__(self):
        if self.capabilities is None:
            self.capabilities = []

class PeerDiscovery:
    """Peer discovery coordinator"""
    
    def __init__(self, node_id: bytes, dht: KademliaDHT):
        self.node_id = node_id
        self.dht = dht
        
        # Discovered peers
        self.discovered_peers: Dict[bytes, DiscoveredPeer] = {}
        
        # Bootstrap configuration
        self.bootstrap_servers: List[Tuple[str, int]] = []
        self.use_bootstrap = True
        
        # Discovery callbacks
        self.on_peer_discovered: Optional[Callable[[DiscoveredPeer], None]] = None
        self.on_peer_lost: Optional[Callable[[bytes], None]] = None
        
        # Discovery settings
        self.max_peers = 100
        self.discovery_interval = 30.0  # seconds
        self.peer_timeout = 300.0  # 5 minutes
        
        # Discovery state
        self.running = False
        self.discovery_task: Optional[asyncio.Task] = None
        self.cleanup_task: Optional[asyncio.Task] = None
        
        # Peer exchange
        self.peer_exchange_enabled = True
        self.max_peers_per_exchange = 10
    
    async def start(self, bootstrap_servers: List[Tuple[str, int]] = None):
        """Start peer discovery"""
        if self.running:
            return
        
        self.running = True
        
        if bootstrap_servers:
            self.bootstrap_servers.extend(bootstrap_servers)
        
        # Start discovery and cleanup tasks
        self.discovery_task = asyncio.create_task(self._discovery_loop())
        self.cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        # Initial bootstrap
        if self.use_bootstrap:
            await self._bootstrap_discovery()
    
    async def stop(self):
        """Stop peer discovery"""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel tasks
        if self.discovery_task:
            self.discovery_task.cancel()
            try:
                await self.discovery_task
            except asyncio.CancelledError:
                pass
        
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
    
    async def _bootstrap_discovery(self):
        """Bootstrap peer discovery using configured servers"""
        for server_addr, server_port in self.bootstrap_servers:
            try:
                # Try to connect to bootstrap server
                await self._discover_from_bootstrap(server_addr, server_port)
            except Exception as e:
                print(f"Bootstrap discovery failed for {server_addr}:{server_port}: {e}")
    
    async def _discover_from_bootstrap(self, server_addr: str, server_port: int):
        """Discover peers from a bootstrap server"""
        try:
            # Simple HTTP-based bootstrap (in production, use more secure method)
            import aiohttp
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                url = f"http://{server_addr}:{server_port}/peers"
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        peers = data.get('peers', [])
                        
                        for peer_data in peers:
                            peer_id = bytes.fromhex(peer_data['peer_id'])
                            addresses = [(addr['ip'], addr['port']) for addr in peer_data['addresses']]
                            
                            discovered_peer = DiscoveredPeer(
                                peer_id=peer_id,
                                addresses=addresses,
                                last_seen=time.time(),
                                source='bootstrap',
                                capabilities=peer_data.get('capabilities', [])
                            )
                            
                            await self._add_discovered_peer(discovered_peer)
                            
        except Exception as e:
            print(f"Bootstrap server discovery failed: {e}")
    
    async def _discovery_loop(self):
        """Main discovery loop"""
        while self.running:
            try:
                # DHT-based discovery
                await self._dht_discovery()
                
                # Peer exchange with connected peers
                if self.peer_exchange_enabled:
                    await self._peer_exchange_discovery()
                
                # Random walk discovery
                await self._random_walk_discovery()
                
                await asyncio.sleep(self.discovery_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in discovery loop: {e}")
                await asyncio.sleep(self.discovery_interval)
    
    async def _dht_discovery(self):
        """Discover peers using DHT"""
        try:
            # Generate random keys to search for
            for _ in range(5):
                random_key = random.randbytes(20)  # 160-bit key
                
                # Find nodes close to random key
                nodes = await self.dht.find_node(random_key, 
                                               self.dht.bind_address, 
                                               self.dht.bind_port)
                
                for node in nodes:
                    if node.node_id != self.node_id:
                        discovered_peer = DiscoveredPeer(
                            peer_id=node.node_id,
                            addresses=[(node.address, node.port)],
                            last_seen=time.time(),
                            source='dht'
                        )
                        
                        await self._add_discovered_peer(discovered_peer)
                        
        except Exception as e:
            print(f"DHT discovery error: {e}")
    
    async def _peer_exchange_discovery(self):
        """Discover peers through peer exchange"""
        # This would be implemented with actual peer connections
        # For now, it's a placeholder for the protocol
        pass
    
    async def _random_walk_discovery(self):
        """Discover peers through random walks"""
        try:
            # Get random peer from discovered peers
            if not self.discovered_peers:
                return
            
            random_peer_id = random.choice(list(self.discovered_peers.keys()))
            random_peer = self.discovered_peers[random_peer_id]
            
            # Try to discover peers from this peer's neighborhood
            # This would involve actually connecting and asking for peers
            # For now, it's a placeholder
            
        except Exception as e:
            print(f"Random walk discovery error: {e}")
    
    async def _cleanup_loop(self):
        """Clean up old/stale peer entries"""
        while self.running:
            try:
                current_time = time.time()
                stale_peers = []
                
                for peer_id, peer in self.discovered_peers.items():
                    if current_time - peer.last_seen > self.peer_timeout:
                        stale_peers.append(peer_id)
                
                # Remove stale peers
                for peer_id in stale_peers:
                    await self._remove_discovered_peer(peer_id)
                
                await asyncio.sleep(60)  # Check every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in cleanup loop: {e}")
                await asyncio.sleep(60)
    
    async def _add_discovered_peer(self, peer: DiscoveredPeer):
        """Add a discovered peer"""
        if peer.peer_id == self.node_id:
            return  # Don't add ourselves
        
        if len(self.discovered_peers) >= self.max_peers:
            # Remove oldest peer
            oldest_peer_id = min(self.discovered_peers.keys(),
                               key=lambda pid: self.discovered_peers[pid].last_seen)
            await self._remove_discovered_peer(oldest_peer_id)
        
        # Update or add peer
        if peer.peer_id in self.discovered_peers:
            existing_peer = self.discovered_peers[peer.peer_id]
            existing_peer.last_seen = peer.last_seen
            existing_peer.addresses.extend(peer.addresses)
            # Remove duplicates
            existing_peer.addresses = list(set(existing_peer.addresses))
        else:
            self.discovered_peers[peer.peer_id] = peer
            
            # Notify callback
            if self.on_peer_discovered:
                self.on_peer_discovered(peer)
    
    async def _remove_discovered_peer(self, peer_id: bytes):
        """Remove a discovered peer"""
        if peer_id in self.discovered_peers:
            del self.discovered_peers[peer_id]
            
            # Notify callback
            if self.on_peer_lost:
                self.on_peer_lost(peer_id)
    
    def get_discovered_peers(self, max_count: int = None) -> List[DiscoveredPeer]:
        """Get list of discovered peers"""
        peers = list(self.discovered_peers.values())
        
        # Sort by trust score and last seen
        peers.sort(key=lambda p: (p.trust_score, p.last_seen), reverse=True)
        
        if max_count:
            peers = peers[:max_count]
        
        return peers
    
    def get_peer_candidates_for_connection(self, count: int = 10) -> List[PeerInfo]:
        """Get peer candidates suitable for connection"""
        discovered = self.get_discovered_peers(count * 2)
        candidates = []
        
        for peer in discovered:
            if peer.addresses:
                # Use the first address for now
                address, port = peer.addresses[0]
                
                peer_info = PeerInfo(
                    peer_id=peer.peer_id,
                    address=address,
                    port=port,
                    node_id=peer.peer_id,
                    last_seen=peer.last_seen
                )
                
                candidates.append(peer_info)
        
        return candidates[:count]
    
    def update_peer_trust_score(self, peer_id: bytes, score_delta: float):
        """Update peer trust score"""
        if peer_id in self.discovered_peers:
            peer = self.discovered_peers[peer_id]
            peer.trust_score = max(0.0, min(1.0, peer.trust_score + score_delta))
    
    def mark_peer_active(self, peer_id: bytes):
        """Mark a peer as recently active"""
        if peer_id in self.discovered_peers:
            self.discovered_peers[peer_id].last_seen = time.time()
    
    def add_bootstrap_server(self, address: str, port: int):
        """Add a bootstrap server"""
        self.bootstrap_servers.append((address, port))
    
    def get_discovery_stats(self) -> Dict[str, int]:
        """Get discovery statistics"""
        sources = {}
        for peer in self.discovered_peers.values():
            sources[peer.source] = sources.get(peer.source, 0) + 1
        
        return {
            'total_peers': len(self.discovered_peers),
            'sources': sources,
            'max_peers': self.max_peers
        } 