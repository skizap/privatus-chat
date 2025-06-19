"""
NAT Traversal Implementation for Privatus-chat
Week 3: Networking Infrastructure

This module implements NAT traversal mechanisms including STUN/TURN support
for establishing direct peer-to-peer connections behind NAT devices.
"""

import asyncio
import socket
import struct
import random
import time
from typing import Optional, Tuple, List
from dataclasses import dataclass
from enum import Enum

class STUNMessageType(Enum):
    """STUN message types"""
    BINDING_REQUEST = 0x0001
    BINDING_RESPONSE = 0x0101
    BINDING_ERROR_RESPONSE = 0x0111

class STUNAttribute(Enum):
    """STUN attribute types"""
    MAPPED_ADDRESS = 0x0001
    XOR_MAPPED_ADDRESS = 0x0020
    ERROR_CODE = 0x0009

@dataclass
class STUNResponse:
    """STUN server response"""
    public_ip: str
    public_port: int
    server_ip: str
    server_port: int
    success: bool = True
    error_message: str = ""

class STUNClient:
    """STUN client for NAT traversal"""
    
    # Public STUN servers
    DEFAULT_STUN_SERVERS = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun2.l.google.com", 19302),
        ("stun.stunprotocol.org", 3478),
        ("stun.softjoys.com", 3478)
    ]
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.magic_cookie = 0x2112A442
    
    async def get_public_address(self, local_port: int = 0, 
                               stun_servers: List[Tuple[str, int]] = None) -> Optional[STUNResponse]:
        """Get public IP and port using STUN"""
        if stun_servers is None:
            stun_servers = self.DEFAULT_STUN_SERVERS
        
        for server_ip, server_port in stun_servers:
            try:
                response = await self._query_stun_server(server_ip, server_port, local_port)
                if response and response.success:
                    return response
            except Exception as e:
                print(f"STUN query failed for {server_ip}:{server_port}: {e}")
                continue
        
        return None
    
    async def _query_stun_server(self, server_ip: str, server_port: int, 
                               local_port: int) -> Optional[STUNResponse]:
        """Query a STUN server"""
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        try:
            if local_port > 0:
                sock.bind(('', local_port))
            
            # Generate transaction ID
            transaction_id = struct.pack('!3I', 
                                       random.randint(0, 0xFFFFFFFF),
                                       random.randint(0, 0xFFFFFFFF),
                                       random.randint(0, 0xFFFFFFFF))
            
            # Create STUN binding request
            request = self._create_binding_request(transaction_id)
            
            # Send request
            sock.sendto(request, (server_ip, server_port))
            
            # Wait for response
            sock.settimeout(self.timeout)
            data, addr = sock.recvfrom(1024)
            
            # Parse response
            return self._parse_stun_response(data, transaction_id, server_ip, server_port)
            
        except Exception as e:
            return STUNResponse("", 0, server_ip, server_port, False, str(e))
        finally:
            sock.close()
    
    def _create_binding_request(self, transaction_id: bytes) -> bytes:
        """Create STUN binding request message"""
        message_type = STUNMessageType.BINDING_REQUEST.value
        message_length = 0  # No attributes
        
        header = struct.pack('!HHI12s',
                           message_type,
                           message_length,
                           self.magic_cookie,
                           transaction_id)
        
        return header
    
    def _parse_stun_response(self, data: bytes, expected_transaction_id: bytes,
                           server_ip: str, server_port: int) -> Optional[STUNResponse]:
        """Parse STUN response message"""
        if len(data) < 20:
            return STUNResponse("", 0, server_ip, server_port, False, "Response too short")
        
        # Parse header
        message_type, message_length, magic_cookie, transaction_id = struct.unpack('!HHI12s', data[:20])
        
        # Verify transaction ID
        if transaction_id != expected_transaction_id:
            return STUNResponse("", 0, server_ip, server_port, False, "Transaction ID mismatch")
        
        # Check if it's a binding response
        if message_type == STUNMessageType.BINDING_ERROR_RESPONSE.value:
            return STUNResponse("", 0, server_ip, server_port, False, "STUN error response")
        
        if message_type != STUNMessageType.BINDING_RESPONSE.value:
            return STUNResponse("", 0, server_ip, server_port, False, "Unexpected message type")
        
        # Parse attributes
        offset = 20
        public_ip = ""
        public_port = 0
        
        while offset < len(data):
            if offset + 4 >= len(data):
                break
                
            attr_type, attr_length = struct.unpack('!HH', data[offset:offset+4])
            offset += 4
            
            if offset + attr_length > len(data):
                break
            
            attr_data = data[offset:offset+attr_length]
            
            if attr_type == STUNAttribute.MAPPED_ADDRESS.value:
                public_ip, public_port = self._parse_mapped_address(attr_data)
            elif attr_type == STUNAttribute.XOR_MAPPED_ADDRESS.value:
                public_ip, public_port = self._parse_xor_mapped_address(attr_data, transaction_id)
            
            # Move to next attribute (with padding)
            offset += attr_length
            if attr_length % 4 != 0:
                offset += 4 - (attr_length % 4)
        
        if public_ip and public_port:
            return STUNResponse(public_ip, public_port, server_ip, server_port)
        else:
            return STUNResponse("", 0, server_ip, server_port, False, "No address found")
    
    def _parse_mapped_address(self, data: bytes) -> Tuple[str, int]:
        """Parse MAPPED-ADDRESS attribute"""
        if len(data) < 8:
            return "", 0
        
        reserved, family, port = struct.unpack('!BBH', data[:4])
        
        if family == 1:  # IPv4
            ip_bytes = data[4:8]
            ip = socket.inet_ntoa(ip_bytes)
            return ip, port
        
        return "", 0
    
    def _parse_xor_mapped_address(self, data: bytes, transaction_id: bytes) -> Tuple[str, int]:
        """Parse XOR-MAPPED-ADDRESS attribute"""
        if len(data) < 8:
            return "", 0
        
        reserved, family, xor_port = struct.unpack('!BBH', data[:4])
        
        if family == 1:  # IPv4
            # XOR port with magic cookie high 16 bits
            port = xor_port ^ (self.magic_cookie >> 16)
            
            # XOR IP with magic cookie
            xor_ip_bytes = data[4:8]
            magic_cookie_bytes = struct.pack('!I', self.magic_cookie)
            
            ip_bytes = bytes(a ^ b for a, b in zip(xor_ip_bytes, magic_cookie_bytes))
            ip = socket.inet_ntoa(ip_bytes)
            
            return ip, port
        
        return "", 0

class NATTraversal:
    """NAT traversal coordination"""
    
    def __init__(self):
        self.stun_client = STUNClient()
        self.public_address: Optional[STUNResponse] = None
        self.nat_type = "unknown"
    
    async def discover_nat_type(self) -> str:
        """Discover NAT type using STUN"""
        try:
            # Basic NAT detection
            response1 = await self.stun_client.get_public_address()
            
            if not response1 or not response1.success:
                self.nat_type = "no_connectivity"
                return self.nat_type
            
            self.public_address = response1
            
            # Try from different local ports
            response2 = await self.stun_client.get_public_address(local_port=0)
            
            if response2 and response2.success:
                if (response1.public_ip == response2.public_ip and 
                    response1.public_port == response2.public_port):
                    self.nat_type = "open_internet"
                elif response1.public_ip == response2.public_ip:
                    self.nat_type = "port_restricted"
                else:
                    self.nat_type = "symmetric"
            else:
                self.nat_type = "full_cone"
            
            return self.nat_type
            
        except Exception as e:
            print(f"NAT type discovery failed: {e}")
            self.nat_type = "unknown"
            return self.nat_type
    
    async def setup_hole_punch(self, peer_address: str, peer_port: int, 
                             local_port: int) -> bool:
        """Attempt UDP hole punching"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('', local_port))
            
            # Send packets to peer to create NAT mapping
            punch_message = b"HOLE_PUNCH"
            
            for _ in range(10):  # Try multiple times
                sock.sendto(punch_message, (peer_address, peer_port))
                await asyncio.sleep(0.1)
            
            # Try to receive response
            sock.settimeout(5.0)
            try:
                data, addr = sock.recvfrom(1024)
                if data == punch_message:
                    return True
            except socket.timeout:
                pass
            
            return False
            
        except Exception as e:
            print(f"Hole punching failed: {e}")
            return False
        finally:
            if 'sock' in locals():
                sock.close()
    
    async def get_connection_candidates(self, local_port: int) -> List[Tuple[str, int]]:
        """Get connection candidates (local and public addresses)"""
        candidates = []
        
        # Add local addresses
        try:
            # Get local IP addresses
            hostname = socket.gethostname()
            local_ips = socket.gethostbyname_ex(hostname)[2]
            
            for ip in local_ips:
                if not ip.startswith('127.'):  # Skip loopback
                    candidates.append((ip, local_port))
        except Exception:
            pass
        
        # Add public address if available
        if self.public_address and self.public_address.success:
            candidates.append((self.public_address.public_ip, self.public_address.public_port))
        else:
            # Try to get public address
            public_addr = await self.stun_client.get_public_address(local_port)
            if public_addr and public_addr.success:
                self.public_address = public_addr
                candidates.append((public_addr.public_ip, public_addr.public_port))
        
        return candidates
    
    def can_connect_directly(self, peer_nat_type: str) -> bool:
        """Check if direct connection is possible based on NAT types"""
        # Simplified NAT compatibility matrix
        compatibility = {
            ("open_internet", "open_internet"): True,
            ("open_internet", "full_cone"): True,
            ("open_internet", "port_restricted"): True,
            ("open_internet", "symmetric"): True,
            ("full_cone", "open_internet"): True,
            ("full_cone", "full_cone"): True,
            ("full_cone", "port_restricted"): True,
            ("full_cone", "symmetric"): False,
            ("port_restricted", "open_internet"): True,
            ("port_restricted", "full_cone"): True,
            ("port_restricted", "port_restricted"): True,
            ("port_restricted", "symmetric"): False,
            ("symmetric", "open_internet"): True,
            ("symmetric", "full_cone"): False,
            ("symmetric", "port_restricted"): False,
            ("symmetric", "symmetric"): False,
        }
        
        return compatibility.get((self.nat_type, peer_nat_type), False)
    
    async def test_connectivity(self, address: str, port: int, timeout: float = 5.0) -> bool:
        """Test if we can connect to an address"""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False 