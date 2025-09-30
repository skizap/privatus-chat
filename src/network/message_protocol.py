"""
Message Protocol and Serialization for Privatus-chat
Week 3: Networking Infrastructure

This module implements the message protocol for peer-to-peer communication
including message serialization, deserialization, and protocol handling.
"""

import json
import struct
import time
import zlib
import hashlib
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from enum import Enum

# Import cryptographic modules
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# Import key management
try:
    from ..crypto.key_management import KeyManager
except ImportError:
    KeyManager = None

class MessageType(Enum):
    """P2P message types"""
    # Connection management
    HANDSHAKE = "handshake"
    HANDSHAKE_ACK = "handshake_ack"
    PING = "ping"
    PONG = "pong"
    DISCONNECT = "disconnect"
    
    # Chat messages  
    CHAT_MESSAGE = "chat_message"
    MESSAGE_ACK = "message_ack"
    TYPING_INDICATOR = "typing_indicator"
    
    # File transfer
    FILE_OFFER = "file_offer"
    FILE_ACCEPT = "file_accept"
    FILE_REJECT = "file_reject"
    FILE_CHUNK = "file_chunk"
    FILE_COMPLETE = "file_complete"
    
    # Peer discovery
    PEER_DISCOVERY = "peer_discovery"
    PEER_LIST = "peer_list"
    PEER_ANNOUNCEMENT = "peer_announcement"
    
    # Group chat
    GROUP_INVITE = "group_invite"
    GROUP_JOIN = "group_join"
    GROUP_LEAVE = "group_leave"
    GROUP_MESSAGE = "group_message"
    
    # Error handling
    ERROR = "error"

@dataclass
class MessageHeader:
    """Message header"""
    version: int = 1
    message_type: str = ""
    message_id: str = ""
    sender_id: bytes = b""
    recipient_id: bytes = b""
    timestamp: float = 0.0
    flags: int = 0
    
    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

@dataclass  
class P2PMessage:
    """P2P message structure"""
    header: MessageHeader
    payload: Dict[str, Any]
    signature: bytes = b""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary"""
        return {
            'header': asdict(self.header),
            'payload': self.payload,
            'signature': self.signature.hex() if self.signature else ""
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'P2PMessage':
        """Create message from dictionary"""
        header_data = data['header']
        header = MessageHeader(
            version=header_data['version'],
            message_type=header_data['message_type'],
            message_id=header_data['message_id'],
            sender_id=bytes.fromhex(header_data['sender_id']) if header_data['sender_id'] else b"",
            recipient_id=bytes.fromhex(header_data['recipient_id']) if header_data['recipient_id'] else b"",
            timestamp=header_data['timestamp'],
            flags=header_data['flags']
        )
        
        signature = bytes.fromhex(data['signature']) if data['signature'] else b""
        
        return cls(
            header=header,
            payload=data['payload'],
            signature=signature
        )

class MessageFlags:
    """Message flags"""
    ENCRYPTED = 1 << 0
    COMPRESSED = 1 << 1
    REQUIRES_ACK = 1 << 2
    HIGH_PRIORITY = 1 << 3
    GROUP_MESSAGE = 1 << 4
    SIGNED = 1 << 5  # Cryptographically signed message

class MessageSerializer:
    """Message serialization and deserialization"""

    def __init__(self, compress_threshold: int = 1024, key_manager: Optional['KeyManager'] = None,
                 signature_required: bool = False):
        """
        Initialize message serializer.

        Args:
            compress_threshold: Minimum size for compression
            key_manager: KeyManager instance for cryptographic signatures
            signature_required: Whether signatures are required for all messages
        """
        self.compress_threshold = compress_threshold
        self.key_manager = key_manager
        self.signature_required = signature_required
    
    def serialize(self, message: P2PMessage) -> bytes:
        """Serialize message to bytes with optional cryptographic signature"""
        try:
            # Generate signature if key manager is available and message should be signed
            should_sign = (
                self.key_manager and
                self.key_manager.identity_key and
                (self.signature_required or message.header.flags & MessageFlags.SIGNED)
            )

            if should_sign:
                # Create signature data from header and payload
                signature_data = self._create_signature_data(message)

                # Generate signature using identity key
                signature = self.key_manager.identity_key.sign(signature_data)
                message.signature = signature
                message.header.flags |= MessageFlags.SIGNED

            # Convert to dictionary
            data = message.to_dict()

            # Convert bytes fields to hex strings for JSON serialization
            header = data['header']
            if isinstance(header['sender_id'], bytes):
                header['sender_id'] = header['sender_id'].hex()
            if isinstance(header['recipient_id'], bytes):
                header['recipient_id'] = header['recipient_id'].hex()

            # Serialize to JSON
            json_data = json.dumps(data, separators=(',', ':')).encode('utf-8')

            # Compress if above threshold
            if len(json_data) > self.compress_threshold:
                json_data = zlib.compress(json_data)
                message.header.flags |= MessageFlags.COMPRESSED

            # Create packet with length prefix
            packet = struct.pack('!I', len(json_data)) + json_data

            return packet

        except Exception as e:
            raise ValueError(f"Failed to serialize message: {e}")
    
    def deserialize(self, data: bytes) -> P2PMessage:
        """Deserialize message from bytes with signature verification"""
        try:
            if len(data) < 4:
                raise ValueError("Data too short for message")

            # Read length prefix
            message_length = struct.unpack('!I', data[:4])[0]

            if len(data) < 4 + message_length:
                raise ValueError("Incomplete message data")

            json_data = data[4:4 + message_length]

            # Check if compressed
            try:
                # Try decompression first
                decompressed = zlib.decompress(json_data)
                json_data = decompressed
            except zlib.error:
                # Not compressed
                pass

            # Parse JSON
            message_dict = json.loads(json_data.decode('utf-8'))

            # Create message object
            message = P2PMessage.from_dict(message_dict)

            # Verify signature if present and key manager is available
            if (message.signature and self.key_manager and
                message.header.flags & MessageFlags.SIGNED):

                # Create signature data for verification
                signature_data = self._create_signature_data(message)

                # Verify signature
                if not self.key_manager.identity_key:
                    if self.signature_required:
                        raise ValueError("Message signature verification failed: No identity key available")
                else:
                    try:
                        is_valid = self.key_manager.identity_key.verify(signature_data, message.signature)
                        if not is_valid:
                            raise ValueError("Message signature verification failed: Invalid signature")
                    except InvalidSignature:
                        raise ValueError("Message signature verification failed: Invalid signature")

            # Check if signature is required but missing
            elif (self.signature_required and not message.signature and
                  not (hasattr(message, 'header') and message.header.flags & MessageFlags.SIGNED)):
                raise ValueError("Message signature verification failed: Signature required but missing")

            return message

        except Exception as e:
            raise ValueError(f"Failed to deserialize message: {e}")
    
    def create_handshake_message(self, sender_id: bytes, public_key: bytes) -> P2PMessage:
        """Create handshake message"""
        header = MessageHeader(
            message_type=MessageType.HANDSHAKE.value,
            message_id=self._generate_message_id(),
            sender_id=sender_id,
            flags=MessageFlags.REQUIRES_ACK
        )
        
        payload = {
            'protocol_version': 1,
            'public_key': public_key.hex(),
            'capabilities': ['chat', 'file_transfer', 'group_chat'],
            'timestamp': time.time()
        }
        
        return P2PMessage(header=header, payload=payload)
    
    def create_ping_message(self, sender_id: bytes) -> P2PMessage:
        """Create ping message"""
        header = MessageHeader(
            message_type=MessageType.PING.value,
            message_id=self._generate_message_id(),
            sender_id=sender_id
        )
        
        payload = {
            'timestamp': time.time()
        }
        
        return P2PMessage(header=header, payload=payload)
    
    def create_chat_message(self, sender_id: bytes, recipient_id: bytes, 
                          content: str, encrypted: bool = True) -> P2PMessage:
        """Create chat message"""
        flags = MessageFlags.REQUIRES_ACK
        if encrypted:
            flags |= MessageFlags.ENCRYPTED
        
        header = MessageHeader(
            message_type=MessageType.CHAT_MESSAGE.value,
            message_id=self._generate_message_id(),
            sender_id=sender_id,
            recipient_id=recipient_id,
            flags=flags
        )
        
        payload = {
            'content': content,
            'timestamp': time.time()
        }
        
        return P2PMessage(header=header, payload=payload)
    
    def create_ack_message(self, sender_id: bytes, original_message_id: str) -> P2PMessage:
        """Create acknowledgment message"""
        header = MessageHeader(
            message_type=MessageType.MESSAGE_ACK.value,
            message_id=self._generate_message_id(),
            sender_id=sender_id
        )
        
        payload = {
            'original_message_id': original_message_id,
            'timestamp': time.time()
        }
        
        return P2PMessage(header=header, payload=payload)
    
    def create_error_message(self, sender_id: bytes, error_code: str,
                           error_message: str) -> P2PMessage:
        """Create error message"""
        header = MessageHeader(
            message_type=MessageType.ERROR.value,
            message_id=self._generate_message_id(),
            sender_id=sender_id
        )

        payload = {
            'error_code': error_code,
            'error_message': error_message,
            'timestamp': time.time()
        }

        return P2PMessage(header=header, payload=payload)

    def create_signed_message(self, sender_id: bytes, message_type: str,
                            payload: Dict[str, Any], recipient_id: bytes = b"",
                            requires_ack: bool = False) -> P2PMessage:
        """Create a cryptographically signed message"""
        flags = MessageFlags.SIGNED
        if requires_ack:
            flags |= MessageFlags.REQUIRES_ACK

        header = MessageHeader(
            message_type=message_type,
            message_id=self._generate_message_id(),
            sender_id=sender_id,
            recipient_id=recipient_id,
            flags=flags
        )

        payload['timestamp'] = time.time()

        return P2PMessage(header=header, payload=payload)

    def enable_signatures(self) -> bool:
        """Enable cryptographic signatures for all messages"""
        return self.key_manager is not None and self.key_manager.identity_key is not None

    def is_signature_required(self) -> bool:
        """Check if signatures are required for messages"""
        return self.signature_required
    
    def _generate_message_id(self) -> str:
        """Generate unique message ID"""
        import uuid
        return str(uuid.uuid4())
    
    def serialize_payload(self, payload: Dict[str, Any]) -> bytes:
        """Serialize payload data to bytes"""
        try:
            json_data = json.dumps(payload, separators=(',', ':')).encode('utf-8')
            return json_data
        except Exception as e:
            raise ValueError(f"Failed to serialize payload: {e}")

    def _create_signature_data(self, message: P2PMessage) -> bytes:
        """Create data for cryptographic signature from message header and payload"""
        try:
            # Create a normalized representation of header and payload for signing
            header_data = {
                'version': message.header.version,
                'message_type': message.header.message_type,
                'message_id': message.header.message_id,
                'sender_id': message.header.sender_id.hex() if message.header.sender_id else "",
                'recipient_id': message.header.recipient_id.hex() if message.header.recipient_id else "",
                'timestamp': message.header.timestamp,
                'flags': message.header.flags
            }

            # Create signature data as JSON with consistent ordering
            signature_components = {
                'header': header_data,
                'payload': message.payload
            }

            signature_json = json.dumps(signature_components, separators=(',', ':'),
                                      sort_keys=True).encode('utf-8')

            return signature_json

        except Exception as e:
            raise ValueError(f"Failed to create signature data: {e}")

class MessageProtocol:
    """P2P message protocol handler"""

    def __init__(self, node_id: bytes, key_manager: Optional['KeyManager'] = None,
                 signature_required: bool = False):
        """
        Initialize message protocol handler.

        Args:
            node_id: Node identifier
            key_manager: KeyManager instance for cryptographic signatures
            signature_required: Whether signatures are required for all messages
        """
        self.node_id = node_id
        self.serializer = MessageSerializer(key_manager=key_manager, signature_required=signature_required)

        # Message handlers
        self.message_handlers: Dict[str, callable] = {
            MessageType.HANDSHAKE.value: self._handle_handshake,
            MessageType.HANDSHAKE_ACK.value: self._handle_handshake_ack,
            MessageType.PING.value: self._handle_ping,
            MessageType.PONG.value: self._handle_pong,
            MessageType.CHAT_MESSAGE.value: self._handle_chat_message,
            MessageType.MESSAGE_ACK.value: self._handle_message_ack,
            MessageType.DISCONNECT.value: self._handle_disconnect,
            MessageType.ERROR.value: self._handle_error
        }

        # Callbacks
        self.on_chat_message: Optional[callable] = None
        self.on_peer_connected: Optional[callable] = None
        self.on_peer_disconnected: Optional[callable] = None
        self.on_error: Optional[callable] = None
        self.on_authentication_failure: Optional[callable] = None

        # Pending acknowledgments
        self.pending_acks: Dict[str, float] = {}  # message_id -> timestamp
    
    async def handle_message(self, message: P2PMessage, peer_id: bytes) -> Optional[P2PMessage]:
        """Handle incoming message with authentication validation"""
        try:
            message_type = message.header.message_type

            if message_type in self.message_handlers:
                response = await self.message_handlers[message_type](message, peer_id)

                # Send ACK if required
                if message.header.flags & MessageFlags.REQUIRES_ACK:
                    ack_message = self.serializer.create_ack_message(
                        self.node_id, message.header.message_id
                    )
                    return ack_message

                return response
            else:
                # Unknown message type
                error_message = self.serializer.create_error_message(
                    self.node_id, "UNKNOWN_MESSAGE_TYPE",
                    f"Unknown message type: {message_type}"
                )
                return error_message

        except ValueError as e:
            # Handle authentication and validation errors
            if "signature" in str(e).lower():
                # Authentication failure
                if self.on_authentication_failure:
                    await self.on_authentication_failure(peer_id, str(e))

                error_message = self.serializer.create_error_message(
                    self.node_id, "AUTHENTICATION_FAILED", str(e)
                )
                return error_message
            else:
                # Other validation error
                error_message = self.serializer.create_error_message(
                    self.node_id, "VALIDATION_ERROR", str(e)
                )
                return error_message

        except Exception as e:
            error_message = self.serializer.create_error_message(
                self.node_id, "MESSAGE_PROCESSING_ERROR", str(e)
            )
            return error_message
    
    async def _handle_handshake(self, message: P2PMessage, peer_id: bytes) -> P2PMessage:
        """Handle handshake message"""
        # Create handshake acknowledgment
        header = MessageHeader(
            message_type=MessageType.HANDSHAKE_ACK.value,
            message_id=self.serializer._generate_message_id(),
            sender_id=self.node_id,
            recipient_id=peer_id
        )
        
        payload = {
            'protocol_version': 1,
            'capabilities': ['chat', 'file_transfer', 'group_chat'],
            'timestamp': time.time()
        }
        
        # Notify connection
        if self.on_peer_connected:
            self.on_peer_connected(peer_id, message.payload)
        
        return P2PMessage(header=header, payload=payload)
    
    async def _handle_handshake_ack(self, message: P2PMessage, peer_id: bytes):
        """Handle handshake acknowledgment"""
        if self.on_peer_connected:
            self.on_peer_connected(peer_id, message.payload)
        
        return None
    
    async def _handle_ping(self, message: P2PMessage, peer_id: bytes) -> P2PMessage:
        """Handle ping message"""
        # Create pong response
        header = MessageHeader(
            message_type=MessageType.PONG.value,
            message_id=self.serializer._generate_message_id(),
            sender_id=self.node_id,
            recipient_id=peer_id
        )
        
        payload = {
            'timestamp': time.time(),
            'original_timestamp': message.payload.get('timestamp', 0)
        }
        
        return P2PMessage(header=header, payload=payload)
    
    async def _handle_pong(self, message: P2PMessage, peer_id: bytes):
        """Handle pong message"""
        # Calculate round-trip time
        original_timestamp = message.payload.get('original_timestamp', 0)
        if original_timestamp > 0:
            rtt = time.time() - original_timestamp
            print(f"RTT to {peer_id.hex()}: {rtt:.3f}s")
        
        return None
    
    async def _handle_chat_message(self, message: P2PMessage, peer_id: bytes):
        """Handle chat message"""
        if self.on_chat_message:
            self.on_chat_message(peer_id, message.payload)
        
        return None
    
    async def _handle_message_ack(self, message: P2PMessage, peer_id: bytes):
        """Handle message acknowledgment"""
        original_message_id = message.payload.get('original_message_id')
        if original_message_id in self.pending_acks:
            del self.pending_acks[original_message_id]
        
        return None
    
    async def _handle_disconnect(self, message: P2PMessage, peer_id: bytes):
        """Handle disconnect message"""
        if self.on_peer_disconnected:
            self.on_peer_disconnected(peer_id, message.payload.get('reason', 'Unknown'))
        
        return None
    
    async def _handle_error(self, message: P2PMessage, peer_id: bytes):
        """Handle error message"""
        if self.on_error:
            self.on_error(peer_id, message.payload)
        
        return None
    
    def add_pending_ack(self, message_id: str):
        """Add message to pending acknowledgments"""
        self.pending_acks[message_id] = time.time()
    
    def check_pending_acks(self, timeout: float = 30.0) -> List[str]:
        """Check for timed out acknowledgments"""
        current_time = time.time()
        timed_out = []
        
        for message_id, timestamp in list(self.pending_acks.items()):
            if current_time - timestamp > timeout:
                timed_out.append(message_id)
                del self.pending_acks[message_id]
        
        return timed_out 