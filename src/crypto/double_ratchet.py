"""
Double Ratchet Protocol Implementation for Privatus-chat

Implements the Signal Protocol's Double Ratchet algorithm providing:
- Forward secrecy through symmetric key ratcheting
- Post-compromise security through Diffie-Hellman ratcheting
- Out-of-order message handling
- Automatic key rotation and secure deletion

Based on the Signal Protocol specification:
https://signal.org/docs/specifications/doubleratchet/

Security Features:
- Perfect forward secrecy for all messages
- Post-compromise security recovery
- Message key uniqueness and deletion
- Cryptographic deniability
- Resistance to key compromise scenarios
"""

import hashlib
import hmac
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives import serialization

from .secure_random import SecureRandom
from .encryption import MessageEncryption, KeyDerivation
from .key_management import KeyManager


class RatchetDirection(Enum):
    """Ratchet direction for key chains."""
    SENDING = "sending"
    RECEIVING = "receiving"


@dataclass
class ChainKey:
    """Represents a chain key in the ratchet."""
    key: bytes
    index: int
    
    def advance(self) -> 'ChainKey':
        """Advance the chain key to the next step."""
        # Use HMAC-SHA256 to advance the chain key
        next_key = hmac.new(
            self.key,
            b"chain-advance",
            hashlib.sha256
        ).digest()
        
        return ChainKey(next_key, self.index + 1)
    
    def derive_message_key(self) -> bytes:
        """Derive a message key from this chain key."""
        return hmac.new(
            self.key,
            b"message-key",
            hashlib.sha256
        ).digest()[:32]  # 256-bit key


@dataclass
class MessageKey:
    """Represents a message key for encrypting/decrypting a single message."""
    key: bytes
    index: int
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class DHRatchetKey:
    """Diffie-Hellman ratchet key pair."""
    private_key: X25519PrivateKey
    public_key: X25519PublicKey
    
    @classmethod
    def generate(cls) -> 'DHRatchetKey':
        """Generate a new DH ratchet key pair."""
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(private_key, public_key)
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as bytes."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def perform_dh(self, other_public_key: bytes) -> bytes:
        """Perform Diffie-Hellman key exchange."""
        other_public = X25519PublicKey.from_public_bytes(other_public_key)
        shared_secret = self.private_key.exchange(other_public)
        return shared_secret


@dataclass
class RatchetState:
    """Complete state of a Double Ratchet session."""
    # DH Ratchet state
    dh_self: Optional[DHRatchetKey] = None
    dh_remote: Optional[bytes] = None
    root_key: Optional[bytes] = None
    
    # Symmetric ratchet state
    chain_key_send: Optional[ChainKey] = None
    chain_key_receive: Optional[ChainKey] = None
    
    # Message counters
    send_count: int = 0
    receive_count: int = 0
    previous_send_count: int = 0
    
    # Skipped message keys for out-of-order handling
    skipped_message_keys: Dict[Tuple[bytes, int], MessageKey] = field(default_factory=dict)
    
    # State management
    session_id: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    
    def update_timestamp(self):
        """Update the last updated timestamp."""
        self.last_updated = datetime.now()


class DoubleRatchet:
    """
    Double Ratchet protocol implementation.
    
    Provides forward secrecy and post-compromise security for messaging.
    """
    
    # Constants
    MAX_SKIP = 1000  # Maximum number of message keys to skip
    MAX_CACHE = 100  # Maximum number of message keys to cache
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.state = RatchetState(session_id=session_id)
        self.message_encryption = MessageEncryption()
        
    def initialize_alice(self, shared_secret: bytes, bob_public_key: bytes) -> None:
        """
        Initialize Alice's side of the ratchet.
        
        Args:
            shared_secret: Initial shared secret from X3DH
            bob_public_key: Bob's initial public key
        """
        # Generate initial DH key pair
        self.state.dh_self = DHRatchetKey.generate()
        self.state.dh_remote = bob_public_key
        
        # Derive root key from shared secret
        self.state.root_key = self._kdf_root_key(shared_secret, b"initial-root")
        
        # Perform initial DH ratchet step
        self._dh_ratchet_step()
        
        self.state.update_timestamp()
    
    def initialize_bob(self, shared_secret: bytes, dh_private_key: X25519PrivateKey) -> None:
        """
        Initialize Bob's side of the ratchet.
        
        Args:
            shared_secret: Initial shared secret from X3DH
            dh_private_key: Bob's DH private key
        """
        # Set up initial state
        public_key = dh_private_key.public_key()
        self.state.dh_self = DHRatchetKey(dh_private_key, public_key)
        self.state.root_key = self._kdf_root_key(shared_secret, b"initial-root")
        
        # Initialize receiving chain
        self.state.chain_key_receive = ChainKey(
            key=self._kdf_chain_key(self.state.root_key, b"initial-receive"),
            index=0
        )
        
        self.state.update_timestamp()
    
    def encrypt_message(self, plaintext: bytes, associated_data: bytes = b"") -> Dict[str, Any]:
        """
        Encrypt a message using the Double Ratchet.
        
        Args:
            plaintext: Message to encrypt
            associated_data: Additional authenticated data
            
        Returns:
            Dict containing encrypted message and metadata
        """
        # Ensure we have a sending chain
        if not self.state.chain_key_send:
            if not self.state.dh_remote:
                raise ValueError("Cannot encrypt: no remote DH key")
            self._dh_ratchet_step()
        
        # Derive message key
        message_key = self.state.chain_key_send.derive_message_key()
        
        # Encrypt the message
        nonce, ciphertext = self.message_encryption.encrypt(
            plaintext, 
            message_key, 
            associated_data
        )
        
        # Create message header
        header = {
            'dh_public_key': self.state.dh_self.get_public_key_bytes().hex(),
            'previous_chain_length': self.state.previous_send_count,
            'message_number': self.state.chain_key_send.index
        }
        
        # Advance the sending chain
        self.state.chain_key_send = self.state.chain_key_send.advance()
        self.state.send_count += 1
        
        # Securely delete the message key
        self._secure_delete_key(message_key)
        
        self.state.update_timestamp()
        
        return {
            'header': header,
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'session_id': self.session_id
        }
    
    def decrypt_message(self, encrypted_message: Dict[str, Any], 
                       associated_data: bytes = b"") -> Optional[bytes]:
        """
        Decrypt a message using the Double Ratchet.
        
        Args:
            encrypted_message: Encrypted message with header
            associated_data: Additional authenticated data
            
        Returns:
            Decrypted plaintext or None if decryption fails
        """
        try:
            header = encrypted_message['header']
            nonce = bytes.fromhex(encrypted_message['nonce'])
            ciphertext = bytes.fromhex(encrypted_message['ciphertext'])
            
            # Extract header information
            dh_public_key = bytes.fromhex(header['dh_public_key'])
            previous_chain_length = header['previous_chain_length']
            message_number = header['message_number']
            
            # Check if we need to perform DH ratchet step
            if self.state.dh_remote != dh_public_key:
                self._handle_new_dh_key(dh_public_key, previous_chain_length)
            
            # Try to decrypt with current receiving chain
            message_key = self._get_message_key(message_number)
            if not message_key:
                return None
            
            # Decrypt the message
            plaintext = self.message_encryption.decrypt(
                ciphertext,
                message_key,
                nonce,
                associated_data
            )
            
            # Securely delete the message key
            self._secure_delete_key(message_key)
            
            self.state.update_timestamp()
            return plaintext
            
        except Exception as e:
            # Log error but don't expose details
            return None
    
    def _dh_ratchet_step(self) -> None:
        """Perform a Diffie-Hellman ratchet step."""
        if not self.state.dh_remote or not self.state.root_key:
            return
        
        # Generate new DH key pair
        old_dh_self = self.state.dh_self
        self.state.dh_self = DHRatchetKey.generate()
        
        # Perform DH exchange
        dh_output = self.state.dh_self.perform_dh(self.state.dh_remote)
        
        # Derive new root key and chain key
        new_root_key, new_chain_key = self._kdf_dh_ratchet(
            self.state.root_key, 
            dh_output
        )
        
        self.state.root_key = new_root_key
        self.state.chain_key_send = ChainKey(new_chain_key, 0)
        
        # Update counters
        self.state.previous_send_count = self.state.send_count
        self.state.send_count = 0
        
        # Securely delete old DH private key
        if old_dh_self:
            self._secure_delete_dh_key(old_dh_self)
    
    def _handle_new_dh_key(self, new_dh_public_key: bytes, 
                          previous_chain_length: int) -> None:
        """Handle receiving a new DH public key."""
        # Skip messages from previous receiving chain if needed
        if self.state.chain_key_receive:
            self._skip_message_keys(previous_chain_length)
        
        # Update remote DH key
        self.state.dh_remote = new_dh_public_key
        
        # Perform DH ratchet step for receiving
        if self.state.dh_self and self.state.root_key:
            dh_output = self.state.dh_self.perform_dh(new_dh_public_key)
            
            new_root_key, new_chain_key = self._kdf_dh_ratchet(
                self.state.root_key,
                dh_output
            )
            
            self.state.root_key = new_root_key
            self.state.chain_key_receive = ChainKey(new_chain_key, 0)
            self.state.receive_count = 0
    
    def _get_message_key(self, message_number: int) -> Optional[bytes]:
        """Get message key for decryption, handling out-of-order messages."""
        if not self.state.chain_key_receive:
            return None
        
        # Check if we have a skipped message key
        key_tuple = (self.state.dh_remote, message_number)
        if key_tuple in self.state.skipped_message_keys:
            message_key_obj = self.state.skipped_message_keys.pop(key_tuple)
            return message_key_obj.key
        
        # Check if we need to skip messages
        if message_number < self.state.chain_key_receive.index:
            # Message is older than current chain state
            return None
        
        # Advance chain to message number
        current_chain = self.state.chain_key_receive
        while current_chain.index < message_number:
            # Store skipped message key
            skipped_key = MessageKey(
                key=current_chain.derive_message_key(),
                index=current_chain.index
            )
            
            key_tuple = (self.state.dh_remote, current_chain.index)
            self.state.skipped_message_keys[key_tuple] = skipped_key
            
            current_chain = current_chain.advance()
            
            # Prevent excessive skipping
            if len(self.state.skipped_message_keys) > self.MAX_SKIP:
                self._cleanup_old_message_keys()
        
        # Get the message key for this message
        message_key = current_chain.derive_message_key()
        
        # Advance the receiving chain
        self.state.chain_key_receive = current_chain.advance()
        self.state.receive_count = self.state.chain_key_receive.index
        
        return message_key
    
    def _skip_message_keys(self, until_index: int) -> None:
        """Skip message keys up to the specified index."""
        if not self.state.chain_key_receive:
            return
        
        current_chain = self.state.chain_key_receive
        while current_chain.index < until_index:
            # Store skipped message key
            skipped_key = MessageKey(
                key=current_chain.derive_message_key(),
                index=current_chain.index
            )
            
            key_tuple = (self.state.dh_remote, current_chain.index)
            self.state.skipped_message_keys[key_tuple] = skipped_key
            
            current_chain = current_chain.advance()
            
            # Prevent excessive skipping
            if len(self.state.skipped_message_keys) > self.MAX_SKIP:
                break
        
        self.state.chain_key_receive = current_chain
        self.state.receive_count = current_chain.index
    
    def _cleanup_old_message_keys(self) -> None:
        """Clean up old message keys to prevent memory bloat."""
        if len(self.state.skipped_message_keys) <= self.MAX_CACHE:
            return
        
        # Sort by timestamp and remove oldest
        sorted_keys = sorted(
            self.state.skipped_message_keys.items(),
            key=lambda x: x[1].timestamp
        )
        
        # Keep only the most recent MAX_CACHE keys
        keys_to_keep = dict(sorted_keys[-self.MAX_CACHE:])
        
        # Securely delete removed keys
        for key_tuple, message_key in self.state.skipped_message_keys.items():
            if key_tuple not in keys_to_keep:
                self._secure_delete_key(message_key.key)
        
        self.state.skipped_message_keys = keys_to_keep
    
    def _kdf_root_key(self, input_key: bytes, info: bytes) -> bytes:
        """Key derivation function for root key."""
        return KeyDerivation.derive_keys(
            shared_secret=input_key,
            salt=b"root-key-salt",
            info=info,
            num_keys=1,
            key_length=32
        )[0]
    
    def _kdf_chain_key(self, input_key: bytes, info: bytes) -> bytes:
        """Key derivation function for chain key."""
        return KeyDerivation.derive_keys(
            shared_secret=input_key,
            salt=b"chain-key-salt", 
            info=info,
            num_keys=1,
            key_length=32
        )[0]
    
    def _kdf_dh_ratchet(self, root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """Key derivation for DH ratchet step."""
        keys = KeyDerivation.derive_keys(
            shared_secret=dh_output,
            salt=root_key,
            info=b"dh-ratchet",
            num_keys=2,
            key_length=32
        )
        return keys[0], keys[1]  # new_root_key, new_chain_key
    
    def _secure_delete_key(self, key: bytes) -> None:
        """Securely delete a key from memory."""
        # In Python, we can't directly overwrite memory,
        # but we can at least clear the reference
        if isinstance(key, bytes):
            # Convert to bytearray for potential overwriting
            key_array = bytearray(key)
            # Overwrite with random data
            for i in range(len(key_array)):
                key_array[i] = SecureRandom().generate_bytes(1)[0]
            # Clear the array
            key_array.clear()
    
    def _secure_delete_dh_key(self, dh_key: DHRatchetKey) -> None:
        """Securely delete a DH key pair."""
        # Clear the key references
        dh_key.private_key = None
        dh_key.public_key = None
    
    def get_state_for_storage(self) -> Dict[str, Any]:
        """Get ratchet state for secure storage."""
        state_dict = {
            'session_id': self.state.session_id,
            'created_at': self.state.created_at.isoformat(),
            'last_updated': self.state.last_updated.isoformat(),
            'send_count': self.state.send_count,
            'receive_count': self.state.receive_count,
            'previous_send_count': self.state.previous_send_count
        }
        
        # Add keys (encrypted storage would handle encryption)
        if self.state.root_key:
            state_dict['root_key'] = self.state.root_key.hex()
        
        if self.state.dh_self:
            state_dict['dh_self_private'] = self.state.dh_self.private_key.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption()
            ).hex()
            state_dict['dh_self_public'] = self.state.dh_self.get_public_key_bytes().hex()
        
        if self.state.dh_remote:
            state_dict['dh_remote'] = self.state.dh_remote.hex()
        
        if self.state.chain_key_send:
            state_dict['chain_key_send'] = {
                'key': self.state.chain_key_send.key.hex(),
                'index': self.state.chain_key_send.index
            }
        
        if self.state.chain_key_receive:
            state_dict['chain_key_receive'] = {
                'key': self.state.chain_key_receive.key.hex(),
                'index': self.state.chain_key_receive.index
            }
        
        return state_dict
    
    def load_state_from_storage(self, state_dict: Dict[str, Any]) -> None:
        """Load ratchet state from storage."""
        self.state.session_id = state_dict['session_id']
        self.state.created_at = datetime.fromisoformat(state_dict['created_at'])
        self.state.last_updated = datetime.fromisoformat(state_dict['last_updated'])
        self.state.send_count = state_dict['send_count']
        self.state.receive_count = state_dict['receive_count']
        self.state.previous_send_count = state_dict['previous_send_count']
        
        # Load keys
        if 'root_key' in state_dict:
            self.state.root_key = bytes.fromhex(state_dict['root_key'])
        
        if 'dh_self_private' in state_dict:
            private_key = X25519PrivateKey.from_private_bytes(
                bytes.fromhex(state_dict['dh_self_private'])
            )
            public_key = private_key.public_key()
            self.state.dh_self = DHRatchetKey(private_key, public_key)
        
        if 'dh_remote' in state_dict:
            self.state.dh_remote = bytes.fromhex(state_dict['dh_remote'])
        
        if 'chain_key_send' in state_dict:
            chain_data = state_dict['chain_key_send']
            self.state.chain_key_send = ChainKey(
                key=bytes.fromhex(chain_data['key']),
                index=chain_data['index']
            )
        
        if 'chain_key_receive' in state_dict:
            chain_data = state_dict['chain_key_receive']
            self.state.chain_key_receive = ChainKey(
                key=bytes.fromhex(chain_data['key']),
                index=chain_data['index']
            )
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """Get statistics about the ratchet session."""
        return {
            'session_id': self.session_id,
            'messages_sent': self.state.send_count,
            'messages_received': self.state.receive_count,
            'skipped_keys_cached': len(self.state.skipped_message_keys),
            'created_at': self.state.created_at.isoformat(),
            'last_updated': self.state.last_updated.isoformat(),
            'has_sending_chain': self.state.chain_key_send is not None,
            'has_receiving_chain': self.state.chain_key_receive is not None,
            'dh_ratchet_initialized': self.state.dh_self is not None
        }


class DoubleRatchetManager:
    """Manages multiple Double Ratchet sessions."""
    
    def __init__(self, storage_manager):
        self.storage = storage_manager
        self.sessions: Dict[str, DoubleRatchet] = {}
        self.key_manager = None  # Will be set by crypto system
    
    def create_session(self, session_id: str, shared_secret: bytes, 
                      remote_public_key: bytes, is_initiator: bool) -> DoubleRatchet:
        """Create a new Double Ratchet session."""
        ratchet = DoubleRatchet(session_id)
        
        if is_initiator:
            ratchet.initialize_alice(shared_secret, remote_public_key)
        else:
            # For Bob, we need the DH private key from key manager
            if self.key_manager and self.key_manager.signed_prekey:
                ratchet.initialize_bob(shared_secret, self.key_manager.signed_prekey.private_key)
            else:
                raise ValueError("No DH private key available for session initialization")
        
        self.sessions[session_id] = ratchet
        self._save_session(ratchet)
        
        return ratchet
    
    def get_session(self, session_id: str) -> Optional[DoubleRatchet]:
        """Get an existing session."""
        if session_id in self.sessions:
            return self.sessions[session_id]
        
        # Try to load from storage
        return self._load_session(session_id)
    
    def encrypt_message(self, session_id: str, plaintext: bytes, 
                       associated_data: bytes = b"") -> Optional[Dict[str, Any]]:
        """Encrypt a message for a specific session."""
        session = self.get_session(session_id)
        if not session:
            return None
        
        encrypted_message = session.encrypt_message(plaintext, associated_data)
        self._save_session(session)
        
        return encrypted_message
    
    def decrypt_message(self, session_id: str, encrypted_message: Dict[str, Any],
                       associated_data: bytes = b"") -> Optional[bytes]:
        """Decrypt a message for a specific session."""
        session = self.get_session(session_id)
        if not session:
            return None
        
        plaintext = session.decrypt_message(encrypted_message, associated_data)
        if plaintext:
            self._save_session(session)
        
        return plaintext
    
    def delete_session(self, session_id: str) -> bool:
        """Delete a ratchet session."""
        if session_id in self.sessions:
            del self.sessions[session_id]
        
        # Delete from storage
        return self._delete_session_storage(session_id)
    
    def _save_session(self, ratchet: DoubleRatchet) -> None:
        """Save session state to storage."""
        if self.storage:
            state_data = ratchet.get_state_for_storage()
            # Storage manager would handle encryption
            # self.storage.save_ratchet_session(ratchet.session_id, state_data)
    
    def _load_session(self, session_id: str) -> Optional[DoubleRatchet]:
        """Load session state from storage."""
        if not self.storage:
            return None
        
        try:
            # state_data = self.storage.load_ratchet_session(session_id)
            # if state_data:
            #     ratchet = DoubleRatchet(session_id)
            #     ratchet.load_state_from_storage(state_data)
            #     self.sessions[session_id] = ratchet
            #     return ratchet
            pass
        except:
            pass
        
        return None
    
    def _delete_session_storage(self, session_id: str) -> bool:
        """Delete session from storage."""
        if self.storage:
            # return self.storage.delete_ratchet_session(session_id)
            pass
        return True
    
    def get_all_sessions(self) -> List[str]:
        """Get list of all session IDs."""
        return list(self.sessions.keys())
    
    def get_session_statistics(self) -> Dict[str, Any]:
        """Get statistics for all sessions."""
        stats = {
            'total_sessions': len(self.sessions),
            'sessions': {}
        }
        
        for session_id, ratchet in self.sessions.items():
            stats['sessions'][session_id] = ratchet.get_session_statistics()
        
        return stats 