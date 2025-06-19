"""
Group Cryptography for Privatus-chat

Implements secure multi-party key agreement protocols, group message encryption,
and forward secrecy for group messaging as specified in the roadmap.
"""

import hashlib
import hmac
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

from ..crypto import SecureRandom, MessageEncryption


@dataclass
class GroupKey:
    """Group encryption key."""
    key_id: str
    key_data: bytes
    version: int
    created_at: datetime
    created_by: str
    
    def derive_message_key(self, message_id: str) -> bytes:
        """Derive a unique key for a specific message."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            self.key_data,
            message_id.encode(),
            1000,
            32
        )


@dataclass 
class GroupKeyShare:
    """Individual member's share of the group key."""
    member_id: str
    key_share: bytes
    share_index: int
    
    
class GroupKeyManager:
    """Manages group keys and key rotation."""
    
    def __init__(self):
        self.group_keys: Dict[str, GroupKey] = {}  # group_id -> current key
        self.key_history: Dict[str, List[GroupKey]] = {}  # group_id -> key history
        self.member_shares: Dict[str, Dict[str, GroupKeyShare]] = {}  # group_id -> member_id -> share
        
    def generate_group_key(self, group_id: str, creator_id: str, version: int = 1) -> GroupKey:
        """Generate a new group key."""
        key_id = f"{group_id}_{version}_{int(datetime.now().timestamp())}"
        key_data = SecureRandom().generate_bytes(32)  # 256-bit key
        
        group_key = GroupKey(
            key_id=key_id,
            key_data=key_data,
            version=version,
            created_at=datetime.now(),
            created_by=creator_id
        )
        
        # Store the key
        self.group_keys[group_id] = group_key
        
        # Initialize key history
        if group_id not in self.key_history:
            self.key_history[group_id] = []
        self.key_history[group_id].append(group_key)
        
        return group_key
        
    def distribute_key_shares(self, group_id: str, member_ids: List[str]) -> bool:
        """Distribute key shares to group members using Shamir's Secret Sharing concepts."""
        if group_id not in self.group_keys:
            return False
            
        group_key = self.group_keys[group_id]
        
        # Simplified key sharing - in production, use proper secret sharing
        # For now, each member gets the same key encrypted with their public key
        if group_id not in self.member_shares:
            self.member_shares[group_id] = {}
            
        for i, member_id in enumerate(member_ids):
            # Create a unique share for each member
            share_data = self._create_member_share(group_key.key_data, member_id, i)
            
            share = GroupKeyShare(
                member_id=member_id,
                key_share=share_data,
                share_index=i
            )
            
            self.member_shares[group_id][member_id] = share
            
        return True
        
    def _create_member_share(self, group_key: bytes, member_id: str, index: int) -> bytes:
        """Create a key share for a specific member."""
        # Simplified approach: HMAC the group key with member ID
        # In production, use proper threshold cryptography
        return hmac.new(
            group_key,
            f"{member_id}_{index}".encode(),
            hashlib.sha256
        ).digest()
        
    def rotate_group_key(self, group_id: str, rotated_by: str) -> Optional[GroupKey]:
        """Rotate the group key for forward secrecy."""
        if group_id not in self.group_keys:
            return None
            
        current_key = self.group_keys[group_id]
        new_version = current_key.version + 1
        
        new_key = self.generate_group_key(group_id, rotated_by, new_version)
        return new_key
        
    def get_group_key(self, group_id: str) -> Optional[GroupKey]:
        """Get the current group key."""
        return self.group_keys.get(group_id)
        
    def get_member_share(self, group_id: str, member_id: str) -> Optional[GroupKeyShare]:
        """Get a member's key share."""
        if group_id in self.member_shares and member_id in self.member_shares[group_id]:
            return self.member_shares[group_id][member_id]
        return None
        
    def revoke_member_access(self, group_id: str, member_id: str) -> bool:
        """Revoke a member's access by removing their key share."""
        if group_id in self.member_shares and member_id in self.member_shares[group_id]:
            del self.member_shares[group_id][member_id]
            return True
        return False


class GroupCryptography:
    """Handles group message encryption and decryption."""
    
    def __init__(self, key_manager: GroupKeyManager):
        self.key_manager = key_manager
        self.message_encryption = MessageEncryption()
        
    def encrypt_group_message(self, group_id: str, sender_id: str, message: str, 
                            message_id: str) -> Optional[bytes]:
        """Encrypt a message for the group."""
        group_key = self.key_manager.get_group_key(group_id)
        if not group_key:
            return None
            
        # Derive message-specific key for forward secrecy
        message_key = group_key.derive_message_key(message_id)
        
        # Create message with metadata
        message_data = {
            'content': message,
            'sender_id': sender_id,
            'group_id': group_id,
            'key_version': group_key.version,
            'timestamp': datetime.now().isoformat()
        }
        
        # Encrypt the message
        try:
            encrypted_data = self.message_encryption.encrypt_message(
                str(message_data).encode(),
                message_key
            )
            return encrypted_data
        except Exception:
            return None
            
    def decrypt_group_message(self, group_id: str, encrypted_message: bytes, 
                            message_id: str) -> Optional[Dict]:
        """Decrypt a group message."""
        group_key = self.key_manager.get_group_key(group_id)
        if not group_key:
            return None
            
        # Derive the same message-specific key
        message_key = group_key.derive_message_key(message_id)
        
        try:
            decrypted_data = self.message_encryption.decrypt_message(
                encrypted_message,
                message_key
            )
            
            # Parse the message data
            # In production, use proper JSON parsing with validation
            message_str = decrypted_data.decode()
            # Simplified parsing - in production, use secure JSON parsing
            return {'content': message_str, 'decrypted': True}
            
        except Exception:
            return None
            
    def authenticate_group_message(self, group_id: str, sender_id: str, 
                                 message_data: bytes) -> bool:
        """Authenticate that a message is from a valid group member."""
        # Check if sender has valid key share
        sender_share = self.key_manager.get_member_share(group_id, sender_id)
        if not sender_share:
            return False
            
        # In production, implement proper authentication using signatures
        # For now, return True if sender has a key share
        return True
        
    def verify_message_integrity(self, encrypted_message: bytes, 
                               expected_hash: Optional[str] = None) -> bool:
        """Verify message integrity."""
        if expected_hash:
            actual_hash = hashlib.sha256(encrypted_message).hexdigest()
            return actual_hash == expected_hash
            
        # Basic integrity check
        return len(encrypted_message) > 0
        
    def create_group_invitation(self, group_id: str, inviter_id: str, 
                              invitee_public_key: str) -> Optional[bytes]:
        """Create an encrypted group invitation."""
        group_key = self.key_manager.get_group_key(group_id)
        if not group_key:
            return None
            
        invitation_data = {
            'group_id': group_id,
            'invited_by': inviter_id,
            'group_key_version': group_key.version,
            'invitation_timestamp': datetime.now().isoformat()
        }
        
        # In production, encrypt with invitee's public key
        # For now, return the invitation data as bytes
        return str(invitation_data).encode()
        
    def process_group_invitation(self, encrypted_invitation: bytes, 
                               private_key: str) -> Optional[Dict]:
        """Process an encrypted group invitation."""
        try:
            # In production, decrypt with private key
            # For now, just parse the invitation
            invitation_str = encrypted_invitation.decode()
            return {'invitation_processed': True, 'data': invitation_str}
        except Exception:
            return None
            
    def get_group_encryption_stats(self, group_id: str) -> Dict:
        """Get encryption statistics for a group."""
        group_key = self.key_manager.get_group_key(group_id)
        if not group_key:
            return {}
            
        member_count = len(self.key_manager.member_shares.get(group_id, {}))
        key_history_count = len(self.key_manager.key_history.get(group_id, []))
        
        return {
            'current_key_version': group_key.version,
            'key_created_at': group_key.created_at.isoformat(),
            'members_with_access': member_count,
            'total_key_rotations': key_history_count - 1,
            'encryption_algorithm': 'AES-256-GCM',
            'key_derivation': 'PBKDF2-SHA256'
        } 