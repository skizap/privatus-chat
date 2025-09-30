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
    """Manages group keys and key rotation with forward secrecy."""

    def __init__(self):
        self.group_keys: Dict[str, GroupKey] = {}  # group_id -> current key
        self.key_history: Dict[str, List[GroupKey]] = {}  # group_id -> key history
        self.member_shares: Dict[str, Dict[str, GroupKeyShare]] = {}  # group_id -> member_id -> share
        self.pending_key_updates: Dict[str, Dict[str, bytes]] = {}  # group_id -> member_id -> encrypted_new_key
        self.key_epochs: Dict[str, int] = {}  # group_id -> current epoch
        self.compromised_keys: Set[str] = set()  # Track compromised key IDs
        
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
        """Revoke a member's access by removing their key share and rotating keys."""
        if group_id in self.member_shares and member_id in self.member_shares[group_id]:
            del self.member_shares[group_id][member_id]

            # Immediately rotate the group key for forward secrecy
            self.rotate_group_key(group_id, "system_revoke")

            # Mark the old key as compromised
            if group_id in self.group_keys:
                old_key = self.group_keys[group_id]
                if old_key.version > 1:  # Don't mark initial key as compromised
                    self.compromised_keys.add(old_key.key_id)

            return True
        return False

    def add_member_with_key_update(self, group_id: str, new_member_id: str,
                                 new_member_public_key: str) -> bool:
        """Add a new member and update group keys for all members."""
        if group_id not in self.group_keys:
            return False

        # Rotate to a new key that includes the new member
        new_key = self.rotate_group_key(group_id, "system_add_member")
        if not new_key:
            return False

        # Get all current members plus the new one
        current_members = list(self.member_shares.get(group_id, {}).keys())
        current_members.append(new_member_id)

        # Redistribute shares to all members including the new one
        return self.distribute_key_shares(group_id, current_members)

    def handle_key_compromise(self, group_id: str, compromised_key_id: str) -> bool:
        """Handle a key compromise by emergency rotation."""
        if group_id not in self.group_keys:
            return False

        current_key = self.group_keys[group_id]
        if current_key.key_id == compromised_key_id:
            # Emergency rotation
            new_key = self.rotate_group_key(group_id, "system_emergency")
            self.compromised_keys.add(compromised_key_id)

            # Redistribute to all members
            members = list(self.member_shares.get(group_id, {}).keys())
            return self.distribute_key_shares(group_id, members)

        return False

    def schedule_key_rotation(self, group_id: str, max_age_hours: int = 24) -> bool:
        """Schedule automatic key rotation based on age."""
        if group_id not in self.group_keys:
            return False

        current_key = self.group_keys[group_id]
        age_hours = (datetime.now() - current_key.created_at).total_seconds() / 3600

        if age_hours >= max_age_hours:
            return bool(self.rotate_group_key(group_id, "system_scheduled"))

        return False

    def get_key_epoch(self, group_id: str) -> int:
        """Get the current key epoch for a group."""
        return self.key_epochs.get(group_id, 0)

    def validate_key_freshness(self, group_id: str, key_version: int) -> bool:
        """Validate that a key version is still fresh (not compromised)."""
        if group_id not in self.group_keys:
            return False

        current_key = self.group_keys[group_id]

        # Check if this version is compromised
        key_id_to_check = f"{group_id}_{key_version}_"
        for compromised_id in self.compromised_keys:
            if compromised_id.startswith(key_id_to_check):
                return False

        return key_version <= current_key.version

    def get_key_rotation_stats(self, group_id: str) -> Dict:
        """Get key rotation statistics for a group."""
        if group_id not in self.key_history:
            return {}

        history = self.key_history[group_id]
        if not history:
            return {}

        rotations = len(history) - 1  # Subtract 1 for initial key
        avg_rotation_interval = 0

        if rotations > 0:
            intervals = []
            for i in range(1, len(history)):
                interval = (history[i].created_at - history[i-1].created_at).total_seconds()
                intervals.append(interval)

            if intervals:
                avg_rotation_interval = sum(intervals) / len(intervals)

        return {
            'total_rotations': rotations,
            'current_epoch': self.get_key_epoch(group_id),
            'avg_rotation_interval_hours': avg_rotation_interval / 3600,
            'oldest_key_age_hours': (datetime.now() - history[0].created_at).total_seconds() / 3600,
            'newest_key_age_hours': (datetime.now() - history[-1].created_at).total_seconds() / 3600,
            'compromised_keys': len([k for k in self.compromised_keys if k.startswith(group_id)])
        }


class GroupCryptography:
    """Handles group message encryption and decryption."""
    
    def __init__(self, key_manager: GroupKeyManager):
        self.key_manager = key_manager
        self.message_encryption = MessageEncryption()
        
    def encrypt_group_message(self, group_id: str, sender_id: str, message: str,
                            message_id: str) -> Optional[Tuple[bytes, bytes]]:
        """Encrypt a message for the group with authentication."""
        group_key = self.key_manager.get_group_key(group_id)
        sender_share = self.key_manager.get_member_share(group_id, sender_id)

        if not group_key or not sender_share:
            return None

        # Derive message-specific key for forward secrecy
        message_key = group_key.derive_message_key(message_id)

        # Create message with enhanced metadata
        message_data = {
            'content': message,
            'sender_id': sender_id,
            'group_id': group_id,
            'key_version': group_key.version,
            'epoch': self.key_manager.get_key_epoch(group_id),
            'timestamp': datetime.now().isoformat(),
            'message_id': message_id
        }

        # Serialize message data
        message_bytes = str(message_data).encode()

        # Encrypt the message
        try:
            encrypted_data = self.message_encryption.encrypt_message(message_bytes, message_key)

            # Create signature using sender's key share
            signature = hmac.new(
                sender_share.key_share,
                encrypted_data,
                hashlib.sha256
            ).digest()

            return encrypted_data, signature
        except Exception:
            return None
            
    def decrypt_group_message(self, group_id: str, encrypted_message: bytes,
                            message_id: str, signature: Optional[bytes] = None,
                            sender_id: Optional[str] = None) -> Optional[Dict]:
        """Decrypt a group message with integrity verification."""
        group_key = self.key_manager.get_group_key(group_id)
        if not group_key:
            return None

        # Verify key freshness
        if not self.key_manager.validate_key_freshness(group_id, group_key.version):
            return None

        # Derive the same message-specific key
        message_key = group_key.derive_message_key(message_id)

        try:
            decrypted_data = self.message_encryption.decrypt_message(
                encrypted_message,
                message_key
            )

            # Verify signature if provided
            if signature and sender_id:
                if not self.authenticate_group_message(group_id, sender_id, encrypted_message, signature):
                    return None

            # Parse the message data
            # In production, use proper JSON parsing with validation
            message_str = decrypted_data.decode()

            # Extract metadata from decrypted content
            # Simplified parsing - in production, use secure JSON parsing
            try:
                # This is a simplified extraction - in production, parse JSON properly
                metadata_start = message_str.find("'sender_id': '") + len("'sender_id': '")
                metadata_end = message_str.find("'", metadata_start)
                extracted_sender = message_str[metadata_start:metadata_end] if metadata_end > metadata_start else sender_id

                content_start = message_str.find("'content': '") + len("'content': '")
                content_end = message_str.find("'", content_start)
                content = message_str[content_start:content_end] if content_end > content_start else message_str

                return {
                    'content': content,
                    'sender_id': extracted_sender or sender_id,
                    'decrypted': True,
                    'key_version': group_key.version,
                    'epoch': self.key_manager.get_key_epoch(group_id)
                }
            except Exception:
                # Fallback for parsing errors
                return {'content': message_str, 'decrypted': True}

        except Exception:
            return None
            
    def authenticate_group_message(self, group_id: str, sender_id: str,
                                 message_data: bytes, signature: Optional[bytes] = None) -> bool:
        """Authenticate that a message is from a valid group member with signature verification."""
        # Check if sender has valid key share
        sender_share = self.key_manager.get_member_share(group_id, sender_id)
        if not sender_share:
            return False

        # Verify key freshness
        group_key = self.key_manager.get_group_key(group_id)
        if not group_key:
            return False

        # In production, verify signature using sender's public key
        # For now, implement basic HMAC authentication using member's key share
        if signature:
            expected_signature = hmac.new(
                sender_share.key_share,
                message_data,
                hashlib.sha256
            ).digest()

            if not hmac.compare_digest(signature, expected_signature):
                return False

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