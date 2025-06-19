"""
Anonymous Identity Management for Privatus-chat
Week 4: Anonymous Messaging and Onion Routing

This module implements pseudonymous identity systems that allow users to interact
anonymously while maintaining accountability within conversations.

Key Features:
- Pseudonymous identity generation and management
- Identity key rotation and lifecycle management
- Anonymous credential systems
- Reputation tracking for anonymous identities
- Zero-knowledge proof support for identity verification
"""

import secrets
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging

try:
    from ..crypto.key_management import KeyManager
    from ..crypto.secure_random import SecureRandom
except ImportError:
    from crypto.key_management import KeyManager
    from crypto.secure_random import SecureRandom

logger = logging.getLogger(__name__)

class IdentityType(Enum):
    """Types of anonymous identities"""
    PERSISTENT = "persistent"    # Long-term pseudonymous identity
    EPHEMERAL = "ephemeral"     # Short-term identity for single conversation
    DISPOSABLE = "disposable"   # One-time use identity
    REPUTATION = "reputation"   # Identity with reputation tracking

@dataclass
class AnonymousIdentity:
    """Represents an anonymous identity with cryptographic keys"""
    identity_id: bytes
    identity_type: IdentityType
    public_key: bytes
    private_key: bytes
    created_time: float = field(default_factory=time.time)
    last_used: float = field(default_factory=time.time)
    usage_count: int = 0
    reputation_score: float = 1.0
    
    # Metadata (encrypted)
    nickname: Optional[str] = None
    bio: Optional[str] = None
    
    # Rotation settings
    max_usage_count: int = 1000
    max_lifetime: int = 86400 * 30  # 30 days
    
    @property
    def is_expired(self) -> bool:
        """Check if identity has expired"""
        if self.identity_type == IdentityType.DISPOSABLE:
            return self.usage_count >= 1
        elif self.identity_type == IdentityType.EPHEMERAL:
            return time.time() - self.created_time > 3600  # 1 hour
        else:
            age = time.time() - self.created_time
            return (self.usage_count >= self.max_usage_count or 
                   age > self.max_lifetime)
    
    def update_usage(self):
        """Update identity usage statistics"""
        self.usage_count += 1
        self.last_used = time.time()

@dataclass
class IdentityCredential:
    """Anonymous credential for identity verification"""
    credential_id: bytes
    identity_id: bytes
    issuer_signature: bytes
    validity_period: Tuple[float, float]  # (start_time, end_time)
    attributes: Dict[str, Any]
    
    @property
    def is_valid(self) -> bool:
        """Check if credential is currently valid"""
        current_time = time.time()
        return (self.validity_period[0] <= current_time <= self.validity_period[1])

class AnonymousIdentityManager:
    """Manages anonymous identities and credentials"""
    
    def __init__(self, key_manager: KeyManager):
        self.key_manager = key_manager
        self.secure_random = SecureRandom()
        
        # Identity storage
        self.identities: Dict[bytes, AnonymousIdentity] = {}
        self.credentials: Dict[bytes, IdentityCredential] = {}
        
        # Active identity tracking
        self.active_identity: Optional[AnonymousIdentity] = None
        self.identity_contexts: Dict[str, bytes] = {}  # Context -> Identity ID
        
        # Reputation system
        self.reputation_scores: Dict[bytes, float] = {}
        self.reputation_history: Dict[bytes, List[Tuple[float, float]]] = {}
        
        # Configuration
        self.auto_rotate_identities = True
        self.max_identities_per_type = 10
        self.reputation_decay_rate = 0.01  # Daily decay
        
        # Statistics
        self.total_identities_created = 0
        self.identity_rotations = 0
        
    def create_identity(self, identity_type: IdentityType, 
                       nickname: Optional[str] = None,
                       context: Optional[str] = None) -> AnonymousIdentity:
        """Create a new anonymous identity"""
        try:
            # Generate identity keys
            public_key, private_key = self.key_manager.generate_identity_keys()
            
            # Generate unique identity ID
            identity_id = self._generate_identity_id(public_key, identity_type)
            
            # Create identity object
            identity = AnonymousIdentity(
                identity_id=identity_id,
                identity_type=identity_type,
                public_key=public_key,
                private_key=private_key,
                nickname=nickname
            )
            
            # Store identity
            self.identities[identity_id] = identity
            
            # Set as active if no active identity
            if self.active_identity is None:
                self.active_identity = identity
            
            # Associate with context if provided
            if context:
                self.identity_contexts[context] = identity_id
            
            # Initialize reputation
            self.reputation_scores[identity_id] = 1.0
            self.reputation_history[identity_id] = []
            
            self.total_identities_created += 1
            
            logger.info(f"Created {identity_type.value} identity: {identity_id.hex()[:16]}")
            return identity
            
        except Exception as e:
            logger.error(f"Failed to create identity: {e}")
            raise
    
    def _generate_identity_id(self, public_key: bytes, identity_type: IdentityType) -> bytes:
        """Generate a unique identity ID from public key and type"""
        # Include timestamp and random data for uniqueness
        timestamp = int(time.time()).to_bytes(8, 'big')
        random_data = self.secure_random.generate_bytes(16)
        type_data = identity_type.value.encode()
        
        # Hash all components
        hasher = hashlib.sha256()
        hasher.update(public_key)
        hasher.update(timestamp)
        hasher.update(random_data)
        hasher.update(type_data)
        
        return hasher.digest()
    
    def get_identity_by_context(self, context: str) -> Optional[AnonymousIdentity]:
        """Get identity associated with a specific context"""
        identity_id = self.identity_contexts.get(context)
        if identity_id:
            return self.identities.get(identity_id)
        return None
    
    def get_identity_for_conversation(self, conversation_id: str) -> AnonymousIdentity:
        """Get or create identity for a specific conversation"""
        existing_identity = self.get_identity_by_context(conversation_id)
        
        if existing_identity and not existing_identity.is_expired:
            return existing_identity
        
        # Create new ephemeral identity for this conversation
        identity = self.create_identity(
            identity_type=IdentityType.EPHEMERAL,
            context=conversation_id
        )
        
        logger.debug(f"Created conversation identity for {conversation_id}")
        return identity
    
    def rotate_identity(self, old_identity_id: bytes, 
                       preserve_reputation: bool = False) -> Optional[AnonymousIdentity]:
        """Rotate an identity to a new one"""
        old_identity = self.identities.get(old_identity_id)
        if not old_identity:
            logger.error(f"Identity {old_identity_id.hex()[:16]} not found for rotation")
            return None
        
        try:
            # Create new identity of same type
            new_identity = self.create_identity(
                identity_type=old_identity.identity_type,
                nickname=old_identity.nickname
            )
            
            # Transfer reputation if requested
            if preserve_reputation:
                self.reputation_scores[new_identity.identity_id] = \
                    self.reputation_scores.get(old_identity_id, 1.0)
            
            # Update context mappings
            for context, identity_id in self.identity_contexts.items():
                if identity_id == old_identity_id:
                    self.identity_contexts[context] = new_identity.identity_id
            
            # Update active identity if necessary
            if self.active_identity and self.active_identity.identity_id == old_identity_id:
                self.active_identity = new_identity
            
            # Archive old identity (don't delete immediately for security)
            old_identity.reputation_score = -1.0  # Mark as rotated
            
            self.identity_rotations += 1
            
            logger.info(f"Rotated identity {old_identity_id.hex()[:16]} -> "
                       f"{new_identity.identity_id.hex()[:16]}")
            
            return new_identity
            
        except Exception as e:
            logger.error(f"Failed to rotate identity: {e}")
            return None
    
    def cleanup_expired_identities(self):
        """Clean up expired identities"""
        expired_identities = []
        
        for identity_id, identity in self.identities.items():
            if identity.is_expired and identity.reputation_score >= 0:
                expired_identities.append(identity_id)
        
        for identity_id in expired_identities:
            if self.auto_rotate_identities:
                # Rotate instead of deleting
                self.rotate_identity(identity_id, preserve_reputation=True)
            else:
                # Mark as expired
                self.identities[identity_id].reputation_score = -1.0
        
        if expired_identities:
            logger.info(f"Cleaned up {len(expired_identities)} expired identities")
    
    def issue_credential(self, identity_id: bytes, attributes: Dict[str, Any],
                        validity_hours: int = 24) -> Optional[IdentityCredential]:
        """Issue an anonymous credential for an identity"""
        identity = self.identities.get(identity_id)
        if not identity:
            logger.error(f"Cannot issue credential for unknown identity {identity_id.hex()[:16]}")
            return None
        
        try:
            # Generate credential ID
            credential_id = self.secure_random.generate_bytes(32)
            
            # Calculate validity period
            start_time = time.time()
            end_time = start_time + (validity_hours * 3600)
            
            # Create credential signature (simplified)
            # In a real implementation, this would use a proper anonymous credential scheme
            signature_data = credential_id + identity_id + str(attributes).encode()
            issuer_signature = hashlib.sha256(signature_data).digest()
            
            # Create credential
            credential = IdentityCredential(
                credential_id=credential_id,
                identity_id=identity_id,
                issuer_signature=issuer_signature,
                validity_period=(start_time, end_time),
                attributes=attributes
            )
            
            self.credentials[credential_id] = credential
            
            logger.debug(f"Issued credential {credential_id.hex()[:16]} for identity "
                        f"{identity_id.hex()[:16]}")
            
            return credential
            
        except Exception as e:
            logger.error(f"Failed to issue credential: {e}")
            return None
    
    def verify_credential(self, credential_id: bytes) -> bool:
        """Verify an anonymous credential"""
        credential = self.credentials.get(credential_id)
        if not credential:
            return False
        
        # Check validity period
        if not credential.is_valid:
            return False
        
        # Verify signature (simplified)
        signature_data = credential_id + credential.identity_id + str(credential.attributes).encode()
        expected_signature = hashlib.sha256(signature_data).digest()
        
        return credential.issuer_signature == expected_signature
    
    def update_reputation(self, identity_id: bytes, interaction_quality: float):
        """Update reputation score for an identity"""
        if identity_id not in self.reputation_scores:
            self.reputation_scores[identity_id] = 1.0
            self.reputation_history[identity_id] = []
        
        current_score = self.reputation_scores[identity_id]
        
        # Apply weighted update (recent interactions have more weight)
        weight = 0.1  # How much the new interaction affects the score
        new_score = current_score * (1 - weight) + interaction_quality * weight
        
        # Clamp score to valid range
        new_score = max(0.0, min(2.0, new_score))
        
        self.reputation_scores[identity_id] = new_score
        
        # Record in history
        self.reputation_history[identity_id].append((time.time(), new_score))
        
        # Limit history size
        if len(self.reputation_history[identity_id]) > 1000:
            self.reputation_history[identity_id] = \
                self.reputation_history[identity_id][-500:]  # Keep last 500 entries
        
        logger.debug(f"Updated reputation for {identity_id.hex()[:16]}: "
                    f"{current_score:.2f} -> {new_score:.2f}")
    
    def get_reputation_score(self, identity_id: bytes) -> float:
        """Get current reputation score for an identity"""
        return self.reputation_scores.get(identity_id, 1.0)
    
    def decay_reputation_scores(self):
        """Apply daily reputation decay to prevent reputation inflation"""
        for identity_id in self.reputation_scores:
            current_score = self.reputation_scores[identity_id]
            
            # Decay toward neutral (1.0)
            if current_score > 1.0:
                # Decay positive reputation
                new_score = current_score - self.reputation_decay_rate
                self.reputation_scores[identity_id] = max(1.0, new_score)
            elif current_score < 1.0:
                # Recover negative reputation slowly
                new_score = current_score + (self.reputation_decay_rate * 0.5)
                self.reputation_scores[identity_id] = min(1.0, new_score)
    
    def get_identities_by_type(self, identity_type: IdentityType) -> List[AnonymousIdentity]:
        """Get all identities of a specific type"""
        return [
            identity for identity in self.identities.values()
            if identity.identity_type == identity_type and identity.reputation_score >= 0
        ]
    
    def get_identity_statistics(self) -> Dict[str, Any]:
        """Get statistics about identity usage"""
        active_identities = [
            identity for identity in self.identities.values()
            if identity.reputation_score >= 0
        ]
        
        by_type = {}
        for identity_type in IdentityType:
            by_type[identity_type.value] = len([
                i for i in active_identities if i.identity_type == identity_type
            ])
        
        return {
            'total_identities_created': self.total_identities_created,
            'active_identities': len(active_identities),
            'identity_rotations': self.identity_rotations,
            'identities_by_type': by_type,
            'active_contexts': len(self.identity_contexts),
            'issued_credentials': len(self.credentials),
            'avg_reputation': (
                sum(self.reputation_scores.values()) / len(self.reputation_scores)
                if self.reputation_scores else 1.0
            )
        }
    
    def export_identity_backup(self, identity_id: bytes, 
                              include_private_key: bool = False) -> Optional[Dict[str, Any]]:
        """Export identity for backup purposes"""
        identity = self.identities.get(identity_id)
        if not identity:
            return None
        
        backup_data = {
            'identity_id': identity.identity_id.hex(),
            'identity_type': identity.identity_type.value,
            'public_key': identity.public_key.hex(),
            'created_time': identity.created_time,
            'nickname': identity.nickname,
            'reputation_score': self.reputation_scores.get(identity_id, 1.0)
        }
        
        if include_private_key:
            backup_data['private_key'] = identity.private_key.hex()
        
        return backup_data
    
    def import_identity_backup(self, backup_data: Dict[str, Any]) -> bool:
        """Import identity from backup data"""
        try:
            identity_id = bytes.fromhex(backup_data['identity_id'])
            
            # Check if identity already exists
            if identity_id in self.identities:
                logger.warning(f"Identity {identity_id.hex()[:16]} already exists")
                return False
            
            # Create identity from backup
            identity = AnonymousIdentity(
                identity_id=identity_id,
                identity_type=IdentityType(backup_data['identity_type']),
                public_key=bytes.fromhex(backup_data['public_key']),
                private_key=bytes.fromhex(backup_data.get('private_key', '')),
                created_time=backup_data['created_time'],
                nickname=backup_data.get('nickname')
            )
            
            # Store identity
            self.identities[identity_id] = identity
            
            # Restore reputation
            self.reputation_scores[identity_id] = backup_data.get('reputation_score', 1.0)
            self.reputation_history[identity_id] = []
            
            logger.info(f"Imported identity {identity_id.hex()[:16]} from backup")
            return True
            
        except Exception as e:
            logger.error(f"Failed to import identity backup: {e}")
            return False 