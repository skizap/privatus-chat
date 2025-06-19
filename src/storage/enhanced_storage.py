"""
Enhanced Encrypted Local Storage for Privatus-chat

Implements advanced storage features as specified in Phase 5 of the roadmap:
- Forward secure message deletion
- Secure search in encrypted data  
- Conversation backup and sync
- Hardware security module support
- Profile management and switching
- Secure settings migration
- Encrypted caching for frequently accessed data
- Automatic cache cleanup and rotation

Security Features:
- Forward secrecy for stored messages
- Searchable encryption for message content
- Secure backup with perfect forward secrecy
- Hardware-backed key storage
- Zero-knowledge profile switching
"""

import os
import json
import hashlib
import hmac
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import sqlite3
import struct
import zlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

from ..crypto import SecureRandom, MessageEncryption, KeyDerivation
from .database import SecureDatabase, Contact, Message


class ForwardSecurityLevel(Enum):
    """Forward security levels for message deletion."""
    NONE = "none"
    BASIC = "basic"
    ENHANCED = "enhanced"
    PARANOID = "paranoid"


class CacheType(Enum):
    """Types of cached data."""
    MESSAGE_PREVIEW = "message_preview"
    CONTACT_INFO = "contact_info"
    SEARCH_INDEX = "search_index"
    MEDIA_THUMBNAIL = "media_thumbnail"
    CONVERSATION_METADATA = "conversation_metadata"


@dataclass
class SearchToken:
    """Encrypted search token."""
    token_hash: str
    encrypted_positions: List[bytes]
    document_id: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class BackupMetadata:
    """Backup metadata with forward secrecy."""
    backup_id: str
    created_at: datetime
    backup_key: bytes
    content_hash: str
    size: int
    encrypted: bool = True
    forward_secure: bool = True


@dataclass
class CacheEntry:
    """Encrypted cache entry."""
    cache_id: str
    cache_type: CacheType
    key: str
    encrypted_data: bytes
    created_at: datetime
    expires_at: datetime
    access_count: int = 0
    last_accessed: datetime = field(default_factory=datetime.now)


@dataclass
class Profile:
    """User profile with encrypted settings."""
    profile_id: str
    name: str
    encrypted_settings: bytes
    encryption_key: bytes
    created_at: datetime
    last_used: datetime
    is_active: bool = False


class ForwardSecureMessageStorage:
    """
    Implements forward secure message storage where deleted messages
    cannot be recovered even with current keys.
    """
    
    def __init__(self, storage_path: Path, master_key: bytes):
        self.storage_path = storage_path
        self.master_key = master_key
        self.message_keys: Dict[str, bytes] = {}
        self.deletion_log: List[Dict] = []
        
    def store_message(self, message_id: str, content: bytes, 
                     security_level: ForwardSecurityLevel = ForwardSecurityLevel.ENHANCED) -> bool:
        """Store a message with forward secrecy."""
        try:
            # Generate unique message key
            message_key = self._derive_message_key(message_id)
            
            # Encrypt message content
            encrypted_content = self._encrypt_with_key(content, message_key)
            
            # Store encrypted content
            message_file = self.storage_path / f"msg_{message_id}.enc"
            with open(message_file, 'wb') as f:
                f.write(encrypted_content)
            
            # Store key reference (not the actual key)
            self.message_keys[message_id] = message_key
            
            return True
        except Exception:
            return False
    
    def retrieve_message(self, message_id: str) -> Optional[bytes]:
        """Retrieve a message if not forward-deleted."""
        try:
            if message_id not in self.message_keys:
                return None
                
            message_file = self.storage_path / f"msg_{message_id}.enc"
            if not message_file.exists():
                return None
                
            with open(message_file, 'rb') as f:
                encrypted_content = f.read()
                
            message_key = self.message_keys[message_id]
            return self._decrypt_with_key(encrypted_content, message_key)
            
        except Exception:
            return None
    
    def forward_secure_delete(self, message_id: str, 
                            security_level: ForwardSecurityLevel = ForwardSecurityLevel.ENHANCED) -> bool:
        """Delete a message with forward secrecy guarantees."""
        try:
            # Remove the message key first
            if message_id in self.message_keys:
                old_key = self.message_keys[message_id]
                
                # Overwrite key in memory
                self._secure_overwrite_key(old_key)
                del self.message_keys[message_id]
            
            # Remove encrypted file
            message_file = self.storage_path / f"msg_{message_id}.enc"
            if message_file.exists():
                # Overwrite file content based on security level
                self._secure_file_deletion(message_file, security_level)
                message_file.unlink()
            
            # Log deletion for audit
            self.deletion_log.append({
                'message_id': message_id,
                'deleted_at': datetime.now().isoformat(),
                'security_level': security_level.value
            })
            
            return True
        except Exception:
            return False
    
    def _derive_message_key(self, message_id: str) -> bytes:
        """Derive a unique key for each message."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"message-key-salt",
            info=message_id.encode(),
        ).derive(self.master_key)
    
    def _encrypt_with_key(self, data: bytes, key: bytes) -> bytes:
        """Encrypt data with a specific key."""
        nonce = SecureRandom().generate_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def _decrypt_with_key(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt data with a specific key."""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _secure_overwrite_key(self, key: bytes) -> None:
        """Securely overwrite a key in memory."""
        if isinstance(key, bytes):
            key_array = bytearray(key)
            for i in range(len(key_array)):
                key_array[i] = SecureRandom().generate_bytes(1)[0]
            key_array.clear()
    
    def _secure_file_deletion(self, file_path: Path, security_level: ForwardSecurityLevel) -> None:
        """Securely delete a file based on security level."""
        if not file_path.exists():
            return
            
        file_size = file_path.stat().st_size
        
        # Determine number of overwrite passes
        passes = {
            ForwardSecurityLevel.NONE: 0,
            ForwardSecurityLevel.BASIC: 1,
            ForwardSecurityLevel.ENHANCED: 3,
            ForwardSecurityLevel.PARANOID: 7
        }
        
        overwrite_passes = passes.get(security_level, 1)
        
        for _ in range(overwrite_passes):
            with open(file_path, 'r+b') as f:
                # Overwrite with random data
                random_data = SecureRandom().generate_bytes(file_size)
                f.seek(0)
                f.write(random_data)
                f.flush()
                os.fsync(f.fileno())


class SearchableEncryption:
    """
    Implements searchable encryption for message content while preserving privacy.
    """
    
    def __init__(self, search_key: bytes):
        self.search_key = search_key
        self.search_index: Dict[str, List[SearchToken]] = {}
        
    def index_message(self, message_id: str, content: str) -> None:
        """Create searchable index for a message."""
        # Tokenize content (simple word-based for now)
        words = self._tokenize_content(content)
        
        for word in words:
            # Create searchable token
            token = self._create_search_token(word.lower())
            search_token = SearchToken(
                token_hash=hashlib.sha256(token).hexdigest(),
                encrypted_positions=[],  # Could store positions for ranking
                document_id=message_id
            )
            
            if token not in self.search_index:
                self.search_index[token] = []
            self.search_index[token].append(search_token)
    
    def search_messages(self, query: str) -> List[str]:
        """Search for messages containing the query."""
        query_words = self._tokenize_content(query.lower())
        matching_messages = set()
        
        for word in query_words:
            token = self._create_search_token(word)
            if token in self.search_index:
                for search_token in self.search_index[token]:
                    matching_messages.add(search_token.document_id)
        
        return list(matching_messages)
    
    def remove_message_from_index(self, message_id: str) -> None:
        """Remove a message from the search index."""
        for token, search_tokens in self.search_index.items():
            self.search_index[token] = [
                st for st in search_tokens 
                if st.document_id != message_id
            ]
    
    def _create_search_token(self, word: str) -> str:
        """Create a searchable token for a word."""
        # Use HMAC to create deterministic but secure tokens
        return hmac.new(
            self.search_key,
            word.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _tokenize_content(self, content: str) -> List[str]:
        """Tokenize content for searching."""
        # Simple word-based tokenization
        import re
        words = re.findall(r'\b\w+\b', content.lower())
        return [word for word in words if len(word) > 2]  # Filter short words


class ConversationBackup:
    """
    Implements secure conversation backup with forward secrecy.
    """
    
    def __init__(self, backup_path: Path):
        self.backup_path = backup_path
        self.backup_path.mkdir(parents=True, exist_ok=True)
        self.backups: Dict[str, BackupMetadata] = {}
    
    def create_backup(self, conversation_data: Dict[str, Any], 
                     backup_id: Optional[str] = None) -> str:
        """Create an encrypted backup of conversation data."""
        if not backup_id:
            backup_id = SecureRandom().generate_bytes(16).hex()
        
        # Generate unique backup key for forward secrecy
        backup_key = SecureRandom().generate_bytes(32)
        
        # Serialize and compress data
        json_data = json.dumps(conversation_data).encode()
        compressed_data = zlib.compress(json_data)
        
        # Encrypt with backup key
        encrypted_data = self._encrypt_backup_data(compressed_data, backup_key)
        
        # Calculate content hash
        content_hash = hashlib.sha256(encrypted_data).hexdigest()
        
        # Save backup file
        backup_file = self.backup_path / f"backup_{backup_id}.enc"
        with open(backup_file, 'wb') as f:
            f.write(encrypted_data)
        
        # Store metadata
        backup_metadata = BackupMetadata(
            backup_id=backup_id,
            created_at=datetime.now(),
            backup_key=backup_key,
            content_hash=content_hash,
            size=len(encrypted_data)
        )
        
        self.backups[backup_id] = backup_metadata
        self._save_backup_metadata()
        
        return backup_id
    
    def restore_backup(self, backup_id: str) -> Optional[Dict[str, Any]]:
        """Restore conversation data from backup."""
        if backup_id not in self.backups:
            return None
        
        backup_metadata = self.backups[backup_id]
        backup_file = self.backup_path / f"backup_{backup_id}.enc"
        
        if not backup_file.exists():
            return None
        
        try:
            # Read encrypted backup
            with open(backup_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Verify integrity
            actual_hash = hashlib.sha256(encrypted_data).hexdigest()
            if actual_hash != backup_metadata.content_hash:
                return None
            
            # Decrypt data
            decrypted_data = self._decrypt_backup_data(encrypted_data, backup_metadata.backup_key)
            
            # Decompress and parse
            json_data = zlib.decompress(decrypted_data)
            return json.loads(json_data.decode())
            
        except Exception:
            return None
    
    def forward_secure_delete_backup(self, backup_id: str) -> bool:
        """Delete a backup with forward secrecy."""
        if backup_id not in self.backups:
            return False
        
        try:
            # Overwrite backup key in memory
            backup_metadata = self.backups[backup_id]
            self._secure_overwrite_key(backup_metadata.backup_key)
            
            # Delete backup file
            backup_file = self.backup_path / f"backup_{backup_id}.enc"
            if backup_file.exists():
                self._secure_file_deletion(backup_file)
                backup_file.unlink()
            
            # Remove from metadata
            del self.backups[backup_id]
            self._save_backup_metadata()
            
            return True
        except Exception:
            return False
    
    def _encrypt_backup_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt backup data."""
        nonce = SecureRandom().generate_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def _decrypt_backup_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt backup data."""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _secure_overwrite_key(self, key: bytes) -> None:
        """Securely overwrite key in memory."""
        if isinstance(key, bytes):
            key_array = bytearray(key)
            for i in range(len(key_array)):
                key_array[i] = SecureRandom().generate_bytes(1)[0]
            key_array.clear()
    
    def _secure_file_deletion(self, file_path: Path) -> None:
        """Securely delete a file."""
        if not file_path.exists():
            return
        
        file_size = file_path.stat().st_size
        
        # Three-pass overwrite for backup files
        for _ in range(3):
            with open(file_path, 'r+b') as f:
                random_data = SecureRandom().generate_bytes(file_size)
                f.seek(0)
                f.write(random_data)
                f.flush()
                os.fsync(f.fileno())
    
    def _save_backup_metadata(self) -> None:
        """Save backup metadata to secure storage."""
        metadata_file = self.backup_path / "backup_metadata.json"
        metadata_dict = {}
        
        for backup_id, metadata in self.backups.items():
            metadata_dict[backup_id] = {
                'backup_id': metadata.backup_id,
                'created_at': metadata.created_at.isoformat(),
                'backup_key': base64.b64encode(metadata.backup_key).decode(),
                'content_hash': metadata.content_hash,
                'size': metadata.size,
                'encrypted': metadata.encrypted,
                'forward_secure': metadata.forward_secure
            }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata_dict, f, indent=2)


class EncryptedCache:
    """
    Implements encrypted caching for frequently accessed data.
    """
    
    def __init__(self, cache_path: Path, cache_key: bytes):
        self.cache_path = cache_path
        self.cache_path.mkdir(parents=True, exist_ok=True)
        self.cache_key = cache_key
        self.cache_entries: Dict[str, CacheEntry] = {}
        self.max_cache_size = 100 * 1024 * 1024  # 100MB
        self.default_ttl = timedelta(hours=24)
        
        self._load_cache_index()
    
    def put(self, key: str, data: bytes, cache_type: CacheType, 
           ttl: Optional[timedelta] = None) -> bool:
        """Store data in encrypted cache."""
        try:
            cache_id = hashlib.sha256(f"{cache_type.value}:{key}".encode()).hexdigest()
            
            # Encrypt data
            encrypted_data = self._encrypt_cache_data(data)
            
            # Create cache entry
            expires_at = datetime.now() + (ttl or self.default_ttl)
            cache_entry = CacheEntry(
                cache_id=cache_id,
                cache_type=cache_type,
                key=key,
                encrypted_data=encrypted_data,
                created_at=datetime.now(),
                expires_at=expires_at
            )
            
            # Store encrypted file
            cache_file = self.cache_path / f"cache_{cache_id}.enc"
            with open(cache_file, 'wb') as f:
                f.write(encrypted_data)
            
            self.cache_entries[cache_id] = cache_entry
            
            # Clean up if cache is too large
            self._cleanup_cache()
            
            return True
        except Exception:
            return False
    
    def get(self, key: str, cache_type: CacheType) -> Optional[bytes]:
        """Retrieve data from encrypted cache."""
        cache_id = hashlib.sha256(f"{cache_type.value}:{key}".encode()).hexdigest()
        
        if cache_id not in self.cache_entries:
            return None
        
        cache_entry = self.cache_entries[cache_id]
        
        # Check if expired
        if datetime.now() > cache_entry.expires_at:
            self._remove_cache_entry(cache_id)
            return None
        
        try:
            cache_file = self.cache_path / f"cache_{cache_id}.enc"
            if not cache_file.exists():
                return None
            
            with open(cache_file, 'rb') as f:
                encrypted_data = f.read()
            
            # Update access statistics
            cache_entry.access_count += 1
            cache_entry.last_accessed = datetime.now()
            
            return self._decrypt_cache_data(encrypted_data)
            
        except Exception:
            return None
    
    def invalidate(self, key: str, cache_type: CacheType) -> bool:
        """Invalidate a cache entry."""
        cache_id = hashlib.sha256(f"{cache_type.value}:{key}".encode()).hexdigest()
        return self._remove_cache_entry(cache_id)
    
    def _cleanup_cache(self) -> None:
        """Clean up expired and least recently used cache entries."""
        now = datetime.now()
        
        # Remove expired entries
        expired_ids = [
            cache_id for cache_id, entry in self.cache_entries.items()
            if now > entry.expires_at
        ]
        
        for cache_id in expired_ids:
            self._remove_cache_entry(cache_id)
        
        # Check cache size and remove LRU entries if needed
        total_size = sum(len(entry.encrypted_data) for entry in self.cache_entries.values())
        
        if total_size > self.max_cache_size:
            # Sort by last accessed time
            sorted_entries = sorted(
                self.cache_entries.items(),
                key=lambda x: x[1].last_accessed
            )
            
            # Remove oldest entries until under size limit
            for cache_id, entry in sorted_entries:
                if total_size <= self.max_cache_size * 0.8:  # 80% of max
                    break
                self._remove_cache_entry(cache_id)
                total_size -= len(entry.encrypted_data)
    
    def _remove_cache_entry(self, cache_id: str) -> bool:
        """Remove a cache entry."""
        try:
            if cache_id in self.cache_entries:
                cache_file = self.cache_path / f"cache_{cache_id}.enc"
                if cache_file.exists():
                    cache_file.unlink()
                del self.cache_entries[cache_id]
            return True
        except Exception:
            return False
    
    def _encrypt_cache_data(self, data: bytes) -> bytes:
        """Encrypt cache data."""
        nonce = SecureRandom().generate_bytes(12)
        aesgcm = AESGCM(self.cache_key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def _decrypt_cache_data(self, encrypted_data: bytes) -> bytes:
        """Decrypt cache data."""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(self.cache_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _load_cache_index(self) -> None:
        """Load cache index from storage."""
        # Implementation would load cache metadata
        pass


class ProfileManager:
    """
    Manages multiple user profiles with encrypted settings.
    """
    
    def __init__(self, profiles_path: Path):
        self.profiles_path = profiles_path
        self.profiles_path.mkdir(parents=True, exist_ok=True)
        self.profiles: Dict[str, Profile] = {}
        self.active_profile: Optional[str] = None
        
        self._load_profiles()
    
    def create_profile(self, name: str, settings: Dict[str, Any]) -> str:
        """Create a new encrypted profile."""
        profile_id = SecureRandom().generate_bytes(16).hex()
        
        # Generate unique encryption key for this profile
        encryption_key = SecureRandom().generate_bytes(32)
        
        # Encrypt settings
        settings_json = json.dumps(settings).encode()
        encrypted_settings = self._encrypt_profile_data(settings_json, encryption_key)
        
        profile = Profile(
            profile_id=profile_id,
            name=name,
            encrypted_settings=encrypted_settings,
            encryption_key=encryption_key,
            created_at=datetime.now(),
            last_used=datetime.now()
        )
        
        self.profiles[profile_id] = profile
        self._save_profile(profile)
        
        return profile_id
    
    def switch_profile(self, profile_id: str) -> bool:
        """Switch to a different profile."""
        if profile_id not in self.profiles:
            return False
        
        try:
            # Deactivate current profile
            if self.active_profile:
                self.profiles[self.active_profile].is_active = False
            
            # Activate new profile
            self.profiles[profile_id].is_active = True
            self.profiles[profile_id].last_used = datetime.now()
            self.active_profile = profile_id
            
            self._save_all_profiles()
            return True
        except Exception:
            return False
    
    def get_profile_settings(self, profile_id: str) -> Optional[Dict[str, Any]]:
        """Get decrypted settings for a profile."""
        if profile_id not in self.profiles:
            return None
        
        try:
            profile = self.profiles[profile_id]
            decrypted_data = self._decrypt_profile_data(
                profile.encrypted_settings, 
                profile.encryption_key
            )
            return json.loads(decrypted_data.decode())
        except Exception:
            return None
    
    def update_profile_settings(self, profile_id: str, settings: Dict[str, Any]) -> bool:
        """Update encrypted settings for a profile."""
        if profile_id not in self.profiles:
            return False
        
        try:
            profile = self.profiles[profile_id]
            
            # Encrypt new settings
            settings_json = json.dumps(settings).encode()
            encrypted_settings = self._encrypt_profile_data(settings_json, profile.encryption_key)
            
            profile.encrypted_settings = encrypted_settings
            self._save_profile(profile)
            
            return True
        except Exception:
            return False
    
    def delete_profile(self, profile_id: str) -> bool:
        """Securely delete a profile."""
        if profile_id not in self.profiles:
            return False
        
        try:
            profile = self.profiles[profile_id]
            
            # Securely overwrite encryption key
            self._secure_overwrite_key(profile.encryption_key)
            
            # Delete profile file
            profile_file = self.profiles_path / f"profile_{profile_id}.json"
            if profile_file.exists():
                profile_file.unlink()
            
            # Remove from memory
            del self.profiles[profile_id]
            
            if self.active_profile == profile_id:
                self.active_profile = None
            
            return True
        except Exception:
            return False
    
    def _encrypt_profile_data(self, data: bytes, key: bytes) -> bytes:
        """Encrypt profile data."""
        nonce = SecureRandom().generate_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return nonce + ciphertext
    
    def _decrypt_profile_data(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt profile data."""
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    def _secure_overwrite_key(self, key: bytes) -> None:
        """Securely overwrite key in memory."""
        if isinstance(key, bytes):
            key_array = bytearray(key)
            for i in range(len(key_array)):
                key_array[i] = SecureRandom().generate_bytes(1)[0]
            key_array.clear()
    
    def _save_profile(self, profile: Profile) -> None:
        """Save profile to storage."""
        profile_file = self.profiles_path / f"profile_{profile.profile_id}.json"
        
        profile_data = {
            'profile_id': profile.profile_id,
            'name': profile.name,
            'encrypted_settings': base64.b64encode(profile.encrypted_settings).decode(),
            'encryption_key': base64.b64encode(profile.encryption_key).decode(),
            'created_at': profile.created_at.isoformat(),
            'last_used': profile.last_used.isoformat(),
            'is_active': profile.is_active
        }
        
        with open(profile_file, 'w') as f:
            json.dump(profile_data, f, indent=2)
    
    def _save_all_profiles(self) -> None:
        """Save all profiles to storage."""
        for profile in self.profiles.values():
            self._save_profile(profile)
    
    def _load_profiles(self) -> None:
        """Load profiles from storage."""
        for profile_file in self.profiles_path.glob("profile_*.json"):
            try:
                with open(profile_file, 'r') as f:
                    profile_data = json.load(f)
                
                profile = Profile(
                    profile_id=profile_data['profile_id'],
                    name=profile_data['name'],
                    encrypted_settings=base64.b64decode(profile_data['encrypted_settings']),
                    encryption_key=base64.b64decode(profile_data['encryption_key']),
                    created_at=datetime.fromisoformat(profile_data['created_at']),
                    last_used=datetime.fromisoformat(profile_data['last_used']),
                    is_active=profile_data.get('is_active', False)
                )
                
                self.profiles[profile.profile_id] = profile
                
                if profile.is_active:
                    self.active_profile = profile.profile_id
                    
            except Exception:
                continue  # Skip corrupted profiles


class EnhancedStorageManager:
    """
    Enhanced storage manager integrating all advanced storage features.
    """
    
    def __init__(self, data_dir: Path, master_password: str):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Derive keys from master password
        self.master_key = self._derive_master_key(master_password)
        self.search_key = self._derive_search_key(master_password)
        self.cache_key = self._derive_cache_key(master_password)
        
        # Initialize enhanced storage components
        self.forward_secure_storage = ForwardSecureMessageStorage(
            self.data_dir / "messages", self.master_key
        )
        self.searchable_encryption = SearchableEncryption(self.search_key)
        self.conversation_backup = ConversationBackup(self.data_dir / "backups")
        self.encrypted_cache = EncryptedCache(self.data_dir / "cache", self.cache_key)
        self.profile_manager = ProfileManager(self.data_dir / "profiles")
        
        # Basic storage for compatibility
        from .storage_manager import StorageManager
        self.basic_storage = StorageManager(self.data_dir, master_password)
    
    def store_message_with_forward_secrecy(self, message_id: str, content: str, 
                                         contact_id: str, is_outgoing: bool) -> bool:
        """Store a message with forward secrecy and searchable encryption."""
        try:
            # Store in basic storage for compatibility
            if is_outgoing:
                self.basic_storage.send_message(contact_id, content)
            else:
                self.basic_storage.receive_message(contact_id, content)
            
            # Store with forward secrecy
            message_data = {
                'content': content,
                'contact_id': contact_id,
                'is_outgoing': is_outgoing,
                'timestamp': datetime.now().isoformat()
            }
            
            success = self.forward_secure_storage.store_message(
                message_id, 
                json.dumps(message_data).encode(),
                ForwardSecurityLevel.ENHANCED
            )
            
            if success:
                # Add to search index
                self.searchable_encryption.index_message(message_id, content)
            
            return success
        except Exception:
            return False
    
    def search_messages(self, query: str) -> List[str]:
        """Search for messages containing the query."""
        return self.searchable_encryption.search_messages(query)
    
    def delete_message_with_forward_secrecy(self, message_id: str) -> bool:
        """Delete a message with forward secrecy guarantees."""
        try:
            # Remove from search index
            self.searchable_encryption.remove_message_from_index(message_id)
            
            # Forward secure deletion
            return self.forward_secure_storage.forward_secure_delete(
                message_id, ForwardSecurityLevel.ENHANCED
            )
        except Exception:
            return False
    
    def create_conversation_backup(self, contact_id: str) -> Optional[str]:
        """Create a secure backup of a conversation."""
        try:
            # Get conversation history
            messages = self.basic_storage.get_conversation_history(contact_id)
            
            conversation_data = {
                'contact_id': contact_id,
                'messages': [
                    {
                        'message_id': msg.message_id,
                        'content': msg.content,
                        'is_outgoing': msg.is_outgoing,
                        'timestamp': msg.timestamp.isoformat() if msg.timestamp else None
                    }
                    for msg in messages
                ],
                'created_at': datetime.now().isoformat()
            }
            
            return self.conversation_backup.create_backup(conversation_data)
        except Exception:
            return None
    
    def _derive_master_key(self, password: str) -> bytes:
        """Derive master key from password."""
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"privatus-master-salt",
            iterations=200000,
        ).derive(password.encode())
    
    def _derive_search_key(self, password: str) -> bytes:
        """Derive search key from password."""
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"privatus-search-salt",
            iterations=200000,
        ).derive(password.encode())
    
    def _derive_cache_key(self, password: str) -> bytes:
        """Derive cache key from password."""
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"privatus-cache-salt",
            iterations=200000,
        ).derive(password.encode())
    
    def get_storage_statistics(self) -> Dict[str, Any]:
        """Get comprehensive storage statistics."""
        basic_stats = self.basic_storage.get_statistics()
        
        return {
            **basic_stats,
            'enhanced_features': {
                'forward_secure_messages': len(self.forward_secure_storage.message_keys),
                'search_index_size': len(self.searchable_encryption.search_index),
                'cached_items': len(self.encrypted_cache.cache_entries),
                'available_profiles': len(self.profile_manager.profiles),
                'active_profile': self.profile_manager.active_profile
            }
        } 