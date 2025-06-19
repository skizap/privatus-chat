"""
Secure Database Storage for Privatus-chat

Implements encrypted local storage using SQLite for contacts, messages,
and other persistent data with security-focused design.
"""

import sqlite3
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os


@dataclass
class Contact:
    """Contact data structure."""
    contact_id: str
    display_name: str
    public_key: str
    is_verified: bool = False
    is_online: bool = False
    added_at: datetime = None
    last_seen: datetime = None
    
    def __post_init__(self):
        if self.added_at is None:
            self.added_at = datetime.now()


@dataclass 
class Message:
    """Message data structure."""
    message_id: str
    contact_id: str
    content: str
    is_outgoing: bool
    is_encrypted: bool = True
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class SecureDatabase:
    """Secure encrypted database for Privatus-chat data."""
    
    def __init__(self, db_path: Path, password: str):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Generate encryption key from password
        self.fernet = self._create_encryption_key(password)
        
        # Initialize database
        self._init_database()
        
    def _create_encryption_key(self, password: str) -> Fernet:
        """Create encryption key from password."""
        # Use database file path as salt for deterministic key generation
        salt = hashlib.sha256(str(self.db_path).encode()).digest()[:16]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)
        
    def _init_database(self):
        """Initialize database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Contacts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS contacts (
                    contact_id TEXT PRIMARY KEY,
                    display_name TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    is_verified BOOLEAN DEFAULT FALSE,
                    is_online BOOLEAN DEFAULT FALSE,
                    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP
                )
            ''')
            
            # Messages table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    message_id TEXT PRIMARY KEY,
                    contact_id TEXT NOT NULL,
                    content BLOB NOT NULL,
                    is_outgoing BOOLEAN NOT NULL,
                    is_encrypted BOOLEAN DEFAULT TRUE,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (contact_id) REFERENCES contacts (contact_id)
                )
            ''')
            
            # Settings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value BLOB NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            
    def _encrypt_data(self, data: str) -> bytes:
        """Encrypt sensitive data."""
        return self.fernet.encrypt(data.encode())
        
    def _decrypt_data(self, encrypted_data: bytes) -> str:
        """Decrypt sensitive data."""
        return self.fernet.decrypt(encrypted_data).decode()
        
    # Contact Management
    def add_contact(self, contact: Contact) -> bool:
        """Add a new contact."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO contacts 
                    (contact_id, display_name, public_key, is_verified, is_online, added_at, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    contact.contact_id,
                    contact.display_name,
                    contact.public_key,
                    contact.is_verified,
                    contact.is_online,
                    contact.added_at,
                    contact.last_seen
                ))
                conn.commit()
                return True
        except sqlite3.Error:
            return False
            
    def get_contact(self, contact_id: str) -> Optional[Contact]:
        """Get a contact by ID."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT contact_id, display_name, public_key, is_verified, 
                           is_online, added_at, last_seen
                    FROM contacts WHERE contact_id = ?
                ''', (contact_id,))
                
                row = cursor.fetchone()
                if row:
                    return Contact(
                        contact_id=row[0],
                        display_name=row[1], 
                        public_key=row[2],
                        is_verified=bool(row[3]),
                        is_online=bool(row[4]),
                        added_at=datetime.fromisoformat(row[5]) if row[5] else None,
                        last_seen=datetime.fromisoformat(row[6]) if row[6] else None
                    )
        except sqlite3.Error:
            pass
        return None
        
    def get_all_contacts(self) -> List[Contact]:
        """Get all contacts."""
        contacts = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT contact_id, display_name, public_key, is_verified,
                           is_online, added_at, last_seen
                    FROM contacts ORDER BY display_name
                ''')
                
                for row in cursor.fetchall():
                    contacts.append(Contact(
                        contact_id=row[0],
                        display_name=row[1],
                        public_key=row[2], 
                        is_verified=bool(row[3]),
                        is_online=bool(row[4]),
                        added_at=datetime.fromisoformat(row[5]) if row[5] else None,
                        last_seen=datetime.fromisoformat(row[6]) if row[6] else None
                    ))
        except sqlite3.Error:
            pass
        return contacts
        
    def update_contact_status(self, contact_id: str, is_online: bool) -> bool:
        """Update contact online status."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE contacts SET is_online = ?, last_seen = ?
                    WHERE contact_id = ?
                ''', (is_online, datetime.now() if is_online else None, contact_id))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False
            
    def remove_contact(self, contact_id: str) -> bool:
        """Remove a contact and all associated messages."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                # Remove messages first (foreign key constraint)
                cursor.execute('DELETE FROM messages WHERE contact_id = ?', (contact_id,))
                # Remove contact
                cursor.execute('DELETE FROM contacts WHERE contact_id = ?', (contact_id,))
                conn.commit()
                return cursor.rowcount > 0
        except sqlite3.Error:
            return False
            
    # Message Management
    def add_message(self, message: Message) -> bool:
        """Add a new message."""
        try:
            # Encrypt message content
            encrypted_content = self._encrypt_data(message.content)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO messages
                    (message_id, contact_id, content, is_outgoing, is_encrypted, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    message.message_id,
                    message.contact_id,
                    encrypted_content,
                    message.is_outgoing,
                    message.is_encrypted,
                    message.timestamp
                ))
                conn.commit()
                return True
        except sqlite3.Error:
            return False
            
    def get_messages(self, contact_id: str, limit: int = 100) -> List[Message]:
        """Get messages for a contact."""
        messages = []
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT message_id, contact_id, content, is_outgoing, is_encrypted, timestamp
                    FROM messages 
                    WHERE contact_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (contact_id, limit))
                
                for row in cursor.fetchall():
                    # Decrypt message content
                    decrypted_content = self._decrypt_data(row[2])
                    
                    messages.append(Message(
                        message_id=row[0],
                        contact_id=row[1],
                        content=decrypted_content,
                        is_outgoing=bool(row[3]),
                        is_encrypted=bool(row[4]),
                        timestamp=datetime.fromisoformat(row[5]) if row[5] else None
                    ))
                    
                # Return in chronological order
                messages.reverse()
        except sqlite3.Error:
            pass
        return messages
        
    def get_conversation_count(self, contact_id: str) -> int:
        """Get total message count for a contact."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM messages WHERE contact_id = ?', (contact_id,))
                return cursor.fetchone()[0]
        except sqlite3.Error:
            return 0
            
    # Settings Management
    def set_setting(self, key: str, value: any) -> bool:
        """Set a configuration setting."""
        try:
            # Encrypt the setting value
            encrypted_value = self._encrypt_data(json.dumps(value))
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO settings (key, value, updated_at)
                    VALUES (?, ?, ?)
                ''', (key, encrypted_value, datetime.now()))
                conn.commit()
                return True
        except sqlite3.Error:
            return False
            
    def get_setting(self, key: str, default_value: any = None) -> any:
        """Get a configuration setting."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
                row = cursor.fetchone()
                
                if row:
                    # Decrypt and parse the setting value
                    decrypted_value = self._decrypt_data(row[0])
                    return json.loads(decrypted_value)
        except sqlite3.Error:
            pass
        return default_value
        
    # Database Maintenance
    def vacuum_database(self):
        """Optimize database storage."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('VACUUM')
        except sqlite3.Error:
            pass
            
    def get_database_stats(self) -> Dict:
        """Get database statistics."""
        stats = {
            'total_contacts': 0,
            'total_messages': 0,
            'database_size': 0
        }
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Count contacts
                cursor.execute('SELECT COUNT(*) FROM contacts')
                stats['total_contacts'] = cursor.fetchone()[0]
                
                # Count messages
                cursor.execute('SELECT COUNT(*) FROM messages')
                stats['total_messages'] = cursor.fetchone()[0]
                
                # Database file size
                if self.db_path.exists():
                    stats['database_size'] = self.db_path.stat().st_size
                    
        except sqlite3.Error:
            pass
            
        return stats 