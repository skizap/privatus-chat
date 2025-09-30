"""
Storage Manager for Privatus-chat

Provides high-level interface for data persistence operations,
integrating the secure database with application components.
"""

import uuid
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime

from .database import SecureDatabase, Contact, Message
from ..error_handling import (
    error_handler, handle_errors, secure_logger,
    StorageError, DatabaseConnectionError, ErrorSeverity
)


class StorageManager:
    """High-level storage manager for Privatus-chat data."""
    
    @handle_errors("storage_manager_initialization", show_user_feedback=False)
    def __init__(self, data_dir: Path, master_password: str):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)

        # Initialize secure database
        db_path = self.data_dir / "privatus_chat.db"
        self.db = SecureDatabase(db_path, master_password)
        
    def generate_contact_id(self) -> str:
        """Generate a unique contact ID."""
        return str(uuid.uuid4())
        
    def generate_message_id(self) -> str:
        """Generate a unique message ID."""
        return str(uuid.uuid4())
        
    # Contact Management
    def add_contact(self, display_name: str, public_key: str, is_verified: bool = False) -> Optional[str]:
        """Add a new contact and return the contact ID."""
        contact_id = self.generate_contact_id()
        
        contact = Contact(
            contact_id=contact_id,
            display_name=display_name,
            public_key=public_key,
            is_verified=is_verified,
            is_online=False
        )
        
        if self.db.add_contact(contact):
            return contact_id
        return None
        
    def get_contact(self, contact_id: str) -> Optional[Contact]:
        """Get a contact by ID."""
        return self.db.get_contact(contact_id)
        
    def get_all_contacts(self) -> List[Contact]:
        """Get all contacts."""
        return self.db.get_all_contacts()
        
    def update_contact_status(self, contact_id: str, is_online: bool) -> bool:
        """Update contact online status."""
        return self.db.update_contact_status(contact_id, is_online)
        
    def verify_contact(self, contact_id: str) -> bool:
        """Mark a contact as verified."""
        contact = self.db.get_contact(contact_id)
        if contact:
            contact.is_verified = True
            return self.db.add_contact(contact)  # UPDATE via INSERT OR REPLACE
        return False
        
    def remove_contact(self, contact_id: str) -> bool:
        """Remove a contact and all messages."""
        return self.db.remove_contact(contact_id)
        
    # Message Management
    def send_message(self, contact_id: str, content: str) -> Optional[str]:
        """Add an outgoing message and return message ID."""
        message_id = self.generate_message_id()
        
        message = Message(
            message_id=message_id,
            contact_id=contact_id,
            content=content,
            is_outgoing=True,
            is_encrypted=True
        )
        
        if self.db.add_message(message):
            return message_id
        return None
        
    def receive_message(self, contact_id: str, content: str, is_encrypted: bool = True) -> Optional[str]:
        """Add an incoming message and return message ID."""
        message_id = self.generate_message_id()
        
        message = Message(
            message_id=message_id,
            contact_id=contact_id,
            content=content,
            is_outgoing=False,
            is_encrypted=is_encrypted
        )
        
        if self.db.add_message(message):
            return message_id
        return None
        
    def get_conversation_history(self, contact_id: str, limit: int = 100) -> List[Message]:
        """Get conversation history for a contact."""
        return self.db.get_messages(contact_id, limit)
        
    def get_conversation_count(self, contact_id: str) -> int:
        """Get total message count for a contact."""
        return self.db.get_conversation_count(contact_id)
        
    # Settings Management
    def save_settings(self, settings: Dict) -> bool:
        """Save application settings."""
        success = True
        for key, value in settings.items():
            if not self.db.set_setting(key, value):
                success = False
        return success
        
    def load_settings(self, keys: List[str]) -> Dict:
        """Load application settings."""
        settings = {}
        for key in keys:
            settings[key] = self.db.get_setting(key)
        return settings
        
    def get_setting(self, key: str, default_value=None):
        """Get a single setting."""
        return self.db.get_setting(key, default_value)
        
    def set_setting(self, key: str, value) -> bool:
        """Set a single setting."""
        return self.db.set_setting(key, value)
        
    # Statistics and Maintenance
    def get_storage_stats(self) -> Dict:
        """Get storage statistics."""
        db_stats = self.db.get_database_stats()
        
        # Add additional stats
        stats = {
            **db_stats,
            'data_directory': str(self.data_dir),
            'database_file': str(self.db.db_path)
        }
        
        return stats
        
    def cleanup_old_messages(self, days_to_keep: int = 30) -> int:
        """Clean up old messages (return count of deleted messages)."""
        # This would be implemented based on retention policy
        # For now, return 0 as no cleanup is performed
        return 0
        
    def vacuum_database(self):
        """Optimize database storage."""
        self.db.vacuum_database()
        
    def export_contacts(self) -> List[Dict]:
        """Export contacts for backup."""
        contacts = self.get_all_contacts()
        return [
            {
                'contact_id': c.contact_id,
                'display_name': c.display_name,
                'public_key': c.public_key,
                'is_verified': c.is_verified,
                'added_at': c.added_at.isoformat() if c.added_at else None
            }
            for c in contacts
        ]
        
    def import_contacts(self, contacts_data: List[Dict]) -> int:
        """Import contacts from backup (return count of imported contacts)."""
        imported_count = 0
        for contact_data in contacts_data:
            try:
                contact = Contact(
                    contact_id=contact_data['contact_id'],
                    display_name=contact_data['display_name'],
                    public_key=contact_data['public_key'],
                    is_verified=contact_data.get('is_verified', False),
                    is_online=False,
                    added_at=datetime.fromisoformat(contact_data['added_at']) if contact_data.get('added_at') else None
                )
                
                if self.db.add_contact(contact):
                    imported_count += 1
            except (KeyError, ValueError):
                continue  # Skip invalid contact data
                
        return imported_count 