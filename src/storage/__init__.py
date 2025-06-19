"""
Data Storage and Persistence Module

This module implements secure local data storage using SQLite with encryption
for all persistent data including messages, contacts, and cryptographic keys.

Security Features:
- Encrypted database with Fernet encryption
- Secure key storage and management
- Data integrity verification
- Secure deletion capabilities
"""

from .database import SecureDatabase, Contact, Message
from .storage_manager import StorageManager

__all__ = [
    'SecureDatabase',
    'Contact', 
    'Message',
    'StorageManager'
]

# Module will be populated during Week 4: Storage and Data Management 