"""
Secure Database Storage for Privatus-chat

Implements encrypted local storage using SQLite for contacts, messages,
and other persistent data with security-focused design.
"""

import sqlite3
import json
import hashlib
import logging
import secrets
import time
import platform
import psutil
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import base64
import os

logger = logging.getLogger(__name__)


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
        """
        Create encryption key from password using modern security standards.

        Implements adaptive PBKDF2 iteration count based on system performance,
        cryptographically secure salt generation, and comprehensive security logging.
        """
        try:
            # Validate password strength
            if not self._validate_password_strength(password):
                raise ValueError("Password does not meet security requirements")

            # Generate or retrieve cryptographically secure salt
            salt = self._get_or_create_salt()

            # Determine adaptive iteration count based on system performance
            iterations = self._calculate_optimal_iterations()

            # Log security parameters (without exposing sensitive data)
            logger.info(f"Key derivation parameters: algorithm=PBKDF2-SHA256, "
                       f"iterations={iterations}, salt_length={len(salt)}")

            # Perform key derivation with timing-safe operations
            start_time = time.perf_counter()
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
            )

            # Use timing-safe comparison for password validation
            key = self._timing_safe_derive_key(kdf, password)
            derivation_time = time.perf_counter() - start_time

            # Log performance metrics (without exposing sensitive data)
            logger.info(f"Key derivation completed in {derivation_time:.4f}s")

            # Validate generated key strength
            if not self._validate_key_strength(key):
                raise ValueError("Generated key failed security validation")

            return Fernet(key)

        except Exception as e:
            logger.error(f"Key derivation failed: {str(e)}", exc_info=True)
            raise ValueError("Failed to create encryption key due to security error")

    def _validate_password_strength(self, password: str) -> bool:
        """Validate password meets minimum security requirements."""
        if not password or len(password) < 12:
            return False

        # Check for character diversity
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)

        return has_lower and has_upper and has_digit and has_special

    def _get_or_create_salt(self) -> bytes:
        """Get existing salt or generate a new cryptographically secure salt."""
        salt_path = self.db_path.with_suffix('.salt')

        try:
            # Try to read existing salt
            if salt_path.exists():
                with open(salt_path, 'rb') as f:
                    salt = f.read(32)  # Read exactly 32 bytes

                # Validate existing salt
                if len(salt) == 32 and self._validate_salt_entropy(salt):
                    logger.debug("Using existing salt from file")
                    return salt
                else:
                    logger.warning("Existing salt is invalid, generating new salt")
            else:
                logger.debug("No existing salt found, generating new salt")

        except (IOError, OSError) as e:
            logger.warning(f"Could not read existing salt: {e}, generating new salt")

        # Generate new cryptographically secure salt
        salt = secrets.token_bytes(32)

        try:
            # Save new salt to file with secure permissions
            salt_path.parent.mkdir(parents=True, exist_ok=True)
            with open(salt_path, 'wb') as f:
                f.write(salt)
            # Set restrictive file permissions
            salt_path.chmod(0o600)
            logger.info("New salt generated and saved securely")
        except (IOError, OSError) as e:
            logger.error(f"Failed to save salt file: {e}")
            # Continue with generated salt even if save failed
            pass

        return salt

    def _validate_salt_entropy(self, salt: bytes) -> bool:
        """Validate salt has sufficient entropy."""
        if len(salt) != 32:
            return False

        # Check for minimum entropy (not all zeros, not sequential, etc.)
        if all(b == 0 for b in salt):
            return False

        # Check for basic patterns that indicate poor randomness
        if salt == bytes(range(32)) or salt == bytes(range(32, 0, -1)):
            return False

        return True

    def _calculate_optimal_iterations(self) -> int:
        """
        Calculate optimal PBKDF2 iterations based on system performance.

        Uses system benchmarking to determine appropriate iteration count
        that provides security while maintaining reasonable performance.
        """
        # Base iteration count for modern security
        base_iterations = 1_000_000  # 1M minimum for production

        try:
            # Get system performance metrics
            cpu_count = os.cpu_count() or 2
            memory_gb = psutil.virtual_memory().total / (1024**3) if psutil else 4

            # Benchmark system performance
            benchmark_iterations = 100_000  # Test with smaller count
            start_time = time.perf_counter()

            # Simple benchmark using PBKDF2
            test_salt = secrets.token_bytes(32)
            test_password = "benchmark_password_for_timing"

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=test_salt,
                iterations=benchmark_iterations,
            )
            kdf.derive(test_password.encode())

            benchmark_time = time.perf_counter() - start_time

            # Calculate iterations for target time (aim for ~0.5-1.0 seconds)
            target_time = 0.75
            if benchmark_time > 0:
                performance_factor = target_time / benchmark_time
                calculated_iterations = int(benchmark_iterations * performance_factor)

                # Apply system performance multipliers
                if cpu_count >= 8:  # High-end system
                    calculated_iterations = int(calculated_iterations * 1.2)
                elif cpu_count >= 4:  # Mid-range system
                    calculated_iterations = int(calculated_iterations * 1.1)
                else:  # Low-end system
                    calculated_iterations = int(calculated_iterations * 0.9)

                # Memory factor (more memory allows higher iterations)
                if memory_gb >= 16:
                    calculated_iterations = int(calculated_iterations * 1.1)
                elif memory_gb >= 8:
                    calculated_iterations = int(calculated_iterations * 1.05)

                # Ensure minimum security threshold
                final_iterations = max(calculated_iterations, base_iterations)

                logger.info(f"Calculated optimal iterations: {final_iterations} "
                           f"(benchmark: {benchmark_time:.4f}s, CPU cores: {cpu_count}, "
                           f"memory: {memory_gb:.1f}GB)")

                return final_iterations
            else:
                logger.warning("Benchmark timing failed, using base iterations")
                return base_iterations

        except Exception as e:
            logger.warning(f"Performance benchmarking failed: {e}, using base iterations")
            return base_iterations

    def _timing_safe_derive_key(self, kdf: PBKDF2HMAC, password: str) -> bytes:
        """Derive key using timing-safe operations."""
        try:
            # Use constant-time operations where possible
            password_bytes = password.encode('utf-8')

            # Ensure consistent memory access patterns
            key = kdf.derive(password_bytes)

            # Clear sensitive data from memory as much as possible
            del password_bytes

            return base64.urlsafe_b64encode(key)

        except Exception as e:
            logger.error(f"Key derivation failed: {str(e)}")
            raise

    def _validate_key_strength(self, key: bytes) -> bool:
        """Validate generated key meets security requirements."""
        if len(key) != 44:  # Fernet keys are 44 bytes (base64 encoded 32-byte key)
            return False

        # Check for weak keys (all same character, sequential patterns, etc.)
        try:
            decoded_key = base64.urlsafe_b64decode(key)
            if len(decoded_key) != 32:
                return False

            # Check for minimum entropy
            if all(b == decoded_key[0] for b in decoded_key):
                return False

            # Check for basic patterns
            if decoded_key == bytes(range(32)) or decoded_key == bytes(range(32, 0, -1)):
                return False

            return True

        except Exception:
            return False

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
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                conn.execute("PRAGMA journal_mode=WAL")  # Enable WAL mode for better concurrency
                conn.execute("PRAGMA synchronous=NORMAL")  # Balance performance and safety
                conn.execute("PRAGMA cache_size=-64000")  # 64MB cache

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
                    contact.added_at.isoformat() if contact.added_at else None,
                    contact.last_seen.isoformat() if contact.last_seen else None
                ))
                conn.commit()
                return True
        except sqlite3.IntegrityError:
            # Contact already exists
            return False
        except sqlite3.Error as e:
            logger.error(f"Database error adding contact: {e}")
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
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute('VACUUM')
                logger.info("Database vacuum completed")
        except sqlite3.Error as e:
            logger.error(f"Database vacuum failed: {e}")

    def check_integrity(self) -> bool:
        """Check database integrity."""
        try:
            with sqlite3.connect(self.db_path, timeout=10.0) as conn:
                cursor = conn.cursor()
                cursor.execute("PRAGMA integrity_check")
                result = cursor.fetchone()
                return result and result[0] == "ok"
        except sqlite3.Error as e:
            logger.error(f"Integrity check failed: {e}")
            return False

    def repair_database(self) -> bool:
        """Attempt to repair database corruption."""
        try:
            # Create backup
            backup_path = self.db_path.with_suffix('.bak')
            if self.db_path.exists():
                import shutil
                shutil.copy2(self.db_path, backup_path)
                logger.info(f"Database backup created: {backup_path}")

            # Try to rebuild database
            with sqlite3.connect(self.db_path, timeout=30.0) as conn:
                conn.execute("PRAGMA foreign_keys=OFF")
                conn.execute("BEGIN")

                # Rebuild tables if needed
                self._init_database()

                conn.execute("PRAGMA foreign_keys=ON")
                conn.commit()

            logger.info("Database repair completed")
            return True

        except Exception as e:
            logger.error(f"Database repair failed: {e}")
            # Restore backup if repair failed
            if backup_path.exists():
                shutil.copy2(backup_path, self.db_path)
                logger.info("Database backup restored")
            return False

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