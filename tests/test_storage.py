"""
Storage Infrastructure Tests for Privatus-chat
Week 6: Storage Infrastructure

Test suite for the storage components including database, enhanced storage,
and storage management.
"""

import pytest
import asyncio
import tempfile
import os
import sqlite3
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from src.storage.database import SecureDatabase, Message, Contact
from src.storage.enhanced_storage import EnhancedStorageManager, CacheType
from src.storage.storage_manager import StorageManager
from src.crypto.key_management import KeyManager
from src.crypto.encryption import MessageEncryption


class TestDatabaseManager:
    """Test database manager functionality"""

    @pytest.fixture
    async def db_manager(self):
        """Create database manager for testing"""
        # Use temporary database
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as temp_db:
            db_path = temp_db.name

        key_manager = KeyManager()
        await key_manager.initialize()

        manager = DatabaseManager(db_path, key_manager)
        await manager.initialize()

        yield manager

        # Cleanup
        await manager.close()
        os.unlink(db_path)

    @pytest.mark.asyncio
    async def test_database_initialization(self, db_manager):
        """Test database initialization"""
        # Check tables exist
        tables = await db_manager._execute_query(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        table_names = [row[0] for row in tables]

        assert 'messages' in table_names
        assert 'contacts' in table_names
        assert 'settings' in table_names
        assert 'metadata' in table_names

    @pytest.mark.asyncio
    async def test_message_storage(self, db_manager):
        """Test message storage and retrieval"""
        # Create test message
        message = MessageRecord(
            message_id="test_msg_123",
            sender=b'sender',
            recipient=b'recipient',
            content=b"test message",
            timestamp=1234567890,
            message_type="chat",
            encrypted=True
        )

        # Store message
        success = await db_manager.store_message(message)
        assert success

        # Retrieve message
        retrieved = await db_manager.get_message("test_msg_123")
        assert retrieved is not None
        assert retrieved.message_id == "test_msg_123"
        assert retrieved.sender == b'sender'
        assert retrieved.content == b"test message"

    @pytest.mark.asyncio
    async def test_contact_management(self, db_manager):
        """Test contact storage and retrieval"""
        # Create test contact
        contact = ContactRecord(
            contact_id=b'contact123',
            nickname="TestContact",
            public_key=b'public_key_data',
            last_seen=1234567890,
            trust_level=0.8
        )

        # Store contact
        success = await db_manager.store_contact(contact)
        assert success

        # Retrieve contact
        retrieved = await db_manager.get_contact(b'contact123')
        assert retrieved is not None
        assert retrieved.contact_id == b'contact123'
        assert retrieved.nickname == "TestContact"

    @pytest.mark.asyncio
    async def test_message_querying(self, db_manager):
        """Test message querying capabilities"""
        # Store multiple messages
        messages = [
            MessageRecord(f"msg_{i}", b'sender', b'recipient', f"content {i}".encode(),
                         1000000000 + i, "chat", True)
            for i in range(5)
        ]

        for msg in messages:
            await db_manager.store_message(msg)

        # Query messages
        results = await db_manager.get_messages(b'recipient', limit=3)
        assert len(results) == 3

        # Query by time range
        time_results = await db_manager.get_messages_by_time_range(
            b'recipient', 1000000000, 1000000005
        )
        assert len(time_results) == 5

    @pytest.mark.asyncio
    async def test_database_cleanup(self, db_manager):
        """Test database cleanup operations"""
        # Store some old messages
        old_messages = [
            MessageRecord(f"old_msg_{i}", b'sender', b'recipient', b"old content",
                         1000000000 - i * 86400, "chat", True)  # Days ago
            for i in range(3)
        ]

        for msg in old_messages:
            await db_manager.store_message(msg)

        # Clean up old messages (older than 1 day)
        deleted_count = await db_manager.cleanup_old_messages(86400)
        assert deleted_count == 3

    def test_database_statistics(self, db_manager):
        """Test database statistics"""
        stats = db_manager.get_statistics()

        assert 'total_messages' in stats
        assert 'total_contacts' in stats
        assert 'database_size' in stats
        assert 'oldest_message' in stats
        assert 'newest_message' in stats


class TestEnhancedStorageManager:
    """Test enhanced storage manager functionality"""

    @pytest.fixture
    async def storage_manager(self):
        """Create enhanced storage manager for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            key_manager = KeyManager()
            await key_manager.initialize()

            manager = EnhancedStorageManager(temp_dir, key_manager)
            await manager.initialize()

            yield manager

            await manager.close()

    @pytest.mark.asyncio
    async def test_file_storage(self, storage_manager):
        """Test file storage operations"""
        test_data = b"test file content for storage"
        file_id = "test_file_123"

        # Store file
        success = await storage_manager.store_file(file_id, test_data, StorageType.FILE)
        assert success

        # Retrieve file
        retrieved_data = await storage_manager.retrieve_file(file_id)
        assert retrieved_data == test_data

    @pytest.mark.asyncio
    async def test_chunked_storage(self, storage_manager):
        """Test chunked file storage"""
        # Create large test data
        large_data = b"x" * (1024 * 1024)  # 1MB
        file_id = "large_file_123"

        # Store in chunks
        success = await storage_manager.store_large_file(file_id, large_data, chunk_size=65536)
        assert success

        # Retrieve and verify
        retrieved_data = await storage_manager.retrieve_large_file(file_id)
        assert retrieved_data == large_data

    @pytest.mark.asyncio
    async def test_metadata_storage(self, storage_manager):
        """Test metadata storage"""
        metadata = {
            'filename': 'test.txt',
            'size': 1024,
            'checksum': 'abc123',
            'upload_time': 1234567890
        }

        # Store metadata
        success = await storage_manager.store_metadata("test_file", metadata)
        assert success

        # Retrieve metadata
        retrieved = await storage_manager.get_metadata("test_file")
        assert retrieved == metadata

    @pytest.mark.asyncio
    async def test_storage_cleanup(self, storage_manager):
        """Test storage cleanup"""
        # Store some files
        files_to_store = [
            ("file1", b"content1"),
            ("file2", b"content2"),
            ("file3", b"content3")
        ]

        for file_id, content in files_to_store:
            await storage_manager.store_file(file_id, content, StorageType.FILE)

        # Mark some as old
        old_files = ["file1", "file2"]
        for file_id in old_files:
            await storage_manager.mark_file_deleted(file_id)

        # Clean up deleted files
        cleaned_count = await storage_manager.cleanup_deleted_files()
        assert cleaned_count == 2

    def test_storage_validation(self, storage_manager):
        """Test storage validation"""
        # Valid file ID
        assert storage_manager.validate_file_id("valid_file_123")

        # Invalid file ID
        assert not storage_manager.validate_file_id("")
        assert not storage_manager.validate_file_id("invalid/file")

    def test_storage_statistics(self, storage_manager):
        """Test storage statistics"""
        stats = storage_manager.get_storage_statistics()

        assert 'total_files' in stats
        assert 'total_size' in stats
        assert 'storage_used' in stats
        assert 'available_space' in stats
        assert 'compression_ratio' in stats


class TestStorageManager:
    """Test main storage manager functionality"""

    @pytest.fixture
    async def storage_mgr(self):
        """Create storage manager for testing"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = StorageConfig(
                database_path=os.path.join(temp_dir, 'test.db'),
                storage_path=temp_dir,
                max_file_size=10*1024*1024,  # 10MB
                retention_days=30
            )

            key_manager = KeyManager()
            await key_manager.initialize()

            manager = StorageManager(config, key_manager)
            await manager.initialize()

            yield manager

            await manager.close()

    @pytest.mark.asyncio
    async def test_message_persistence(self, storage_mgr):
        """Test message persistence"""
        message_data = {
            'message_id': 'msg_123',
            'sender': b'sender',
            'recipient': b'recipient',
            'content': b'encrypted content',
            'timestamp': 1234567890,
            'message_type': 'chat'
        }

        # Store message
        success = await storage_mgr.store_message(message_data)
        assert success

        # Retrieve message
        retrieved = await storage_mgr.get_message('msg_123')
        assert retrieved is not None
        assert retrieved['message_id'] == 'msg_123'

    @pytest.mark.asyncio
    async def test_contact_persistence(self, storage_mgr):
        """Test contact persistence"""
        contact_data = {
            'contact_id': b'contact123',
            'nickname': 'TestUser',
            'public_key': b'public_key_data',
            'last_seen': 1234567890,
            'trust_level': 0.9
        }

        # Store contact
        success = await storage_mgr.store_contact(contact_data)
        assert success

        # Retrieve contact
        retrieved = await storage_mgr.get_contact(b'contact123')
        assert retrieved is not None
        assert retrieved['nickname'] == 'TestUser'

    @pytest.mark.asyncio
    async def test_file_operations(self, storage_mgr):
        """Test file operations"""
        # Create test file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            test_content = b"file content for testing"
            temp_file.write(test_content)
            temp_path = temp_file.name

        try:
            # Store file
            file_id = await storage_mgr.store_file(temp_path, "test.txt")
            assert file_id is not None

            # Retrieve file
            retrieved_path = await storage_mgr.retrieve_file(file_id, "/tmp/retrieved.txt")
            assert retrieved_path is not None

            # Verify content
            with open(retrieved_path, 'rb') as f:
                retrieved_content = f.read()
            assert retrieved_content == test_content

        finally:
            os.unlink(temp_path)
            if os.path.exists("/tmp/retrieved.txt"):
                os.unlink("/tmp/retrieved.txt")

    @pytest.mark.asyncio
    async def test_backup_restore(self, storage_mgr):
        """Test backup and restore functionality"""
        # Store some data
        await storage_mgr.store_message({
            'message_id': 'backup_test',
            'sender': b'sender',
            'recipient': b'recipient',
            'content': b'test content',
            'timestamp': 1234567890,
            'message_type': 'chat'
        })

        # Create backup
        backup_path = "/tmp/test_backup.db"
        success = await storage_mgr.create_backup(backup_path)
        assert success
        assert os.path.exists(backup_path)

        # Restore from backup
        restore_success = await storage_mgr.restore_from_backup(backup_path)
        assert restore_success

        # Verify data
        restored_msg = await storage_mgr.get_message('backup_test')
        assert restored_msg is not None

        # Cleanup
        os.unlink(backup_path)

    def test_storage_configuration(self, storage_mgr):
        """Test storage configuration"""
        config = storage_mgr.get_config()

        assert 'max_file_size' in config
        assert 'retention_days' in config
        assert 'compression_enabled' in config
        assert 'encryption_enabled' in config

    def test_storage_health_check(self, storage_mgr):
        """Test storage health check"""
        health = storage_mgr.health_check()

        assert 'database_status' in health
        assert 'storage_status' in health
        assert 'disk_space' in health
        assert 'corruption_check' in health


# Integration tests
class TestStorageIntegration:
    """Integration tests for storage components"""

    @pytest.mark.asyncio
    async def test_full_storage_workflow(self):
        """Test complete storage workflow"""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Setup
            config = StorageConfig(
                database_path=os.path.join(temp_dir, 'integration.db'),
                storage_path=temp_dir
            )

            key_manager = KeyManager()
            await key_manager.initialize()

            storage_mgr = StorageManager(config, key_manager)
            await storage_mgr.initialize()

            try:
                # Store message
                msg_data = {
                    'message_id': 'integration_msg',
                    'sender': b'alice',
                    'recipient': b'bob',
                    'content': b'Hello from integration test!',
                    'timestamp': 1234567890,
                    'message_type': 'chat'
                }

                success = await storage_mgr.store_message(msg_data)
                assert success

                # Store contact
                contact_data = {
                    'contact_id': b'bob_contact',
                    'nickname': 'Bob',
                    'public_key': b'bob_public_key',
                    'last_seen': 1234567890,
                    'trust_level': 1.0
                }

                success = await storage_mgr.store_contact(contact_data)
                assert success

                # Query data
                messages = await storage_mgr.get_messages(b'bob', limit=10)
                assert len(messages) == 1

                contact = await storage_mgr.get_contact(b'bob_contact')
                assert contact is not None

                # Statistics
                stats = storage_mgr.get_statistics()
                assert stats['total_messages'] == 1
                assert stats['total_contacts'] == 1

            finally:
                await storage_mgr.close()

    @pytest.mark.asyncio
    async def test_storage_performance(self):
        """Test storage performance under load"""
        with tempfile.TemporaryDirectory() as temp_dir:
            config = StorageConfig(
                database_path=os.path.join(temp_dir, 'perf.db'),
                storage_path=temp_dir
            )

            key_manager = KeyManager()
            await key_manager.initialize()

            storage_mgr = StorageManager(config, key_manager)
            await storage_mgr.initialize()

            try:
                import time

                # Store multiple messages
                start_time = time.time()

                for i in range(100):
                    msg_data = {
                        'message_id': f'perf_msg_{i}',
                        'sender': b'sender',
                        'recipient': b'recipient',
                        'content': f'Message {i}'.encode(),
                        'timestamp': 1234567890 + i,
                        'message_type': 'chat'
                    }
                    await storage_mgr.store_message(msg_data)

                store_time = time.time() - start_time

                # Query messages
                start_time = time.time()
                messages = await storage_mgr.get_messages(b'recipient', limit=50)
                query_time = time.time() - start_time

                # Performance assertions (reasonable times)
                assert store_time < 5.0  # Should store 100 messages in under 5 seconds
                assert query_time < 1.0  # Should query in under 1 second
                assert len(messages) == 50

            finally:
                await storage_mgr.close()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])