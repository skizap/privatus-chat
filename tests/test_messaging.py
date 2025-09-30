"""
Messaging Infrastructure Tests for Privatus-chat
Week 5: Messaging Infrastructure

Test suite for the messaging components including message routing, file transfer,
group chat, and group cryptography.
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import Mock, patch, AsyncMock
from pathlib import Path

from src.messaging.message_router import MessageRouter, MessageType, MessageStatus
from src.messaging.file_transfer import FileTransferManager, FileTransferStatus, FileTransferDirection
from src.messaging.group_chat import GroupChatManager, Group, GroupMember, GroupRole, GroupType
from src.messaging.group_crypto import GroupKeyManager, GroupCryptography
from src.crypto.key_management import KeyManager
from src.crypto.secure_random import SecureRandom


class TestMessageRouter:
    """Test message routing functionality"""

    @pytest.fixture
    def message_router(self):
        """Create message router for testing"""
        # Mock group manager and crypto manager
        group_manager = Mock()
        crypto_manager = Mock()

        router = MessageRouter(group_manager, crypto_manager)
        return router


    def test_message_routing(self, message_router):
        """Test basic message routing"""
        # Test direct message routing
        message_id = message_router.route_direct_message(
            sender_id=b'test_sender',
            recipient_id=b'test_recipient',
            encrypted_content=b'Hello World'
        )
        assert message_id is not None
        assert isinstance(message_id, str)

    def test_message_validation(self, message_router):
        """Test message validation"""
        # Valid message
        valid_message = {
            'type': 'chat',
            'sender': b'sender',
            'recipient': b'recipient',
            'content': 'test',
            'timestamp': 1234567890
        }
        assert message_router.validate_message(valid_message)

        # Invalid message - missing fields
        invalid_message = {'type': 'chat'}
        assert not message_router.validate_message(invalid_message)

    def test_routing_statistics(self, message_router):
        """Test routing statistics collection"""
        stats = message_router.get_routing_statistics()

        assert 'messages_routed' in stats
        assert 'messages_failed' in stats
        assert 'average_routing_time' in stats
        assert 'queue_size' in stats


class TestFileTransfer:
    """Test file transfer functionality"""

    @pytest.fixture
    async def transfer_manager(self):
        """Create file transfer manager for testing"""
        key_manager = KeyManager()
        await key_manager.initialize()

        manager = FileTransferManager(key_manager)
        await manager.start()
        yield manager
        await manager.stop()

    @pytest.mark.asyncio
    async def test_file_transfer_creation(self, transfer_manager):
        """Test file transfer creation"""
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"test file content")
            temp_file_path = temp_file.name

        try:
            # Create transfer
            transfer_id = await transfer_manager.create_transfer(
                file_path=temp_file_path,
                recipient=b'recipient',
                transfer_type=TransferType.FILE
            )

            assert transfer_id is not None
            assert isinstance(transfer_id, str)

            # Check transfer exists
            transfer = transfer_manager.get_transfer(transfer_id)
            assert transfer is not None
            assert transfer.state == TransferState.PENDING

        finally:
            os.unlink(temp_file_path)

    def test_transfer_state_transitions(self, transfer_manager):
        """Test transfer state transitions"""
        # Create mock transfer
        transfer = Mock()
        transfer.state = TransferState.PENDING

        # Test state transitions
        transfer_manager._update_transfer_state(transfer, TransferState.IN_PROGRESS)
        assert transfer.state == TransferState.IN_PROGRESS

        transfer_manager._update_transfer_state(transfer, TransferState.COMPLETED)
        assert transfer.state == TransferState.COMPLETED

    def test_transfer_validation(self, transfer_manager):
        """Test transfer validation"""
        # Valid transfer parameters
        assert transfer_manager.validate_transfer_params(
            file_path="/tmp/test.txt",
            recipient=b'recipient',
            max_size=1024*1024
        )

        # Invalid - empty file path
        assert not transfer_manager.validate_transfer_params(
            file_path="",
            recipient=b'recipient',
            max_size=1024*1024
        )

    def test_transfer_statistics(self, transfer_manager):
        """Test transfer statistics"""
        stats = transfer_manager.get_transfer_statistics()

        assert 'total_transfers' in stats
        assert 'active_transfers' in stats
        assert 'completed_transfers' in stats
        assert 'failed_transfers' in stats
        assert 'total_bytes_transferred' in stats


class TestGroupChat:
    """Test group chat functionality"""

    @pytest.fixture
    async def group_manager(self):
        """Create group chat manager for testing"""
        key_manager = KeyManager()
        await key_manager.initialize()

        manager = GroupChatManager(key_manager)
        await manager.start()
        yield manager
        await manager.stop()

    @pytest.mark.asyncio
    async def test_group_creation(self, group_manager):
        """Test group creation"""
        group_id = await group_manager.create_group(
            name="Test Group",
            creator=b'creator',
            initial_members=[b'member1', b'member2']
        )

        assert group_id is not None
        assert isinstance(group_id, str)

        # Check group exists
        group = group_manager.get_group(group_id)
        assert group is not None
        assert group.name == "Test Group"
        assert len(group.members) == 3  # creator + 2 members

    def test_group_message_creation(self, group_manager):
        """Test group message creation"""
        message = group_manager.create_group_message(
            group_id="test_group",
            sender=b'sender',
            content="Hello Group!",
            message_type="text"
        )

        assert message is not None
        assert message.group_id == "test_group"
        assert message.sender == b'sender'
        assert message.content == "Hello Group!"
        assert message.message_type == "text"

    def test_member_management(self, group_manager):
        """Test group member management"""
        # Create mock group
        group = Mock()
        group.members = [b'member1', b'member2']

        # Test adding member
        group_manager._add_group_member(group, b'member3')
        assert b'member3' in group.members

        # Test removing member
        group_manager._remove_group_member(group, b'member2')
        assert b'member2' not in group.members
        assert b'member1' in group.members

    def test_group_validation(self, group_manager):
        """Test group validation"""
        # Valid group parameters
        assert group_manager.validate_group_params(
            name="Valid Group",
            max_members=100
        )

        # Invalid - empty name
        assert not group_manager.validate_group_params(
            name="",
            max_members=100
        )

    def test_group_statistics(self, group_manager):
        """Test group statistics"""
        stats = group_manager.get_group_statistics()

        assert 'total_groups' in stats
        assert 'active_groups' in stats
        assert 'total_members' in stats
        assert 'messages_sent' in stats


class TestGroupCrypto:
    """Test group cryptography functionality"""

    @pytest.fixture
    async def crypto_manager(self):
        """Create group crypto manager for testing"""
        key_manager = KeyManager()
        await key_manager.initialize()

        manager = GroupCryptoManager(key_manager)
        await manager.start()
        yield manager
        await manager.stop()

    @pytest.mark.asyncio
    async def test_group_key_creation(self, crypto_manager):
        """Test group key creation"""
        group_id = "test_group"

        # Create group keys
        success = await crypto_manager.create_group_keys(group_id)
        assert success

        # Check keys exist
        keys = crypto_manager.get_group_keys(group_id)
        assert keys is not None
        assert 'encryption_key' in keys
        assert 'signing_key' in keys

    def test_member_key_distribution(self, crypto_manager):
        """Test member key distribution"""
        group_id = "test_group"
        member_id = b'member1'

        # Mock group keys
        crypto_manager.group_keys[group_id] = {
            'encryption_key': b'test_enc_key',
            'signing_key': b'test_sign_key'
        }

        # Distribute keys to member
        success = crypto_manager.distribute_keys_to_member(group_id, member_id)
        assert success

        # Check member has keys
        member_keys = crypto_manager.get_member_keys(group_id, member_id)
        assert member_keys is not None

    def test_message_encryption_decryption(self, crypto_manager):
        """Test group message encryption/decryption"""
        group_id = "test_group"
        message = b"secret group message"

        # Mock group key
        crypto_manager.group_keys[group_id] = {
            'encryption_key': SecureRandom().generate_bytes(32)
        }

        # Encrypt message
        encrypted = crypto_manager.encrypt_group_message(group_id, message)
        assert encrypted is not None
        assert encrypted != message

        # Decrypt message
        decrypted = crypto_manager.decrypt_group_message(group_id, encrypted)
        assert decrypted == message

    def test_member_verification(self, crypto_manager):
        """Test member verification"""
        group_id = "test_group"
        member_id = b'member1'

        # Add member
        member = GroupMember(member_id, role="member")
        crypto_manager.group_members.setdefault(group_id, {})[member_id] = member

        # Verify member
        assert crypto_manager.verify_group_member(group_id, member_id)

        # Verify non-member
        assert not crypto_manager.verify_group_member(group_id, b'non_member')

    def test_key_rotation(self, crypto_manager):
        """Test group key rotation"""
        group_id = "test_group"

        # Create initial keys
        crypto_manager.group_keys[group_id] = {
            'encryption_key': b'old_key',
            'key_version': 1
        }

        # Rotate keys
        success = crypto_manager.rotate_group_keys(group_id)
        assert success

        # Check new keys
        new_keys = crypto_manager.get_group_keys(group_id)
        assert new_keys['encryption_key'] != b'old_key'
        assert new_keys['key_version'] == 2

    def test_crypto_statistics(self, crypto_manager):
        """Test crypto statistics"""
        stats = crypto_manager.get_crypto_statistics()

        assert 'total_groups' in stats
        assert 'keys_rotated' in stats
        assert 'messages_encrypted' in stats
        assert 'encryption_failures' in stats


# Integration tests
class TestMessagingIntegration:
    """Integration tests for messaging components"""

    @pytest.mark.asyncio
    async def test_end_to_end_messaging(self):
        """Test end-to-end messaging flow"""
        # Create components
        key_manager = KeyManager()
        await key_manager.initialize()

        router = MessageRouter(key_manager)
        await router.start()

        # Create and route a message
        message = {
            'type': 'chat',
            'sender': b'sender',
            'recipient': b'recipient',
            'content': 'Integration test message',
            'timestamp': 1234567890
        }

        result = await router.route_message(message, MessagePriority.NORMAL)
        assert isinstance(result, bool)

        await router.stop()

    @pytest.mark.asyncio
    async def test_file_transfer_workflow(self):
        """Test complete file transfer workflow"""
        # Create transfer manager
        key_manager = KeyManager()
        await key_manager.initialize()

        transfer_manager = FileTransferManager(key_manager)
        await transfer_manager.start()

        # Create temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            test_content = b"test file content for transfer"
            temp_file.write(test_content)
            temp_file_path = temp_file.name

        try:
            # Create transfer
            transfer_id = await transfer_manager.create_transfer(
                file_path=temp_file_path,
                recipient=b'recipient',
                transfer_type=TransferType.FILE
            )

            assert transfer_id is not None

            # Simulate transfer completion
            transfer = transfer_manager.get_transfer(transfer_id)
            transfer_manager._update_transfer_state(transfer, TransferState.COMPLETED)

            # Verify completion
            updated_transfer = transfer_manager.get_transfer(transfer_id)
            assert updated_transfer.state == TransferState.COMPLETED

        finally:
            os.unlink(temp_file_path)
            await transfer_manager.stop()

    @pytest.mark.asyncio
    async def test_group_messaging_flow(self):
        """Test group messaging flow"""
        # Create group manager
        key_manager = KeyManager()
        await key_manager.initialize()

        group_manager = GroupChatManager(key_manager)
        await group_manager.start()

        # Create group
        group_id = await group_manager.create_group(
            name="Integration Test Group",
            creator=b'creator',
            initial_members=[b'member1']
        )

        assert group_id is not None

        # Send group message
        message = group_manager.create_group_message(
            group_id=group_id,
            sender=b'member1',
            content="Hello Group!",
            message_type="text"
        )

        assert message is not None
        assert message.group_id == group_id

        await group_manager.stop()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])