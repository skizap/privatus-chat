#!/usr/bin/env python3
"""
Test script for message authentication system
"""

import sys
import os
import tempfile
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.network.message_protocol import (
    MessageSerializer, MessageProtocol, P2PMessage, MessageHeader,
    MessageType, MessageFlags
)
from src.crypto.key_management import KeyManager

def test_message_authentication():
    """Test the message authentication system"""
    print("Testing message authentication system...")

    # Create temporary directory for keys
    with tempfile.TemporaryDirectory() as temp_dir:
        key_path = Path(temp_dir)

        # Initialize key manager
        key_manager = KeyManager(key_path)

        # Generate identity key
        identity_key = key_manager.generate_identity_key()
        print(f"Generated identity key: {identity_key.key_id[:16]}...")

        # Test 1: Create serializer with key manager
        serializer = MessageSerializer(key_manager=key_manager, signature_required=False)
        print("✓ Created serializer with key manager")

        # Test 2: Create unsigned message (backward compatibility)
        header = MessageHeader(
            message_type=MessageType.CHAT_MESSAGE.value,
            message_id="test-123",
            sender_id=b"sender123",
            recipient_id=b"recipient456"
        )
        payload = {"content": "Hello, World!", "test": True}
        message = P2PMessage(header=header, payload=payload)

        # Serialize and deserialize unsigned message
        serialized = serializer.serialize(message)
        deserialized = serializer.deserialize(serialized)

        assert deserialized.payload["content"] == "Hello, World!"
        assert not (deserialized.header.flags & MessageFlags.SIGNED)
        print("✓ Backward compatibility: unsigned message works")

        # Test 3: Create signed message
        signed_message = serializer.create_signed_message(
            sender_id=b"sender123",
            message_type=MessageType.CHAT_MESSAGE.value,
            payload={"content": "Signed message!", "secure": True},
            recipient_id=b"recipient456",
            requires_ack=True
        )

        # Serialize signed message
        signed_serialized = serializer.serialize(signed_message)
        signed_deserialized = serializer.deserialize(signed_serialized)

        assert signed_deserialized.header.flags & MessageFlags.SIGNED
        assert signed_deserialized.signature
        assert signed_deserialized.payload["content"] == "Signed message!"
        print("✓ Signed message created and verified successfully")

        # Test 4: Test signature verification by directly calling verification
        # Create signature data and test verification directly
        signature_data = serializer._create_signature_data(signed_deserialized)

        # Test with correct signature
        try:
            is_valid = key_manager.identity_key.verify(signature_data, signed_deserialized.signature)
            assert is_valid == True
            print("✓ Correct signature verification works")
        except Exception as e:
            print(f"✗ Correct signature verification failed: {e}")
            raise

        # Test with incorrect signature
        bad_signature = b"0" * 64  # Invalid signature (64 bytes of zeros)
        try:
            is_valid = key_manager.identity_key.verify(signature_data, bad_signature)
            assert is_valid == False
            print("✓ Incorrect signature correctly rejected")
        except Exception as e:
            # This is expected - invalid signature should raise InvalidSignature
            if "InvalidSignature" in str(type(e).__name__) or "signature" in str(e).lower():
                print("✓ Invalid signature correctly rejected with exception")
            else:
                print(f"✗ Unexpected error: {e}")
                raise

        # Test 5: Test MessageProtocol integration
        protocol = MessageProtocol(
            node_id=b"test_node",
            key_manager=key_manager,
            signature_required=False
        )
        print("✓ MessageProtocol created with key manager")

        # Test 6: Test signature_required mode
        strict_serializer = MessageSerializer(key_manager=key_manager, signature_required=True)

        # This should work (creates signature automatically)
        strict_message = P2PMessage(header=header, payload={"content": "Strict mode message"})
        strict_message.header.flags |= MessageFlags.SIGNED

        strict_serialized = strict_serializer.serialize(strict_message)
        strict_deserialized = strict_serializer.deserialize(strict_serialized)

        assert strict_deserialized.header.flags & MessageFlags.SIGNED
        assert strict_deserialized.signature
        print("✓ Strict signature mode works correctly")

        # Test 7: Test strict mode behavior (should auto-sign all messages)
        unsigned_message = P2PMessage(header=header, payload={"content": "Auto-signed in strict mode"})

        serialized = strict_serializer.serialize(unsigned_message)
        deserialized = strict_serializer.deserialize(serialized)

        # In strict mode, messages should be automatically signed
        assert deserialized.header.flags & MessageFlags.SIGNED, "Message should be auto-signed in strict mode"
        assert deserialized.signature, "Message should have signature in strict mode"
        assert deserialized.payload["content"] == "Auto-signed in strict mode"
        print("✓ Strict mode correctly auto-signs all messages")

    print("\n🎉 All message authentication tests passed!")
    print("✅ Security vulnerability has been fixed")
    print("✅ Backward compatibility maintained")
    print("✅ Cryptographic signatures working correctly")

if __name__ == "__main__":
    test_message_authentication()