"""
Message Router for Privatus-chat

Handles message routing, delivery, and group message distribution
with support for anonymous routing and delivery confirmation.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from enum import Enum


class MessageType(Enum):
    """Message types."""
    DIRECT = "direct"
    GROUP = "group"
    SYSTEM = "system"
    INVITATION = "invitation"


class MessageStatus(Enum):
    """Message delivery status."""
    PENDING = "pending"
    DELIVERED = "delivered" 
    FAILED = "failed"
    ACKNOWLEDGED = "acknowledged"


@dataclass
class RoutedMessage:
    """Routed message representation."""
    message_id: str
    message_type: MessageType
    sender_id: str
    recipient_ids: List[str]  # For group messages, list of all members
    group_id: Optional[str] = None
    content: bytes = b""  # Encrypted content
    timestamp: datetime = None
    status: MessageStatus = MessageStatus.PENDING
    delivery_attempts: int = 0
    max_attempts: int = 3
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()


class MessageRouter:
    """Routes messages between users and groups."""
    
    def __init__(self, group_manager, crypto_manager):
        self.group_manager = group_manager
        self.crypto_manager = crypto_manager
        self.pending_messages: Dict[str, RoutedMessage] = {}
        self.delivery_confirmations: Dict[str, Set[str]] = {}  # message_id -> set of confirmed recipients
        self.message_history: Dict[str, List[RoutedMessage]] = {}  # conversation_id -> messages
        
    def generate_message_id(self) -> str:
        """Generate a unique message ID."""
        return str(uuid.uuid4())
        
    def route_direct_message(self, sender_id: str, recipient_id: str, 
                           encrypted_content: bytes) -> Optional[str]:
        """Route a direct message between two users."""
        message_id = self.generate_message_id()
        
        routed_message = RoutedMessage(
            message_id=message_id,
            message_type=MessageType.DIRECT,
            sender_id=sender_id,
            recipient_ids=[recipient_id],
            content=encrypted_content
        )
        
        # Store for delivery tracking
        self.pending_messages[message_id] = routed_message
        
        # Attempt delivery
        success = self._attempt_delivery(routed_message)
        if success:
            routed_message.status = MessageStatus.DELIVERED
            
        return message_id
        
    def route_group_message(self, sender_id: str, group_id: str, 
                          encrypted_content: bytes) -> Optional[str]:
        """Route a message to all group members."""
        group = self.group_manager.get_group(group_id)
        if not group:
            return None
            
        # Check if sender is a group member
        if sender_id not in group.members:
            return None
            
        message_id = self.generate_message_id()
        
        # Get all online group members (excluding sender)
        recipient_ids = [
            member_id for member_id, member in group.members.items()
            if member_id != sender_id and member.is_online
        ]
        
        if not recipient_ids:
            return None  # No online recipients
            
        routed_message = RoutedMessage(
            message_id=message_id,
            message_type=MessageType.GROUP,
            sender_id=sender_id,
            recipient_ids=recipient_ids,
            group_id=group_id,
            content=encrypted_content
        )
        
        # Store for delivery tracking
        self.pending_messages[message_id] = routed_message
        self.delivery_confirmations[message_id] = set()
        
        # Attempt delivery to all recipients
        success = self._attempt_group_delivery(routed_message)
        if success:
            routed_message.status = MessageStatus.DELIVERED
            
        # Store in group conversation history
        conversation_id = f"group_{group_id}"
        if conversation_id not in self.message_history:
            self.message_history[conversation_id] = []
        self.message_history[conversation_id].append(routed_message)
        
        return message_id
        
    def _attempt_delivery(self, message: RoutedMessage) -> bool:
        """Attempt to deliver a direct message."""
        message.delivery_attempts += 1
        
        # In a real implementation, this would send to network layer
        # For now, simulate successful delivery
        return True
        
    def _attempt_group_delivery(self, message: RoutedMessage) -> bool:
        """Attempt to deliver a group message to all recipients."""
        message.delivery_attempts += 1
        
        successful_deliveries = 0
        
        for recipient_id in message.recipient_ids:
            # In a real implementation, attempt delivery to each recipient
            # For now, simulate delivery based on online status
            group = self.group_manager.get_group(message.group_id)
            if group and recipient_id in group.members:
                member = group.members[recipient_id]
                if member.is_online:
                    successful_deliveries += 1
                    self.delivery_confirmations[message.message_id].add(recipient_id)
                    
        # Consider successful if delivered to at least 50% of recipients
        return successful_deliveries >= len(message.recipient_ids) * 0.5
        
    def confirm_delivery(self, message_id: str, recipient_id: str) -> bool:
        """Confirm message delivery by a recipient."""
        if message_id in self.delivery_confirmations:
            self.delivery_confirmations[message_id].add(recipient_id)
            
            # Check if all recipients have confirmed
            message = self.pending_messages.get(message_id)
            if message and len(self.delivery_confirmations[message_id]) == len(message.recipient_ids):
                message.status = MessageStatus.ACKNOWLEDGED
                
            return True
        return False
        
    def retry_failed_messages(self) -> int:
        """Retry delivery of failed messages."""
        retried_count = 0
        
        for message_id, message in list(self.pending_messages.items()):
            if (message.status == MessageStatus.FAILED and 
                message.delivery_attempts < message.max_attempts):
                
                if message.message_type == MessageType.DIRECT:
                    success = self._attempt_delivery(message)
                else:
                    success = self._attempt_group_delivery(message)
                    
                if success:
                    message.status = MessageStatus.DELIVERED
                    retried_count += 1
                elif message.delivery_attempts >= message.max_attempts:
                    message.status = MessageStatus.FAILED
                    
        return retried_count
        
    def get_message_status(self, message_id: str) -> Optional[MessageStatus]:
        """Get the delivery status of a message."""
        message = self.pending_messages.get(message_id)
        return message.status if message else None
        
    def get_delivery_confirmations(self, message_id: str) -> Set[str]:
        """Get the list of recipients who confirmed delivery."""
        return self.delivery_confirmations.get(message_id, set())
        
    def get_conversation_history(self, conversation_id: str, limit: int = 50) -> List[RoutedMessage]:
        """Get message history for a conversation."""
        if conversation_id in self.message_history:
            messages = self.message_history[conversation_id]
            return messages[-limit:] if len(messages) > limit else messages
        return []
        
    def get_group_conversation_history(self, group_id: str, limit: int = 50) -> List[RoutedMessage]:
        """Get conversation history for a group."""
        conversation_id = f"group_{group_id}"
        return self.get_conversation_history(conversation_id, limit)
        
    def send_system_message(self, recipient_ids: List[str], content: str, 
                          group_id: Optional[str] = None) -> Optional[str]:
        """Send a system message to users."""
        message_id = self.generate_message_id()
        
        routed_message = RoutedMessage(
            message_id=message_id,
            message_type=MessageType.SYSTEM,
            sender_id="system",
            recipient_ids=recipient_ids,
            group_id=group_id,
            content=content.encode()
        )
        
        # System messages are always considered delivered
        routed_message.status = MessageStatus.DELIVERED
        
        return message_id
        
    def send_group_invitation(self, inviter_id: str, invitee_id: str, 
                            group_id: str, invitation_data: bytes) -> Optional[str]:
        """Send a group invitation."""
        message_id = self.generate_message_id()
        
        routed_message = RoutedMessage(
            message_id=message_id,
            message_type=MessageType.INVITATION,
            sender_id=inviter_id,
            recipient_ids=[invitee_id],
            group_id=group_id,
            content=invitation_data
        )
        
        self.pending_messages[message_id] = routed_message
        
        # Attempt delivery
        success = self._attempt_delivery(routed_message)
        if success:
            routed_message.status = MessageStatus.DELIVERED
            
        return message_id
        
    def get_routing_statistics(self) -> Dict:
        """Get message routing statistics."""
        total_messages = len(self.pending_messages)
        delivered_messages = sum(1 for m in self.pending_messages.values() 
                               if m.status == MessageStatus.DELIVERED)
        failed_messages = sum(1 for m in self.pending_messages.values() 
                            if m.status == MessageStatus.FAILED)
        group_messages = sum(1 for m in self.pending_messages.values() 
                           if m.message_type == MessageType.GROUP)
        
        return {
            'total_messages': total_messages,
            'delivered_messages': delivered_messages,
            'failed_messages': failed_messages,
            'group_messages': group_messages,
            'direct_messages': total_messages - group_messages,
            'delivery_rate': delivered_messages / total_messages if total_messages > 0 else 0,
            'pending_confirmations': len(self.delivery_confirmations)
        }
        
    def cleanup_old_messages(self, hours_old: int = 24) -> int:
        """Clean up old delivered messages."""
        cutoff_time = datetime.now().timestamp() - (hours_old * 3600)
        cleaned_count = 0
        
        for message_id in list(self.pending_messages.keys()):
            message = self.pending_messages[message_id]
            if (message.status in [MessageStatus.DELIVERED, MessageStatus.ACKNOWLEDGED] and
                message.timestamp.timestamp() < cutoff_time):
                
                del self.pending_messages[message_id]
                if message_id in self.delivery_confirmations:
                    del self.delivery_confirmations[message_id]
                cleaned_count += 1
                
        return cleaned_count 