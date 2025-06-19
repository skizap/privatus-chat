"""
Group Chat Management for Privatus-chat

Implements secure multi-party group chat functionality with anonymous participation,
member management, and group identity preservation.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

from ..crypto import SecureRandom


class GroupRole(Enum):
    """Group member roles."""
    OWNER = "owner"
    ADMIN = "admin" 
    MEMBER = "member"


class GroupType(Enum):
    """Group types."""
    PUBLIC = "public"      # Anyone can join
    PRIVATE = "private"    # Invitation only
    SECRET = "secret"      # Hidden group


@dataclass
class GroupMember:
    """Group member representation."""
    member_id: str
    display_name: str
    public_key: str
    role: GroupRole = GroupRole.MEMBER
    joined_at: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    is_online: bool = False
    anonymous_id: Optional[str] = None  # Anonymous identity for this group
    
    def update_activity(self):
        """Update last activity timestamp."""
        self.last_active = datetime.now()


@dataclass
class Group:
    """Group chat representation."""
    group_id: str
    name: str
    description: str = ""
    group_type: GroupType = GroupType.PRIVATE
    created_at: datetime = field(default_factory=datetime.now)
    created_by: Optional[str] = None
    members: Dict[str, GroupMember] = field(default_factory=dict)
    max_members: int = 100
    is_anonymous: bool = True
    group_key_version: int = 1
    
    def add_member(self, member: GroupMember) -> bool:
        """Add a member to the group."""
        if len(self.members) >= self.max_members:
            return False
            
        if member.member_id not in self.members:
            self.members[member.member_id] = member
            return True
        return False
        
    def remove_member(self, member_id: str) -> bool:
        """Remove a member from the group."""
        if member_id in self.members:
            del self.members[member_id]
            return True
        return False
        
    def get_member(self, member_id: str) -> Optional[GroupMember]:
        """Get a member by ID."""
        return self.members.get(member_id)
        
    def get_members_by_role(self, role: GroupRole) -> List[GroupMember]:
        """Get all members with a specific role."""
        return [member for member in self.members.values() if member.role == role]
        
    def get_online_members(self) -> List[GroupMember]:
        """Get all online members."""
        return [member for member in self.members.values() if member.is_online]
        
    def update_member_status(self, member_id: str, is_online: bool):
        """Update member online status."""
        if member_id in self.members:
            self.members[member_id].is_online = is_online
            if is_online:
                self.members[member_id].update_activity()
                
    def promote_member(self, member_id: str, new_role: GroupRole, promoted_by: str) -> bool:
        """Promote/demote a member's role."""
        if member_id not in self.members or promoted_by not in self.members:
            return False
            
        promoter = self.members[promoted_by]
        target = self.members[member_id]
        
        # Check permissions
        if promoter.role == GroupRole.OWNER:
            target.role = new_role
            return True
        elif promoter.role == GroupRole.ADMIN and new_role == GroupRole.MEMBER:
            target.role = new_role
            return True
            
        return False


class GroupChatManager:
    """Manager for group chat operations."""
    
    def __init__(self, storage_manager, crypto_manager):
        self.storage = storage_manager
        self.crypto = crypto_manager
        self.groups: Dict[str, Group] = {}
        self.user_groups: Dict[str, Set[str]] = {}  # user_id -> set of group_ids
        
    def generate_group_id(self) -> str:
        """Generate a unique group ID."""
        return str(uuid.uuid4())
        
    def generate_anonymous_id(self) -> str:
        """Generate an anonymous member ID for a group."""
        return SecureRandom().generate_bytes(16).hex()
        
    def create_group(self, creator_id: str, name: str, description: str = "", 
                    group_type: GroupType = GroupType.PRIVATE, is_anonymous: bool = True) -> Optional[str]:
        """Create a new group."""
        group_id = self.generate_group_id()
        
        # Create creator as owner
        creator_member = GroupMember(
            member_id=creator_id,
            display_name="Group Creator",  # In anonymous groups, use generic names
            public_key="",  # Will be filled by crypto system
            role=GroupRole.OWNER,
            anonymous_id=self.generate_anonymous_id() if is_anonymous else None
        )
        
        group = Group(
            group_id=group_id,
            name=name,
            description=description,
            group_type=group_type,
            created_by=creator_id,
            is_anonymous=is_anonymous
        )
        
        group.add_member(creator_member)
        
        # Store group
        self.groups[group_id] = group
        
        # Update user's group membership
        if creator_id not in self.user_groups:
            self.user_groups[creator_id] = set()
        self.user_groups[creator_id].add(group_id)
        
        return group_id
        
    def join_group(self, group_id: str, user_id: str, display_name: str, 
                  public_key: str, invitation_code: Optional[str] = None) -> bool:
        """Join a group."""
        if group_id not in self.groups:
            return False
            
        group = self.groups[group_id]
        
        # Check if group is full
        if len(group.members) >= group.max_members:
            return False
            
        # Check if user is already a member
        if user_id in group.members:
            return False
            
        # For private groups, would normally check invitation
        # For now, allow joining any group for demo purposes
        
        member = GroupMember(
            member_id=user_id,
            display_name=display_name if not group.is_anonymous else f"Member_{len(group.members)+1}",
            public_key=public_key,
            anonymous_id=self.generate_anonymous_id() if group.is_anonymous else None
        )
        
        if group.add_member(member):
            # Update user's group membership
            if user_id not in self.user_groups:
                self.user_groups[user_id] = set()
            self.user_groups[user_id].add(group_id)
            return True
            
        return False
        
    def leave_group(self, group_id: str, user_id: str) -> bool:
        """Leave a group."""
        if group_id not in self.groups:
            return False
            
        group = self.groups[group_id]
        
        if group.remove_member(user_id):
            # Update user's group membership
            if user_id in self.user_groups:
                self.user_groups[user_id].discard(group_id)
                
            # If group is empty or only owner left, could delete group
            if len(group.members) == 0:
                del self.groups[group_id]
                
            return True
            
        return False
        
    def get_group(self, group_id: str) -> Optional[Group]:
        """Get a group by ID."""
        return self.groups.get(group_id)
        
    def get_user_groups(self, user_id: str) -> List[Group]:
        """Get all groups a user is member of."""
        if user_id not in self.user_groups:
            return []
            
        return [self.groups[group_id] for group_id in self.user_groups[user_id] 
                if group_id in self.groups]
        
    def get_group_members(self, group_id: str) -> List[GroupMember]:
        """Get all members of a group."""
        if group_id not in self.groups:
            return []
            
        return list(self.groups[group_id].members.values())
        
    def update_member_status(self, group_id: str, user_id: str, is_online: bool):
        """Update member online status in a group."""
        if group_id in self.groups:
            self.groups[group_id].update_member_status(user_id, is_online)
            
    def invite_to_group(self, group_id: str, inviter_id: str, invitee_public_key: str) -> Optional[str]:
        """Generate an invitation code for a group."""
        if group_id not in self.groups:
            return None
            
        group = self.groups[group_id]
        inviter = group.get_member(inviter_id)
        
        if not inviter or inviter.role == GroupRole.MEMBER:
            return None  # Only admins and owners can invite
            
        # Generate invitation code
        invitation_code = SecureRandom().generate_bytes(16).hex()
        
        # In a real implementation, this would be stored with expiration
        # For now, return the code
        return invitation_code
        
    def get_group_stats(self) -> Dict:
        """Get group chat statistics."""
        total_groups = len(self.groups)
        total_members = sum(len(group.members) for group in self.groups.values())
        anonymous_groups = sum(1 for group in self.groups.values() if group.is_anonymous)
        
        return {
            'total_groups': total_groups,
            'total_members': total_members,
            'anonymous_groups': anonymous_groups,
            'public_groups': sum(1 for g in self.groups.values() if g.group_type == GroupType.PUBLIC),
            'private_groups': sum(1 for g in self.groups.values() if g.group_type == GroupType.PRIVATE),
            'secret_groups': sum(1 for g in self.groups.values() if g.group_type == GroupType.SECRET)
        } 