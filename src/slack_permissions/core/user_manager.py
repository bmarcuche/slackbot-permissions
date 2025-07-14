"""
User Manager for Slack Permission System.

This module manages user information, permissions, and group memberships.
It provides the core user management functionality for the permission system.
"""

import logging
from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import json

from ..utils.exceptions import UserNotFoundError, ValidationError, ConfigurationError

logger = logging.getLogger(__name__)


@dataclass
class UserProfile:
    """
    Represents a user profile with permissions and metadata.
    
    This class encapsulates all user information including permissions,
    group memberships, and activity tracking.
    """
    user_id: str
    username: Optional[str] = None
    email: Optional[str] = None
    display_name: Optional[str] = None
    permissions: Set[str] = field(default_factory=set)
    groups: Set[str] = field(default_factory=set)
    is_admin: bool = False
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate user profile after initialization."""
        if not self.user_id:
            raise ValidationError("User ID cannot be empty")
        
        # Ensure permissions and groups are sets
        if isinstance(self.permissions, (list, tuple)):
            self.permissions = set(self.permissions)
        if isinstance(self.groups, (list, tuple)):
            self.groups = set(self.groups)
    
    def has_permission(self, permission: str) -> bool:
        """Check if user has a specific permission."""
        return permission in self.permissions or self.is_admin
    
    def has_any_permission(self, permissions: List[str]) -> bool:
        """Check if user has any of the specified permissions."""
        return self.is_admin or any(perm in self.permissions for perm in permissions)
    
    def has_all_permissions(self, permissions: List[str]) -> bool:
        """Check if user has all of the specified permissions."""
        return self.is_admin or all(perm in self.permissions for perm in permissions)
    
    def is_in_group(self, group: str) -> bool:
        """Check if user is in a specific group."""
        return group in self.groups
    
    def add_permission(self, permission: str):
        """Add a permission to the user."""
        self.permissions.add(permission)
        logger.debug(f"Added permission '{permission}' to user {self.user_id}")
    
    def remove_permission(self, permission: str):
        """Remove a permission from the user."""
        self.permissions.discard(permission)
        logger.debug(f"Removed permission '{permission}' from user {self.user_id}")
    
    def add_group(self, group: str):
        """Add user to a group."""
        self.groups.add(group)
        logger.debug(f"Added user {self.user_id} to group '{group}'")
    
    def remove_group(self, group: str):
        """Remove user from a group."""
        self.groups.discard(group)
        logger.debug(f"Removed user {self.user_id} from group '{group}'")
    
    def update_last_seen(self):
        """Update the last seen timestamp."""
        self.last_seen = datetime.utcnow()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert user profile to dictionary."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "display_name": self.display_name,
            "permissions": list(self.permissions),
            "groups": list(self.groups),
            "is_admin": self.is_admin,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat(),
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "metadata": self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'UserProfile':
        """Create user profile from dictionary."""
        # Parse datetime fields
        created_at = datetime.fromisoformat(data.get('created_at', datetime.utcnow().isoformat()))
        last_seen = None
        if data.get('last_seen'):
            last_seen = datetime.fromisoformat(data['last_seen'])
        
        return cls(
            user_id=data['user_id'],
            username=data.get('username'),
            email=data.get('email'),
            display_name=data.get('display_name'),
            permissions=set(data.get('permissions', [])),
            groups=set(data.get('groups', [])),
            is_admin=data.get('is_admin', False),
            is_active=data.get('is_active', True),
            created_at=created_at,
            last_seen=last_seen,
            metadata=data.get('metadata', {})
        )


class UserManager:
    """
    Manages user profiles, permissions, and group memberships.
    
    This class provides the core user management functionality including
    user lookup, permission management, and group operations.
    """
    
    def __init__(self):
        self._users: Dict[str, UserProfile] = {}
        self._groups: Dict[str, Set[str]] = {}  # group_name -> set of user_ids
        self._group_permissions: Dict[str, Set[str]] = {}  # group_name -> set of permissions
        self._admin_users: Set[str] = set()
        
        logger.info("UserManager initialized")
    
    def create_user(
        self,
        user_id: str,
        username: Optional[str] = None,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        permissions: Optional[List[str]] = None,
        groups: Optional[List[str]] = None,
        is_admin: bool = False,
        is_active: bool = True,
        metadata: Optional[Dict[str, Any]] = None
    ) -> UserProfile:
        """
        Create a new user profile.
        
        Args:
            user_id: Unique user identifier
            username: User's username
            email: User's email address
            display_name: User's display name
            permissions: List of permissions to grant
            groups: List of groups to add user to
            is_admin: Whether user is an admin
            is_active: Whether user is active
            metadata: Additional user metadata
            
        Returns:
            UserProfile: The created user profile
            
        Raises:
            ConfigurationError: If user already exists
        """
        if user_id in self._users:
            raise ConfigurationError(
                f"User '{user_id}' already exists",
                config_key="user_id",
                config_value=user_id
            )
        
        user = UserProfile(
            user_id=user_id,
            username=username,
            email=email,
            display_name=display_name,
            permissions=set(permissions or []),
            groups=set(groups or []),
            is_admin=is_admin,
            is_active=is_active,
            metadata=metadata or {}
        )
        
        self._users[user_id] = user
        
        # Add to admin set if needed
        if is_admin:
            self._admin_users.add(user_id)
        
        # Add to groups
        for group in user.groups:
            if group not in self._groups:
                self._groups[group] = set()
            self._groups[group].add(user_id)
        
        logger.info(
            "User created",
            extra={
                "user_id": user_id,
                "username": username,
                "permissions": list(user.permissions),
                "groups": list(user.groups),
                "is_admin": is_admin
            }
        )
        
        return user
    
    def get_user(self, user_id: str) -> UserProfile:
        """
        Get user profile by ID.
        
        Args:
            user_id: User identifier
            
        Returns:
            UserProfile: The user profile
            
        Raises:
            UserNotFoundError: If user doesn't exist
        """
        if user_id not in self._users:
            raise UserNotFoundError(
                f"User '{user_id}' not found",
                user_id=user_id
            )
        
        user = self._users[user_id]
        user.update_last_seen()
        return user
    
    def get_user_safe(self, user_id: str) -> Optional[UserProfile]:
        """
        Get user profile by ID without raising exception.
        
        Args:
            user_id: User identifier
            
        Returns:
            UserProfile or None: The user profile if found
        """
        try:
            return self.get_user(user_id)
        except UserNotFoundError:
            return None
    
    def update_user(
        self,
        user_id: str,
        username: Optional[str] = None,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        is_admin: Optional[bool] = None,
        is_active: Optional[bool] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> UserProfile:
        """
        Update user profile.
        
        Args:
            user_id: User identifier
            username: New username
            email: New email
            display_name: New display name
            is_admin: New admin status
            is_active: New active status
            metadata: New metadata
            
        Returns:
            UserProfile: Updated user profile
        """
        user = self.get_user(user_id)
        
        if username is not None:
            user.username = username
        if email is not None:
            user.email = email
        if display_name is not None:
            user.display_name = display_name
        if is_admin is not None:
            user.is_admin = is_admin
            if is_admin:
                self._admin_users.add(user_id)
            else:
                self._admin_users.discard(user_id)
        if is_active is not None:
            user.is_active = is_active
        if metadata is not None:
            user.metadata.update(metadata)
        
        logger.info(f"User {user_id} updated")
        return user
    
    def delete_user(self, user_id: str):
        """
        Delete a user profile.
        
        Args:
            user_id: User identifier
        """
        if user_id not in self._users:
            return
        
        user = self._users[user_id]
        
        # Remove from groups
        for group in user.groups:
            if group in self._groups:
                self._groups[group].discard(user_id)
        
        # Remove from admin set
        self._admin_users.discard(user_id)
        
        # Delete user
        del self._users[user_id]
        
        logger.info(f"User {user_id} deleted")
    
    def grant_permission(self, user_id: str, permission: str):
        """Grant a permission to a user."""
        user = self.get_user(user_id)
        user.add_permission(permission)
    
    def revoke_permission(self, user_id: str, permission: str):
        """Revoke a permission from a user."""
        user = self.get_user(user_id)
        user.remove_permission(permission)
    
    def add_user_to_group(self, user_id: str, group: str):
        """Add user to a group."""
        user = self.get_user(user_id)
        user.add_group(group)
        
        if group not in self._groups:
            self._groups[group] = set()
        self._groups[group].add(user_id)
    
    def remove_user_from_group(self, user_id: str, group: str):
        """Remove user from a group."""
        user = self.get_user(user_id)
        user.remove_group(group)
        
        if group in self._groups:
            self._groups[group].discard(user_id)
    
    def create_group(self, group_name: str, permissions: Optional[List[str]] = None):
        """
        Create a new group with permissions.
        
        Args:
            group_name: Name of the group
            permissions: List of permissions for the group
        """
        if group_name not in self._groups:
            self._groups[group_name] = set()
        
        if permissions:
            self._group_permissions[group_name] = set(permissions)
        
        logger.info(f"Group '{group_name}' created with permissions: {permissions}")
    
    def get_group_users(self, group: str) -> List[UserProfile]:
        """Get all users in a group."""
        if group not in self._groups:
            return []
        
        return [self._users[user_id] for user_id in self._groups[group] if user_id in self._users]
    
    def get_user_effective_permissions(self, user_id: str) -> Set[str]:
        """
        Get all effective permissions for a user (direct + group permissions).
        
        Args:
            user_id: User identifier
            
        Returns:
            Set[str]: All effective permissions
        """
        user = self.get_user(user_id)
        
        # Start with direct permissions
        permissions = user.permissions.copy()
        
        # Add group permissions
        for group in user.groups:
            if group in self._group_permissions:
                permissions.update(self._group_permissions[group])
        
        return permissions
    
    def user_has_permission(self, user_id: str, permission: str) -> bool:
        """
        Check if user has a specific permission (direct or through groups).
        
        Args:
            user_id: User identifier
            permission: Permission to check
            
        Returns:
            bool: True if user has permission
        """
        try:
            user = self.get_user(user_id)
            
            # Admin users have all permissions
            if user.is_admin:
                return True
            
            # Check direct permissions
            if permission in user.permissions:
                return True
            
            # Check group permissions
            for group in user.groups:
                if group in self._group_permissions and permission in self._group_permissions[group]:
                    return True
            
            return False
            
        except UserNotFoundError:
            return False
    
    def get_all_users(self, active_only: bool = True) -> List[UserProfile]:
        """
        Get all users.
        
        Args:
            active_only: Whether to return only active users
            
        Returns:
            List[UserProfile]: All users
        """
        users = list(self._users.values())
        if active_only:
            users = [user for user in users if user.is_active]
        return users
    
    def get_admin_users(self) -> List[UserProfile]:
        """Get all admin users."""
        return [self._users[user_id] for user_id in self._admin_users if user_id in self._users]
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get user manager statistics.
        
        Returns:
            Dict[str, Any]: Statistics
        """
        active_users = len([u for u in self._users.values() if u.is_active])
        
        return {
            "total_users": len(self._users),
            "active_users": active_users,
            "inactive_users": len(self._users) - active_users,
            "admin_users": len(self._admin_users),
            "total_groups": len(self._groups),
            "total_permissions": len(set().union(*[u.permissions for u in self._users.values()])),
        }
    
    def clear(self):
        """Clear all users and groups (useful for testing)."""
        self._users.clear()
        self._groups.clear()
        self._group_permissions.clear()
        self._admin_users.clear()
        logger.info("UserManager cleared")
