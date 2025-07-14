"""
Slack Groups Integration for Permission System.

This module provides integration with Slack's native group/usergroup functionality
to automatically sync permissions based on Slack group memberships.
"""

import logging
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timedelta

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from ..core.user_manager import UserManager, UserProfile
from ..utils.exceptions import SlackIntegrationError, UserNotFoundError, ConfigurationError

logger = logging.getLogger(__name__)


class SlackGroupsIntegration:
    """
    Integrates with Slack groups to automatically manage user permissions.
    
    This class syncs user information and group memberships from Slack,
    automatically granting permissions based on group configurations.
    """
    
    def __init__(
        self,
        slack_client: WebClient,
        user_manager: UserManager,
        group_permission_mapping: Optional[Dict[str, List[str]]] = None,
        sync_interval_minutes: int = 60,
        auto_create_users: bool = True
    ):
        """
        Initialize Slack Groups Integration.
        
        Args:
            slack_client: Slack WebClient instance
            user_manager: User manager instance
            group_permission_mapping: Mapping of Slack groups to permissions
            sync_interval_minutes: How often to sync from Slack
            auto_create_users: Whether to auto-create users from Slack
        """
        self.slack_client = slack_client
        self.user_manager = user_manager
        self.group_permission_mapping = group_permission_mapping or {}
        self.sync_interval = timedelta(minutes=sync_interval_minutes)
        self.auto_create_users = auto_create_users
        
        # Cache for Slack data
        self._user_cache: Dict[str, Dict[str, Any]] = {}
        self._group_cache: Dict[str, Dict[str, Any]] = {}
        self._last_sync: Optional[datetime] = None
        
        # Statistics
        self._sync_count = 0
        self._users_synced = 0
        self._groups_synced = 0
        self._errors = 0
        
        logger.info(
            "SlackGroupsIntegration initialized",
            extra={
                "sync_interval_minutes": sync_interval_minutes,
                "auto_create_users": auto_create_users,
                "group_mappings": len(self.group_permission_mapping)
            }
        )
    
    def sync_user(self, user_id: str, force: bool = False) -> Optional[UserProfile]:
        """
        Sync a single user from Slack.
        
        Args:
            user_id: Slack user ID
            force: Force sync even if recently synced
            
        Returns:
            UserProfile or None: Synced user profile
        """
        try:
            # Check if we need to sync
            if not force and self._is_user_recently_synced(user_id):
                existing_user = self.user_manager.get_user_safe(user_id)
                if existing_user:
                    return existing_user
            
            # Get user info from Slack
            slack_user = self._get_slack_user(user_id)
            if not slack_user:
                return None
            
            # Get user's group memberships
            user_groups = self._get_user_groups(user_id)
            
            # Calculate permissions from groups
            permissions = self._calculate_permissions_from_groups(user_groups)
            
            # Create or update user
            existing_user = self.user_manager.get_user_safe(user_id)
            
            if existing_user:
                # Update existing user
                user = self._update_user_from_slack(existing_user, slack_user, user_groups, permissions)
            else:
                # Create new user if auto-create is enabled
                if self.auto_create_users:
                    user = self._create_user_from_slack(slack_user, user_groups, permissions)
                else:
                    logger.warning(f"User {user_id} not found and auto-create disabled")
                    return None
            
            # Update cache
            self._user_cache[user_id] = {
                "slack_data": slack_user,
                "groups": user_groups,
                "last_sync": datetime.utcnow()
            }
            
            self._users_synced += 1
            
            logger.info(
                "User synced from Slack",
                extra={
                    "user_id": user_id,
                    "username": user.username,
                    "groups": list(user.groups),
                    "permissions": list(user.permissions)
                }
            )
            
            return user
            
        except Exception as e:
            self._errors += 1
            logger.error(f"Error syncing user {user_id}: {e}", exc_info=True)
            return None
    
    def sync_all_users(self, force: bool = False) -> Dict[str, Any]:
        """
        Sync all users from Slack.
        
        Args:
            force: Force sync even if recently synced
            
        Returns:
            Dict[str, Any]: Sync results
        """
        self._sync_count += 1
        start_time = datetime.utcnow()
        
        try:
            # Check if we need to sync
            if not force and self._last_sync and datetime.utcnow() - self._last_sync < self.sync_interval:
                return {
                    "skipped": True,
                    "reason": "Recently synced",
                    "last_sync": self._last_sync.isoformat()
                }
            
            # Get all users from Slack
            slack_users = self._get_all_slack_users()
            
            synced_users = []
            failed_users = []
            
            for slack_user in slack_users:
                user_id = slack_user["id"]
                try:
                    user = self.sync_user(user_id, force=True)
                    if user:
                        synced_users.append(user_id)
                    else:
                        failed_users.append(user_id)
                except Exception as e:
                    failed_users.append(user_id)
                    logger.error(f"Failed to sync user {user_id}: {e}")
            
            self._last_sync = datetime.utcnow()
            
            result = {
                "success": True,
                "synced_users": len(synced_users),
                "failed_users": len(failed_users),
                "total_users": len(slack_users),
                "duration_seconds": (datetime.utcnow() - start_time).total_seconds(),
                "sync_timestamp": self._last_sync.isoformat()
            }
            
            logger.info("Bulk user sync completed", extra=result)
            return result
            
        except Exception as e:
            self._errors += 1
            logger.error(f"Error in bulk user sync: {e}", exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "duration_seconds": (datetime.utcnow() - start_time).total_seconds()
            }
    
    def add_group_permission_mapping(self, group_id: str, permissions: List[str]):
        """
        Add or update group permission mapping.
        
        Args:
            group_id: Slack group/usergroup ID
            permissions: List of permissions to grant to group members
        """
        self.group_permission_mapping[group_id] = permissions
        logger.info(f"Added group mapping: {group_id} -> {permissions}")
        
        # Invalidate cache for affected users
        self._invalidate_group_cache(group_id)
    
    def remove_group_permission_mapping(self, group_id: str):
        """
        Remove group permission mapping.
        
        Args:
            group_id: Slack group/usergroup ID
        """
        if group_id in self.group_permission_mapping:
            del self.group_permission_mapping[group_id]
            logger.info(f"Removed group mapping: {group_id}")
            
            # Invalidate cache for affected users
            self._invalidate_group_cache(group_id)
    
    def get_group_members(self, group_id: str) -> List[str]:
        """
        Get members of a Slack group.
        
        Args:
            group_id: Slack group/usergroup ID
            
        Returns:
            List[str]: List of user IDs in the group
        """
        try:
            response = self.slack_client.usergroups_users_list(usergroup=group_id)
            return response["users"]
        except SlackApiError as e:
            logger.error(f"Error getting group members for {group_id}: {e}")
            return []
    
    def _get_slack_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user information from Slack API."""
        try:
            response = self.slack_client.users_info(user=user_id)
            if response["ok"]:
                return response["user"]
            else:
                logger.warning(f"Failed to get Slack user {user_id}: {response.get('error')}")
                return None
        except SlackApiError as e:
            logger.error(f"Slack API error getting user {user_id}: {e}")
            return None
    
    def _get_all_slack_users(self) -> List[Dict[str, Any]]:
        """Get all users from Slack."""
        try:
            users = []
            cursor = None
            
            while True:
                response = self.slack_client.users_list(cursor=cursor, limit=200)
                if not response["ok"]:
                    break
                
                users.extend(response["members"])
                
                cursor = response.get("response_metadata", {}).get("next_cursor")
                if not cursor:
                    break
            
            # Filter out bots and deleted users
            return [
                user for user in users
                if not user.get("is_bot", False) and not user.get("deleted", False)
            ]
            
        except SlackApiError as e:
            logger.error(f"Error getting all Slack users: {e}")
            return []
    
    def _get_user_groups(self, user_id: str) -> Set[str]:
        """Get groups/usergroups that a user belongs to."""
        try:
            groups = set()
            
            # Get usergroups
            response = self.slack_client.usergroups_list()
            if response["ok"]:
                for usergroup in response["usergroups"]:
                    group_id = usergroup["id"]
                    members = self.get_group_members(group_id)
                    if user_id in members:
                        groups.add(group_id)
            
            return groups
            
        except SlackApiError as e:
            logger.error(f"Error getting user groups for {user_id}: {e}")
            return set()
    
    def _calculate_permissions_from_groups(self, user_groups: Set[str]) -> Set[str]:
        """Calculate permissions based on group memberships."""
        permissions = set()
        
        for group_id in user_groups:
            if group_id in self.group_permission_mapping:
                permissions.update(self.group_permission_mapping[group_id])
        
        return permissions
    
    def _create_user_from_slack(
        self,
        slack_user: Dict[str, Any],
        user_groups: Set[str],
        permissions: Set[str]
    ) -> UserProfile:
        """Create a new user from Slack data."""
        profile = slack_user.get("profile", {})
        
        return self.user_manager.create_user(
            user_id=slack_user["id"],
            username=slack_user.get("name"),
            email=profile.get("email"),
            display_name=profile.get("display_name") or profile.get("real_name"),
            permissions=list(permissions),
            groups=list(user_groups),
            is_admin=False,  # Admin status should be set separately
            metadata={
                "slack_profile": profile,
                "synced_from_slack": True,
                "last_slack_sync": datetime.utcnow().isoformat()
            }
        )
    
    def _update_user_from_slack(
        self,
        user: UserProfile,
        slack_user: Dict[str, Any],
        user_groups: Set[str],
        permissions: Set[str]
    ) -> UserProfile:
        """Update existing user with Slack data."""
        profile = slack_user.get("profile", {})
        
        # Update basic info
        user.username = slack_user.get("name")
        user.email = profile.get("email")
        user.display_name = profile.get("display_name") or profile.get("real_name")
        
        # Update groups
        user.groups = user_groups
        
        # Update permissions (merge with existing to preserve manual grants)
        user.permissions.update(permissions)
        
        # Update metadata
        user.metadata.update({
            "slack_profile": profile,
            "last_slack_sync": datetime.utcnow().isoformat()
        })
        
        return user
    
    def _is_user_recently_synced(self, user_id: str) -> bool:
        """Check if user was recently synced."""
        if user_id not in self._user_cache:
            return False
        
        last_sync = self._user_cache[user_id].get("last_sync")
        if not last_sync:
            return False
        
        return datetime.utcnow() - last_sync < self.sync_interval
    
    def _invalidate_group_cache(self, group_id: str):
        """Invalidate cache for users in a specific group."""
        # This is a simplified implementation
        # In practice, you'd want to track group memberships more efficiently
        self._user_cache.clear()
        logger.debug(f"Invalidated cache for group {group_id}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get integration statistics."""
        return {
            "sync_stats": {
                "total_syncs": self._sync_count,
                "users_synced": self._users_synced,
                "groups_synced": self._groups_synced,
                "errors": self._errors,
                "last_sync": self._last_sync.isoformat() if self._last_sync else None
            },
            "cache_stats": {
                "cached_users": len(self._user_cache),
                "cached_groups": len(self._group_cache)
            },
            "configuration": {
                "sync_interval_minutes": self.sync_interval.total_seconds() / 60,
                "auto_create_users": self.auto_create_users,
                "group_mappings": len(self.group_permission_mapping)
            }
        }
