"""
Access Control Engine for Slack Permission System.

This module implements the core access control logic including permission
checking, caching, and security policies.
"""

import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

from .command_registry import CommandRegistry
from .user_manager import UserManager
from ..utils.exceptions import PermissionError, ValidationError

logger = logging.getLogger(__name__)


class PermissionCache:
    """
    Caches permission check results to improve performance.
    
    This class implements a time-based cache with automatic expiration
    to balance performance with security freshness.
    """
    
    def __init__(self, ttl_seconds: int = 300):  # 5 minutes default
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[bool, datetime]] = {}
        self._stats = {
            "hits": 0,
            "misses": 0,
            "evictions": 0
        }
    
    def _generate_key(self, user_id: str, permission: str, context: Optional[Dict] = None) -> str:
        """Generate cache key for permission check."""
        key_data = f"{user_id}:{permission}"
        if context:
            # Include relevant context in cache key
            context_str = str(sorted(context.items()))
            key_data += f":{context_str}"
        
        # Hash to keep key size manageable
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def get(self, user_id: str, permission: str, context: Optional[Dict] = None) -> Optional[bool]:
        """Get cached permission result."""
        key = self._generate_key(user_id, permission, context)
        
        if key in self._cache:
            result, timestamp = self._cache[key]
            
            # Check if cache entry is still valid
            if datetime.utcnow() - timestamp < timedelta(seconds=self.ttl_seconds):
                self._stats["hits"] += 1
                return result
            else:
                # Expired entry
                del self._cache[key]
                self._stats["evictions"] += 1
        
        self._stats["misses"] += 1
        return None
    
    def set(self, user_id: str, permission: str, result: bool, context: Optional[Dict] = None):
        """Cache permission result."""
        key = self._generate_key(user_id, permission, context)
        self._cache[key] = (result, datetime.utcnow())
    
    def invalidate_user(self, user_id: str):
        """Invalidate all cache entries for a user."""
        keys_to_remove = []
        for key in self._cache:
            if key.startswith(hashlib.md5(f"{user_id}:".encode()).hexdigest()[:8]):
                keys_to_remove.append(key)
        
        for key in keys_to_remove:
            del self._cache[key]
            self._stats["evictions"] += 1
    
    def clear(self):
        """Clear all cache entries."""
        evicted = len(self._cache)
        self._cache.clear()
        self._stats["evictions"] += evicted
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        total_requests = self._stats["hits"] + self._stats["misses"]
        hit_rate = self._stats["hits"] / max(total_requests, 1)
        
        return {
            "cache_size": len(self._cache),
            "hit_rate": hit_rate,
            "total_requests": total_requests,
            **self._stats
        }


class AccessControlEngine:
    """
    Core access control engine that implements permission checking logic.
    
    This class handles the actual permission validation including user
    permissions, group memberships, admin privileges, and security policies.
    """
    
    def __init__(
        self,
        command_registry: CommandRegistry,
        user_manager: UserManager,
        enable_caching: bool = True,
        cache_ttl: int = 300,
        default_deny: bool = True
    ):
        """
        Initialize the Access Control Engine.
        
        Args:
            command_registry: Command registry instance
            user_manager: User manager instance
            enable_caching: Whether to enable permission caching
            cache_ttl: Cache TTL in seconds
            default_deny: Whether to deny by default (fail-safe)
        """
        self.command_registry = command_registry
        self.user_manager = user_manager
        self.default_deny = default_deny
        self.enable_caching = enable_caching
        
        # Initialize cache if enabled
        self.cache = PermissionCache(cache_ttl) if enable_caching else None
        
        # Security policies
        self.security_policies = {
            "require_active_user": True,
            "admin_bypass_all": True,
            "log_all_checks": True,
            "rate_limit_enabled": False,
            "max_requests_per_minute": 60
        }
        
        # Rate limiting
        self._rate_limits: Dict[str, List[datetime]] = defaultdict(list)
        
        # Statistics
        self._check_count = 0
        self._grant_count = 0
        self._deny_count = 0
        
        logger.info(
            "AccessControlEngine initialized",
            extra={
                "enable_caching": enable_caching,
                "cache_ttl": cache_ttl,
                "default_deny": default_deny
            }
        )
    
    def check_permission(
        self,
        user_id: str,
        permission: str,
        command: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Check if a user has a specific permission.
        
        This is the main entry point for permission checking.
        
        Args:
            user_id: User identifier
            permission: Permission string to check
            command: Optional command name for context
            context: Additional context for permission check
            
        Returns:
            bool: True if user has permission
        """
        self._check_count += 1
        
        try:
            # Check cache first if enabled
            if self.cache:
                cached_result = self.cache.get(user_id, permission, context)
                if cached_result is not None:
                    return cached_result
            
            # Apply rate limiting if enabled
            if self.security_policies.get("rate_limit_enabled"):
                if not self._check_rate_limit(user_id):
                    logger.warning(f"Rate limit exceeded for user {user_id}")
                    return False
            
            # Perform actual permission check
            result = self._perform_permission_check(user_id, permission, command, context)
            
            # Cache result if caching enabled
            if self.cache:
                self.cache.set(user_id, permission, result, context)
            
            # Update statistics
            if result:
                self._grant_count += 1
            else:
                self._deny_count += 1
            
            # Log if enabled
            if self.security_policies.get("log_all_checks"):
                logger.info(
                    "Permission check",
                    extra={
                        "user_id": user_id,
                        "permission": permission,
                        "command": command,
                        "result": result
                    }
                )
            
            return result
            
        except Exception as e:
            logger.error(
                "Permission check error",
                extra={
                    "user_id": user_id,
                    "permission": permission,
                    "command": command,
                    "error": str(e)
                },
                exc_info=True
            )
            
            # Fail securely - deny on error if default_deny is True
            return not self.default_deny
    
    def _perform_permission_check(
        self,
        user_id: str,
        permission: str,
        command: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Perform the actual permission check logic.
        
        Args:
            user_id: User identifier
            permission: Permission to check
            command: Optional command name
            context: Additional context
            
        Returns:
            bool: True if permission granted
        """
        try:
            # Get user profile
            user = self.user_manager.get_user(user_id)
            
            # Check if user is active (if policy enabled)
            if self.security_policies.get("require_active_user") and not user.is_active:
                return False
            
            # Admin bypass (if policy enabled)
            if self.security_policies.get("admin_bypass_all") and user.is_admin:
                return True
            
            # Check direct permission
            if user.has_permission(permission):
                return True
            
            # Check group permissions
            effective_permissions = self.user_manager.get_user_effective_permissions(user_id)
            if permission in effective_permissions:
                return True
            
            # Check command-specific logic if command provided
            if command:
                cmd_def = self.command_registry.get_command(command)
                
                # Admin-only commands
                if cmd_def.admin_only and not user.is_admin:
                    return False
                
                # Additional command-specific checks could go here
            
            # Default deny
            return False
            
        except Exception as e:
            logger.error(f"Error in permission check: {e}")
            return not self.default_deny
    
    def _check_rate_limit(self, user_id: str) -> bool:
        """
        Check if user has exceeded rate limits.
        
        Args:
            user_id: User identifier
            
        Returns:
            bool: True if within rate limits
        """
        now = datetime.utcnow()
        max_requests = self.security_policies.get("max_requests_per_minute", 60)
        
        # Clean old entries
        cutoff = now - timedelta(minutes=1)
        self._rate_limits[user_id] = [
            timestamp for timestamp in self._rate_limits[user_id]
            if timestamp > cutoff
        ]
        
        # Check current count
        if len(self._rate_limits[user_id]) >= max_requests:
            return False
        
        # Add current request
        self._rate_limits[user_id].append(now)
        return True
    
    def invalidate_user_cache(self, user_id: str):
        """
        Invalidate cached permissions for a user.
        
        This should be called when user permissions change.
        
        Args:
            user_id: User identifier
        """
        if self.cache:
            self.cache.invalidate_user(user_id)
            logger.debug(f"Invalidated cache for user {user_id}")
    
    def clear_cache(self):
        """Clear all cached permissions."""
        if self.cache:
            self.cache.clear()
            logger.info("Permission cache cleared")
    
    def update_security_policy(self, policy: str, value: Any):
        """
        Update a security policy.
        
        Args:
            policy: Policy name
            value: Policy value
        """
        if policy in self.security_policies:
            old_value = self.security_policies[policy]
            self.security_policies[policy] = value
            logger.info(f"Security policy '{policy}' updated: {old_value} -> {value}")
        else:
            logger.warning(f"Unknown security policy: {policy}")
    
    def get_security_policies(self) -> Dict[str, Any]:
        """Get current security policies."""
        return self.security_policies.copy()
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get access control statistics.
        
        Returns:
            Dict[str, Any]: Statistics
        """
        stats = {
            "permission_checks": {
                "total": self._check_count,
                "grants": self._grant_count,
                "denials": self._deny_count,
                "grant_rate": self._grant_count / max(self._check_count, 1)
            },
            "security_policies": self.security_policies,
            "rate_limits": {
                "active_users": len(self._rate_limits),
                "total_requests_last_minute": sum(len(requests) for requests in self._rate_limits.values())
            }
        }
        
        # Add cache stats if caching enabled
        if self.cache:
            stats["cache"] = self.cache.get_stats()
        
        return stats
    
    def audit_user_permissions(self, user_id: str) -> Dict[str, Any]:
        """
        Generate an audit report for a user's permissions.
        
        Args:
            user_id: User identifier
            
        Returns:
            Dict[str, Any]: Audit report
        """
        try:
            user = self.user_manager.get_user(user_id)
            effective_permissions = self.user_manager.get_user_effective_permissions(user_id)
            
            # Get commands user can execute
            allowed_commands = []
            for cmd_def in self.command_registry.get_all_commands():
                if self.check_permission(user_id, cmd_def.permission, cmd_def.name):
                    allowed_commands.append(cmd_def.name)
            
            return {
                "user_id": user_id,
                "username": user.username,
                "is_admin": user.is_admin,
                "is_active": user.is_active,
                "direct_permissions": list(user.permissions),
                "groups": list(user.groups),
                "effective_permissions": list(effective_permissions),
                "allowed_commands": allowed_commands,
                "audit_timestamp": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error generating audit report: {e}")
            return {
                "user_id": user_id,
                "error": str(e),
                "audit_timestamp": datetime.utcnow().isoformat()
            }
