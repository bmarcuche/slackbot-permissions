"""
Permission Manager for Slack Permission System.

This is the main orchestrator that coordinates all permission-related operations.
It provides the primary API for validating permissions and managing access control.
"""

import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

from .command_registry import CommandRegistry, CommandDefinition
from .user_manager import UserManager, UserProfile
from .access_control import AccessControlEngine
from ..integrations.slack_groups import SlackGroupsIntegration
from ..utils.exceptions import (
    PermissionError,
    ValidationError,
    CommandNotFoundError,
    UserNotFoundError,
    SlackIntegrationError
)

logger = logging.getLogger(__name__)


class ValidationResult:
    """
    Represents the result of a permission validation operation.
    
    This class encapsulates all information about a validation attempt
    including success/failure status, error details, and context.
    """
    
    def __init__(
        self,
        success: bool,
        user_id: str,
        command: Optional[str] = None,
        permission: Optional[str] = None,
        error_message: Optional[str] = None,
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        self.success = success
        self.user_id = user_id
        self.command = command
        self.permission = permission
        self.error_message = error_message
        self.error_code = error_code
        self.context = context or {}
        self.timestamp = datetime.utcnow()
    
    @property
    def access_granted(self) -> bool:
        """Alias for success for backward compatibility."""
        return self.success
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for logging/monitoring."""
        return {
            "success": self.success,
            "user_id": self.user_id,
            "command": self.command,
            "permission": self.permission,
            "error_message": self.error_message,
            "error_code": self.error_code,
            "context": self.context,
            "timestamp": self.timestamp.isoformat()
        }


class PermissionManager:
    """
    Main orchestrator for the Slack Permission System.
    
    This class coordinates all permission-related operations including
    validation, user management, command registration, and Slack integration.
    """
    
    def __init__(
        self,
        command_registry: Optional[CommandRegistry] = None,
        user_manager: Optional[UserManager] = None,
        slack_integration: Optional[SlackGroupsIntegration] = None,
        enable_caching: bool = True,
        default_deny: bool = True
    ):
        """
        Initialize the Permission Manager.
        
        Args:
            command_registry: Command registry instance
            user_manager: User manager instance
            slack_integration: Slack groups integration
            enable_caching: Whether to enable permission caching
            default_deny: Whether to deny by default (fail-safe)
        """
        self.command_registry = command_registry or CommandRegistry()
        self.user_manager = user_manager or UserManager()
        self.access_control = AccessControlEngine(
            command_registry=self.command_registry,
            user_manager=self.user_manager,
            enable_caching=enable_caching,
            default_deny=default_deny
        )
        self.slack_integration = slack_integration
        self.default_deny = default_deny
        
        # Statistics tracking
        self._validation_count = 0
        self._permission_grants = 0
        self._permission_denials = 0
        
        logger.info(
            "PermissionManager initialized",
            extra={
                "enable_caching": enable_caching,
                "default_deny": default_deny,
                "has_slack_integration": slack_integration is not None
            }
        )
    
    def validate_request(
        self,
        user_id: str,
        command: str,
        client: Optional[Any] = None,
        channel_id: Optional[str] = None,
        message_text: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """
        Validate a user's permission to execute a command.
        
        This is the main entry point for permission validation.
        
        Args:
            user_id: Slack user ID
            command: Command name or text
            client: Slack client for sending error messages
            channel_id: Channel ID for context
            message_text: Full message text
            context: Additional context
            
        Returns:
            ValidationResult: Validation result with success/failure info
        """
        self._validation_count += 1
        
        try:
            # Find command definition
            cmd_def = self._resolve_command(command, message_text)
            if not cmd_def:
                return self._create_failure_result(
                    user_id=user_id,
                    command=command,
                    error_message=f"Command '{command}' not found",
                    error_code="COMMAND_NOT_FOUND"
                )
            
            # Get or create user
            user = self._get_or_sync_user(user_id)
            if not user:
                return self._create_failure_result(
                    user_id=user_id,
                    command=cmd_def.name,
                    permission=cmd_def.permission,
                    error_message="User not found and could not be created",
                    error_code="USER_NOT_FOUND"
                )
            
            # Check if user is active
            if not user.is_active:
                return self._create_failure_result(
                    user_id=user_id,
                    command=cmd_def.name,
                    permission=cmd_def.permission,
                    error_message="User account is inactive",
                    error_code="USER_INACTIVE"
                )
            
            # Validate permission
            has_permission = self.access_control.check_permission(
                user_id=user_id,
                permission=cmd_def.permission,
                command=cmd_def.name,
                context=context
            )
            
            if has_permission:
                self._permission_grants += 1
                logger.info(
                    "Permission granted",
                    extra={
                        "user_id": user_id,
                        "command": cmd_def.name,
                        "permission": cmd_def.permission
                    }
                )
                
                return ValidationResult(
                    success=True,
                    user_id=user_id,
                    command=cmd_def.name,
                    permission=cmd_def.permission,
                    context={"command_definition": cmd_def.to_dict() if hasattr(cmd_def, 'to_dict') else None}
                )
            else:
                self._permission_denials += 1
                
                # Send user-friendly error message if client provided
                if client and channel_id:
                    self._send_permission_denied_message(
                        client=client,
                        user_id=user_id,
                        channel_id=channel_id,
                        command=cmd_def.name,
                        permission=cmd_def.permission
                    )
                
                logger.warning(
                    "Permission denied",
                    extra={
                        "user_id": user_id,
                        "command": cmd_def.name,
                        "permission": cmd_def.permission
                    }
                )
                
                return self._create_failure_result(
                    user_id=user_id,
                    command=cmd_def.name,
                    permission=cmd_def.permission,
                    error_message=f"Permission '{cmd_def.permission}' required",
                    error_code="PERMISSION_DENIED"
                )
                
        except Exception as e:
            logger.error(
                "Permission validation error",
                extra={
                    "user_id": user_id,
                    "command": command,
                    "error": str(e)
                },
                exc_info=True
            )
            
            return self._create_failure_result(
                user_id=user_id,
                command=command,
                error_message="Internal validation error",
                error_code="VALIDATION_ERROR"
            )
    
    def get_user_commands(
        self,
        user_id: str,
        category: Optional[str] = None,
        include_hidden: bool = False
    ) -> List[CommandDefinition]:
        """
        Get all commands a user has permission to execute.
        
        Args:
            user_id: User identifier
            category: Optional category filter
            include_hidden: Whether to include hidden commands
            
        Returns:
            List[CommandDefinition]: Commands user can execute
        """
        try:
            user = self._get_or_sync_user(user_id)
            if not user or not user.is_active:
                return []
            
            # Get all commands
            all_commands = self.command_registry.get_all_commands(include_hidden=include_hidden)
            
            # Filter by category if specified
            if category:
                all_commands = [cmd for cmd in all_commands if cmd.category == category]
            
            # Filter by permissions
            allowed_commands = []
            for cmd in all_commands:
                if self.access_control.check_permission(user_id, cmd.permission, cmd.name):
                    allowed_commands.append(cmd)
            
            return allowed_commands
            
        except Exception as e:
            logger.error(f"Error getting user commands: {e}", exc_info=True)
            return []
    
    def sync_user_from_slack(self, user_id: str) -> Optional[UserProfile]:
        """
        Sync user information from Slack.
        
        Args:
            user_id: Slack user ID
            
        Returns:
            UserProfile or None: Synced user profile
        """
        if not self.slack_integration:
            return None
        
        try:
            return self.slack_integration.sync_user(user_id)
        except Exception as e:
            logger.error(f"Error syncing user from Slack: {e}", exc_info=True)
            return None
    
    def register_command(self, **kwargs) -> CommandDefinition:
        """Register a new command. Delegates to command registry."""
        return self.command_registry.register_command(**kwargs)
    
    def create_user(self, **kwargs) -> UserProfile:
        """Create a new user. Delegates to user manager."""
        return self.user_manager.create_user(**kwargs)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive system statistics.
        
        Returns:
            Dict[str, Any]: System statistics
        """
        return {
            "validation_stats": {
                "total_validations": self._validation_count,
                "permission_grants": self._permission_grants,
                "permission_denials": self._permission_denials,
                "grant_rate": self._permission_grants / max(self._validation_count, 1)
            },
            "command_stats": self.command_registry.get_command_stats(),
            "user_stats": self.user_manager.get_stats(),
            "access_control_stats": self.access_control.get_stats()
        }
    
    def _resolve_command(
        self,
        command: str,
        message_text: Optional[str] = None
    ) -> Optional[CommandDefinition]:
        """
        Resolve command name to command definition.
        
        Args:
            command: Command name or identifier
            message_text: Full message text for pattern matching
            
        Returns:
            CommandDefinition or None: Resolved command
        """
        try:
            # Try direct lookup first
            return self.command_registry.get_command(command)
        except CommandNotFoundError:
            pass
        
        # Try pattern matching if message text provided
        if message_text:
            return self.command_registry.find_command_by_text(message_text)
        
        # Try pattern matching with command as text
        return self.command_registry.find_command_by_text(command)
    
    def _get_or_sync_user(self, user_id: str) -> Optional[UserProfile]:
        """
        Get user from local store or sync from Slack.
        
        Args:
            user_id: User identifier
            
        Returns:
            UserProfile or None: User profile
        """
        # Try local lookup first
        user = self.user_manager.get_user_safe(user_id)
        if user:
            return user
        
        # Try syncing from Slack
        if self.slack_integration:
            user = self.sync_user_from_slack(user_id)
            if user:
                return user
        
        # Create minimal user if default deny is disabled
        if not self.default_deny:
            try:
                return self.user_manager.create_user(user_id=user_id)
            except Exception as e:
                logger.error(f"Error creating user: {e}")
        
        return None
    
    def _create_failure_result(
        self,
        user_id: str,
        command: Optional[str] = None,
        permission: Optional[str] = None,
        error_message: str = "Access denied",
        error_code: str = "ACCESS_DENIED"
    ) -> ValidationResult:
        """Create a failure validation result."""
        return ValidationResult(
            success=False,
            user_id=user_id,
            command=command,
            permission=permission,
            error_message=error_message,
            error_code=error_code
        )
    
    def _send_permission_denied_message(
        self,
        client: Any,
        user_id: str,
        channel_id: str,
        command: str,
        permission: str
    ):
        """
        Send a user-friendly permission denied message.
        
        Args:
            client: Slack client
            user_id: User ID
            channel_id: Channel ID
            command: Command name
            permission: Required permission
        """
        try:
            message = (
                f"Sorry, you don't have permission to run the '{command}' command. "
                f"This command requires the '{permission}' permission. "
                "Please contact your administrator if you believe this is an error."
            )
            
            # Send ephemeral message (only visible to user)
            client.chat_postEphemeral(
                user=user_id,
                channel=channel_id,
                text=message
            )
            
        except Exception as e:
            logger.error(f"Error sending permission denied message: {e}")
    
    def clear_all(self):
        """Clear all data (useful for testing)."""
        self.command_registry.clear()
        self.user_manager.clear()
        self.access_control.clear_cache()
        self._validation_count = 0
        self._permission_grants = 0
        self._permission_denials = 0
        logger.info("PermissionManager cleared")
