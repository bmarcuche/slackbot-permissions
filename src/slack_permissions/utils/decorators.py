"""
Decorators for Slack Permission System.

This module provides convenient decorators for integrating permission
checking into Slack bot handlers and other functions.
"""

import functools
import logging
from typing import Callable, Any, Optional, Dict

from ..core.permission_manager import PermissionManager
from .exceptions import PermissionError, ValidationError

logger = logging.getLogger(__name__)

# Global permission manager instance
_global_permission_manager: Optional[PermissionManager] = None


def set_global_permission_manager(manager: PermissionManager):
    """Set the global permission manager instance."""
    global _global_permission_manager
    _global_permission_manager = manager


def get_global_permission_manager() -> PermissionManager:
    """Get the global permission manager instance."""
    if _global_permission_manager is None:
        # Create default instance if none set
        return PermissionManager()
    return _global_permission_manager


def require_permission(
    permission: str,
    command: Optional[str] = None,
    manager: Optional[PermissionManager] = None,
    send_error_message: bool = True
):
    """
    Decorator to require a specific permission for a function.
    
    This decorator is designed to work with Slack Bolt handlers but can
    be used with any function that receives message context.
    
    Args:
        permission: Required permission string
        command: Optional command name for context
        manager: Optional permission manager instance
        send_error_message: Whether to send error messages to user
        
    Example:
        @app.message("deploy")
        @require_permission("deployment")
        def handle_deploy(message, say):
            say("Deploying...")
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get permission manager
            perm_manager = manager or get_global_permission_manager()
            
            # Extract message context from arguments
            message_context = _extract_message_context(args, kwargs)
            if not message_context:
                logger.error("Could not extract message context for permission check")
                return
            
            user_id = message_context.get("user_id")
            if not user_id:
                logger.error("No user_id found in message context")
                return
            
            # Validate permission
            result = perm_manager.validate_request(
                user_id=user_id,
                command=command or permission,  # Use permission as command if not specified
                client=message_context.get("client"),
                channel_id=message_context.get("channel_id"),
                message_text=message_context.get("text")
            )
            
            if not result.success:
                logger.warning(
                    f"Permission denied for user {user_id}: {result.error_message}"
                )
                
                # Send error message if enabled and client available
                if send_error_message and message_context.get("client"):
                    _send_permission_error(message_context, result)
                
                return  # Don't execute the wrapped function
            
            # Permission granted - execute the function
            logger.info(f"Permission granted for user {user_id} to execute {permission}")
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def command(
    name: str,
    permission: str,
    description: str,
    category: str = "General",
    examples: Optional[list] = None,
    admin_only: bool = False,
    manager: Optional[PermissionManager] = None
):
    """
    Decorator to register a command and require permission.
    
    This decorator combines command registration with permission checking.
    
    Args:
        name: Command name
        permission: Required permission
        description: Command description
        category: Command category
        examples: Usage examples
        admin_only: Whether command is admin-only
        manager: Optional permission manager instance
        
    Example:
        @app.message("deploy")
        @command(
            name="deploy",
            permission="deployment",
            description="Deploy application"
        )
        def handle_deploy(message, say):
            say("Deploying...")
    """
    def decorator(func: Callable) -> Callable:
        # Get permission manager
        perm_manager = manager or get_global_permission_manager()
        
        # Register the command
        perm_manager.register_command(
            name=name,
            permission=permission,
            description=description,
            category=category,
            examples=examples or [],
            admin_only=admin_only,
            handler=func
        )
        
        # Apply permission requirement
        return require_permission(
            permission=permission,
            command=name,
            manager=perm_manager
        )(func)
    
    return decorator


def admin_only(
    manager: Optional[PermissionManager] = None,
    send_error_message: bool = True
):
    """
    Decorator to require admin privileges.
    
    Args:
        manager: Optional permission manager instance
        send_error_message: Whether to send error messages
        
    Example:
        @app.message("shutdown")
        @admin_only()
        def handle_shutdown(message, say):
            say("Shutting down...")
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Get permission manager
            perm_manager = manager or get_global_permission_manager()
            
            # Extract message context
            message_context = _extract_message_context(args, kwargs)
            if not message_context:
                logger.error("Could not extract message context for admin check")
                return
            
            user_id = message_context.get("user_id")
            if not user_id:
                logger.error("No user_id found in message context")
                return
            
            # Check if user is admin
            try:
                user = perm_manager.user_manager.get_user(user_id)
                if not user.is_admin:
                    logger.warning(f"Admin access denied for user {user_id}")
                    
                    if send_error_message and message_context.get("client"):
                        _send_admin_error(message_context)
                    
                    return
                
                # Admin access granted
                logger.info(f"Admin access granted for user {user_id}")
                return func(*args, **kwargs)
                
            except Exception as e:
                logger.error(f"Error checking admin status for user {user_id}: {e}")
                return
        
        return wrapper
    return decorator


def rate_limit(
    max_requests: int = 10,
    window_minutes: int = 1,
    manager: Optional[PermissionManager] = None
):
    """
    Decorator to apply rate limiting to functions.
    
    Args:
        max_requests: Maximum requests allowed
        window_minutes: Time window in minutes
        manager: Optional permission manager instance
        
    Example:
        @app.message("status")
        @rate_limit(max_requests=5, window_minutes=1)
        def handle_status(message, say):
            say("System status: OK")
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # This is a simplified rate limiting implementation
            # In practice, you'd want more sophisticated rate limiting
            
            message_context = _extract_message_context(args, kwargs)
            user_id = message_context.get("user_id") if message_context else None
            
            if user_id:
                # Check rate limit (simplified - would need proper implementation)
                logger.debug(f"Rate limit check for user {user_id}")
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def log_command_usage(
    manager: Optional[PermissionManager] = None,
    include_args: bool = False
):
    """
    Decorator to log command usage.
    
    Args:
        manager: Optional permission manager instance
        include_args: Whether to include function arguments in logs
        
    Example:
        @app.message("backup")
        @log_command_usage(include_args=True)
        def handle_backup(message, say):
            say("Starting backup...")
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            message_context = _extract_message_context(args, kwargs)
            user_id = message_context.get("user_id") if message_context else "unknown"
            
            log_data = {
                "function": func.__name__,
                "user_id": user_id,
                "command": message_context.get("text") if message_context else None
            }
            
            if include_args:
                log_data["args"] = str(args)
                log_data["kwargs"] = str(kwargs)
            
            logger.info("Command executed", extra=log_data)
            
            try:
                result = func(*args, **kwargs)
                logger.info("Command completed successfully", extra={"function": func.__name__, "user_id": user_id})
                return result
            except Exception as e:
                logger.error("Command failed", extra={"function": func.__name__, "user_id": user_id, "error": str(e)})
                raise
        
        return wrapper
    return decorator


def _extract_message_context(args: tuple, kwargs: dict) -> Optional[Dict[str, Any]]:
    """
    Extract message context from function arguments.
    
    This function attempts to extract Slack message context from various
    argument patterns used by Slack Bolt handlers.
    """
    context = {}
    
    # Look for message in args (common pattern: message, say, client)
    for arg in args:
        if isinstance(arg, dict):
            if "user" in arg and "channel" in arg:
                # This looks like a Slack message
                context.update({
                    "user_id": arg.get("user"),
                    "channel_id": arg.get("channel"),
                    "text": arg.get("text"),
                    "ts": arg.get("ts")
                })
                break
    
    # Look for client in args or kwargs
    for arg in args:
        if hasattr(arg, "chat_postEphemeral"):
            # This looks like a Slack client
            context["client"] = arg
            break
    
    if "client" in kwargs:
        context["client"] = kwargs["client"]
    
    # Look for other context in kwargs
    if "message" in kwargs:
        msg = kwargs["message"]
        if isinstance(msg, dict):
            context.update({
                "user_id": msg.get("user"),
                "channel_id": msg.get("channel"),
                "text": msg.get("text")
            })
    
    return context if context else None


def _send_permission_error(message_context: Dict[str, Any], result):
    """Send permission error message to user."""
    client = message_context.get("client")
    user_id = message_context.get("user_id")
    channel_id = message_context.get("channel_id")
    
    if client and user_id and channel_id:
        try:
            client.chat_postEphemeral(
                user=user_id,
                channel=channel_id,
                text=f"❌ {result.error_message}"
            )
        except Exception as e:
            logger.error(f"Failed to send permission error message: {e}")


def _send_admin_error(message_context: Dict[str, Any]):
    """Send admin-only error message to user."""
    client = message_context.get("client")
    user_id = message_context.get("user_id")
    channel_id = message_context.get("channel_id")
    
    if client and user_id and channel_id:
        try:
            client.chat_postEphemeral(
                user=user_id,
                channel=channel_id,
                text="❌ This command requires administrator privileges."
            )
        except Exception as e:
            logger.error(f"Failed to send admin error message: {e}")
