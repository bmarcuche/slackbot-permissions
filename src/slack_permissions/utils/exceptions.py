"""
Custom exceptions for the Slack Permission System.

This module defines all custom exceptions used throughout the permission system,
providing clear error hierarchies and detailed error information for debugging
and monitoring.
"""

from typing import Optional, Dict, Any


class SlackPermissionSystemError(Exception):
    """
    Base exception for all Slack Permission System errors.
    
    All custom exceptions in this system inherit from this base class,
    allowing for easy catching of all system-related errors.
    """
    
    def __init__(
        self, 
        message: str, 
        error_code: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None
    ):
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.context = context or {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for logging/monitoring."""
        return {
            "error_type": self.__class__.__name__,
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context
        }


class PermissionError(SlackPermissionSystemError):
    """
    Raised when a user lacks required permissions for an action.
    
    This is the most common exception, raised when permission validation fails.
    """
    
    def __init__(
        self,
        message: str,
        user_id: Optional[str] = None,
        required_permission: Optional[str] = None,
        command: Optional[str] = None,
        **kwargs
    ):
        context = {
            "user_id": user_id,
            "required_permission": required_permission,
            "command": command,
            **kwargs
        }
        super().__init__(message, "PERMISSION_DENIED", context)
        self.user_id = user_id
        self.required_permission = required_permission
        self.command = command


class ValidationError(SlackPermissionSystemError):
    """
    Raised when input validation fails.
    
    Used for invalid user inputs, malformed commands, or data validation failures.
    """
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        validation_rule: Optional[str] = None,
        **kwargs
    ):
        context = {
            "field": field,
            "value": str(value) if value is not None else None,
            "validation_rule": validation_rule,
            **kwargs
        }
        super().__init__(message, "VALIDATION_FAILED", context)
        self.field = field
        self.value = value
        self.validation_rule = validation_rule


class ConfigurationError(SlackPermissionSystemError):
    """
    Raised when system configuration is invalid or missing.
    
    Used for missing environment variables, invalid configuration files,
    or misconfigured system components.
    """
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        config_value: Optional[Any] = None,
        **kwargs
    ):
        context = {
            "config_key": config_key,
            "config_value": str(config_value) if config_value is not None else None,
            **kwargs
        }
        super().__init__(message, "CONFIGURATION_ERROR", context)
        self.config_key = config_key
        self.config_value = config_value


class SlackIntegrationError(SlackPermissionSystemError):
    """
    Raised when Slack API integration fails.
    
    Used for Slack API errors, authentication failures, or communication issues.
    """
    
    def __init__(
        self,
        message: str,
        slack_error: Optional[str] = None,
        api_method: Optional[str] = None,
        **kwargs
    ):
        context = {
            "slack_error": slack_error,
            "api_method": api_method,
            **kwargs
        }
        super().__init__(message, "SLACK_INTEGRATION_ERROR", context)
        self.slack_error = slack_error
        self.api_method = api_method


class UserNotFoundError(SlackPermissionSystemError):
    """
    Raised when a user cannot be found in the system.
    
    Used when user lookup fails or user doesn't exist in permission system.
    """
    
    def __init__(
        self,
        message: str,
        user_id: Optional[str] = None,
        **kwargs
    ):
        context = {
            "user_id": user_id,
            **kwargs
        }
        super().__init__(message, "USER_NOT_FOUND", context)
        self.user_id = user_id


class CommandNotFoundError(SlackPermissionSystemError):
    """
    Raised when a command is not registered in the system.
    
    Used when attempting to validate permissions for unknown commands.
    """
    
    def __init__(
        self,
        message: str,
        command: Optional[str] = None,
        **kwargs
    ):
        context = {
            "command": command,
            **kwargs
        }
        super().__init__(message, "COMMAND_NOT_FOUND", context)
        self.command = command


class RateLimitError(SlackPermissionSystemError):
    """
    Raised when rate limits are exceeded.
    
    Used for API rate limiting or user action throttling.
    """
    
    def __init__(
        self,
        message: str,
        retry_after: Optional[int] = None,
        limit_type: Optional[str] = None,
        **kwargs
    ):
        context = {
            "retry_after": retry_after,
            "limit_type": limit_type,
            **kwargs
        }
        super().__init__(message, "RATE_LIMIT_EXCEEDED", context)
        self.retry_after = retry_after
        self.limit_type = limit_type
