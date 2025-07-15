"""
Slack Permission System

A production-ready, declarative permission management system for Slack bots.
"""

import os
from .core.permission_manager import PermissionManager
from .core.command_registry import CommandRegistry
from .core.user_manager import UserManager
from .core.access_control import AccessControlEngine
from .integrations.slack_groups import SlackGroupsIntegration
from .utils.exceptions import (
    PermissionError,
    ValidationError,
    ConfigurationError,
    SlackPermissionSystemError
)
from .utils.decorators import require_permission, command, admin_only, set_global_permission_manager
from .utils.validators import validate_user_input, validate_command_input

__version__ = "1.0.0"
__author__ = os.getenv("PACKAGE_AUTHOR", "Slackbot Permissions Contributors")
__email__ = os.getenv("PACKAGE_AUTHOR_EMAIL", "contributors@example.com")

__all__ = [
    # Core components
    "PermissionManager",
    "CommandRegistry", 
    "UserManager",
    "AccessControlEngine",
    
    # Integrations
    "SlackGroupsIntegration",
    
    # Exceptions
    "PermissionError",
    "ValidationError", 
    "ConfigurationError",
    "SlackPermissionSystemError",
    
    # Decorators
    "require_permission",
    "command",
    "admin_only",
    "set_global_permission_manager",
    
    # Validators
    "validate_user_input",
    "validate_command_input",
]

# Package metadata
__title__ = "slackbot-permissions"
__description__ = "Production-ready permission management system for Slack bots"
__url__ = os.getenv("PACKAGE_URL", "https://github.com/your-org/slackbot-permissions")
__license__ = "MIT"
