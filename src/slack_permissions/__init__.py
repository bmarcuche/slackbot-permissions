"""
Slack Permission System

A production-ready, declarative permission management system for Slack bots.
"""

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
__author__ = "Bruno Marcuche"
__email__ = "bruno.marcuche@gmail.com"

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
__title__ = "slack-permission-system"
__description__ = "Production-ready permission management system for Slack bots"
__url__ = "https://github.com/bmarcuche/slack-permission-system"
__license__ = "MIT"
