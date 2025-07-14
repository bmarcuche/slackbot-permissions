"""
Command Registry for Slack Permission System.

This module provides a centralized registry for all bot commands, their permissions,
and metadata. It enables declarative command definition and dynamic help generation.
"""

import logging
import re
from typing import Dict, List, Optional, Callable, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict

from ..utils.exceptions import CommandNotFoundError, ValidationError, ConfigurationError

logger = logging.getLogger(__name__)


@dataclass
class CommandDefinition:
    """
    Represents a single command definition with all its metadata.
    
    This class encapsulates all information about a command including
    its permission requirements, validation rules, and help text.
    """
    name: str
    permission: str
    description: str
    handler: Optional[Callable] = None
    category: str = "General"
    examples: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    regex_pattern: Optional[str] = None
    aliases: List[str] = field(default_factory=list)
    hidden: bool = False
    admin_only: bool = False
    rate_limit: Optional[int] = None
    
    def __post_init__(self):
        """Validate command definition after initialization."""
        if not self.name:
            raise ValidationError("Command name cannot be empty")
        if not self.permission:
            raise ValidationError("Command permission cannot be empty")
        if not self.description:
            raise ValidationError("Command description cannot be empty")
        
        # Generate regex pattern if not provided
        if not self.regex_pattern:
            # Convert command name to regex pattern
            # e.g., "delete user" -> r"^delete\s+user\s*(.*)"
            escaped_name = re.escape(self.name)
            pattern = escaped_name.replace(r"\ ", r"\s+")
            self.regex_pattern = f"^{pattern}\\s*(.*)"
    
    def matches(self, text: str) -> bool:
        """Check if the given text matches this command."""
        if not self.regex_pattern:
            return False
        return bool(re.match(self.regex_pattern, text.strip(), re.IGNORECASE))
    
    def extract_parameters(self, text: str) -> Optional[str]:
        """Extract parameters from command text."""
        if not self.regex_pattern:
            return None
        match = re.match(self.regex_pattern, text.strip(), re.IGNORECASE)
        return match.group(1).strip() if match and match.group(1) else None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert command definition to dictionary."""
        return {
            "name": self.name,
            "permission": self.permission,
            "description": self.description,
            "category": self.category,
            "examples": self.examples,
            "parameters": self.parameters,
            "regex_pattern": self.regex_pattern,
            "aliases": self.aliases,
            "hidden": self.hidden,
            "admin_only": self.admin_only,
            "rate_limit": self.rate_limit
        }


class CommandRegistry:
    """
    Central registry for all bot commands and their metadata.
    
    This class manages command registration, lookup, and validation.
    It provides the foundation for permission checking and help generation.
    """
    
    def __init__(self):
        self._commands: Dict[str, CommandDefinition] = {}
        self._categories: Dict[str, List[str]] = defaultdict(list)
        self._permissions: Dict[str, List[str]] = defaultdict(list)
        self._aliases: Dict[str, str] = {}
        self._regex_cache: Dict[str, CommandDefinition] = {}
        
        logger.info("CommandRegistry initialized")
    
    def register_command(
        self,
        name: str,
        permission: str,
        description: str,
        handler: Optional[Callable] = None,
        category: str = "General",
        examples: Optional[List[str]] = None,
        parameters: Optional[List[str]] = None,
        regex_pattern: Optional[str] = None,
        aliases: Optional[List[str]] = None,
        hidden: bool = False,
        admin_only: bool = False,
        rate_limit: Optional[int] = None
    ) -> CommandDefinition:
        """
        Register a new command in the system.
        
        Args:
            name: Command name (e.g., "delete user")
            permission: Required permission string
            description: Human-readable description
            handler: Optional command handler function
            category: Command category for help organization
            examples: List of usage examples
            parameters: List of parameter descriptions
            regex_pattern: Custom regex pattern for matching
            aliases: Alternative command names
            hidden: Whether to hide from help
            admin_only: Whether command requires admin privileges
            rate_limit: Rate limit in requests per minute
            
        Returns:
            CommandDefinition: The registered command definition
            
        Raises:
            ValidationError: If command definition is invalid
            ConfigurationError: If command already exists
        """
        if name in self._commands:
            raise ConfigurationError(
                f"Command '{name}' is already registered",
                config_key="command_name",
                config_value=name
            )
        
        # Create command definition
        cmd_def = CommandDefinition(
            name=name,
            permission=permission,
            description=description,
            handler=handler,
            category=category,
            examples=examples or [],
            parameters=parameters or [],
            regex_pattern=regex_pattern,
            aliases=aliases or [],
            hidden=hidden,
            admin_only=admin_only,
            rate_limit=rate_limit
        )
        
        # Register command
        self._commands[name] = cmd_def
        self._categories[category].append(name)
        self._permissions[permission].append(name)
        
        # Register aliases
        for alias in cmd_def.aliases:
            if alias in self._aliases:
                raise ConfigurationError(
                    f"Alias '{alias}' is already registered for command '{self._aliases[alias]}'",
                    config_key="command_alias",
                    config_value=alias
                )
            self._aliases[alias] = name
        
        logger.info(
            "Command registered",
            extra={
                "command": name,
                "permission": permission,
                "category": category,
                "aliases": cmd_def.aliases
            }
        )
        
        return cmd_def
    
    def get_command(self, name: str) -> CommandDefinition:
        """
        Get command definition by name or alias.
        
        Args:
            name: Command name or alias
            
        Returns:
            CommandDefinition: The command definition
            
        Raises:
            CommandNotFoundError: If command doesn't exist
        """
        # Check direct name match
        if name in self._commands:
            return self._commands[name]
        
        # Check alias match
        if name in self._aliases:
            return self._commands[self._aliases[name]]
        
        raise CommandNotFoundError(
            f"Command '{name}' not found",
            command=name
        )
    
    def find_command_by_text(self, text: str) -> Optional[CommandDefinition]:
        """
        Find command that matches the given text.
        
        Args:
            text: Input text to match against commands
            
        Returns:
            CommandDefinition or None: Matching command if found
        """
        text = text.strip()
        
        # Check cache first
        if text in self._regex_cache:
            return self._regex_cache[text]
        
        # Try to match against all commands
        for cmd_def in self._commands.values():
            if cmd_def.matches(text):
                self._regex_cache[text] = cmd_def
                return cmd_def
        
        return None
    
    def get_commands_by_permission(self, permission: str) -> List[CommandDefinition]:
        """
        Get all commands that require a specific permission.
        
        Args:
            permission: Permission string
            
        Returns:
            List[CommandDefinition]: Commands requiring the permission
        """
        return [self._commands[name] for name in self._permissions.get(permission, [])]
    
    def get_commands_by_category(self, category: str) -> List[CommandDefinition]:
        """
        Get all commands in a specific category.
        
        Args:
            category: Category name
            
        Returns:
            List[CommandDefinition]: Commands in the category
        """
        return [self._commands[name] for name in self._categories.get(category, [])]
    
    def get_all_commands(self, include_hidden: bool = False) -> List[CommandDefinition]:
        """
        Get all registered commands.
        
        Args:
            include_hidden: Whether to include hidden commands
            
        Returns:
            List[CommandDefinition]: All commands
        """
        commands = list(self._commands.values())
        if not include_hidden:
            commands = [cmd for cmd in commands if not cmd.hidden]
        return commands
    
    def get_all_permissions(self) -> Set[str]:
        """
        Get all unique permissions used by commands.
        
        Returns:
            Set[str]: All permission strings
        """
        return set(self._permissions.keys())
    
    def get_all_categories(self) -> Set[str]:
        """
        Get all command categories.
        
        Returns:
            Set[str]: All category names
        """
        return set(self._categories.keys())
    
    def validate_command_text(self, text: str) -> bool:
        """
        Validate if text matches any registered command.
        
        Args:
            text: Text to validate
            
        Returns:
            bool: True if text matches a command
        """
        return self.find_command_by_text(text) is not None
    
    def get_command_stats(self) -> Dict[str, Any]:
        """
        Get registry statistics for monitoring.
        
        Returns:
            Dict[str, Any]: Registry statistics
        """
        return {
            "total_commands": len(self._commands),
            "total_categories": len(self._categories),
            "total_permissions": len(self._permissions),
            "total_aliases": len(self._aliases),
            "hidden_commands": len([cmd for cmd in self._commands.values() if cmd.hidden]),
            "admin_commands": len([cmd for cmd in self._commands.values() if cmd.admin_only]),
        }
    
    def clear(self):
        """Clear all registered commands (useful for testing)."""
        self._commands.clear()
        self._categories.clear()
        self._permissions.clear()
        self._aliases.clear()
        self._regex_cache.clear()
        logger.info("CommandRegistry cleared")


# Global registry instance
_global_registry = CommandRegistry()


def get_global_registry() -> CommandRegistry:
    """Get the global command registry instance."""
    return _global_registry
