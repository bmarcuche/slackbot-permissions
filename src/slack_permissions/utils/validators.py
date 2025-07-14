"""
Validation utilities for Slack Permission System.

This module provides input validation functions to ensure data integrity
and security throughout the permission system.
"""

import re
import logging
from typing import Any, Dict, List, Optional, Union, Tuple
from datetime import datetime

from .exceptions import ValidationError

logger = logging.getLogger(__name__)

# Validation patterns
USER_ID_PATTERN = re.compile(r'^U[A-Z0-9]{8,}$')
CHANNEL_ID_PATTERN = re.compile(r'^[CDG][A-Z0-9]{8,}$')
EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]{1,50}$')
PERMISSION_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]{1,100}$')
COMMAND_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9\s._-]{1,100}$')


def validate_user_id(user_id: str) -> str:
    """
    Validate Slack user ID format.
    
    Args:
        user_id: User ID to validate
        
    Returns:
        str: Validated user ID
        
    Raises:
        ValidationError: If user ID is invalid
    """
    if not isinstance(user_id, str):
        raise ValidationError(
            "User ID must be a string",
            field="user_id",
            value=user_id,
            validation_rule="type_check"
        )
    
    if not user_id:
        raise ValidationError(
            "User ID cannot be empty",
            field="user_id",
            value=user_id,
            validation_rule="not_empty"
        )
    
    if not USER_ID_PATTERN.match(user_id):
        raise ValidationError(
            "Invalid Slack user ID format",
            field="user_id",
            value=user_id,
            validation_rule="format_check"
        )
    
    return user_id


def validate_channel_id(channel_id: str) -> str:
    """
    Validate Slack channel ID format.
    
    Args:
        channel_id: Channel ID to validate
        
    Returns:
        str: Validated channel ID
        
    Raises:
        ValidationError: If channel ID is invalid
    """
    if not isinstance(channel_id, str):
        raise ValidationError(
            "Channel ID must be a string",
            field="channel_id",
            value=channel_id,
            validation_rule="type_check"
        )
    
    if not channel_id:
        raise ValidationError(
            "Channel ID cannot be empty",
            field="channel_id",
            value=channel_id,
            validation_rule="not_empty"
        )
    
    if not CHANNEL_ID_PATTERN.match(channel_id):
        raise ValidationError(
            "Invalid Slack channel ID format",
            field="channel_id",
            value=channel_id,
            validation_rule="format_check"
        )
    
    return channel_id


def validate_email(email: str) -> str:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        str: Validated email address
        
    Raises:
        ValidationError: If email is invalid
    """
    if not isinstance(email, str):
        raise ValidationError(
            "Email must be a string",
            field="email",
            value=email,
            validation_rule="type_check"
        )
    
    if not email:
        raise ValidationError(
            "Email cannot be empty",
            field="email",
            value=email,
            validation_rule="not_empty"
        )
    
    if not EMAIL_PATTERN.match(email):
        raise ValidationError(
            "Invalid email format",
            field="email",
            value=email,
            validation_rule="format_check"
        )
    
    return email.lower()


def validate_username(username: str) -> str:
    """
    Validate username format.
    
    Args:
        username: Username to validate
        
    Returns:
        str: Validated username
        
    Raises:
        ValidationError: If username is invalid
    """
    if not isinstance(username, str):
        raise ValidationError(
            "Username must be a string",
            field="username",
            value=username,
            validation_rule="type_check"
        )
    
    if not username:
        raise ValidationError(
            "Username cannot be empty",
            field="username",
            value=username,
            validation_rule="not_empty"
        )
    
    if not USERNAME_PATTERN.match(username):
        raise ValidationError(
            "Invalid username format. Use only letters, numbers, dots, underscores, and hyphens",
            field="username",
            value=username,
            validation_rule="format_check"
        )
    
    return username.lower()


def validate_permission(permission: str) -> str:
    """
    Validate permission string format.
    
    Args:
        permission: Permission string to validate
        
    Returns:
        str: Validated permission string
        
    Raises:
        ValidationError: If permission is invalid
    """
    if not isinstance(permission, str):
        raise ValidationError(
            "Permission must be a string",
            field="permission",
            value=permission,
            validation_rule="type_check"
        )
    
    if not permission:
        raise ValidationError(
            "Permission cannot be empty",
            field="permission",
            value=permission,
            validation_rule="not_empty"
        )
    
    if not PERMISSION_PATTERN.match(permission):
        raise ValidationError(
            "Invalid permission format. Use only letters, numbers, dots, underscores, and hyphens",
            field="permission",
            value=permission,
            validation_rule="format_check"
        )
    
    return permission.lower()


def validate_command_name(command_name: str) -> str:
    """
    Validate command name format.
    
    Args:
        command_name: Command name to validate
        
    Returns:
        str: Validated command name
        
    Raises:
        ValidationError: If command name is invalid
    """
    if not isinstance(command_name, str):
        raise ValidationError(
            "Command name must be a string",
            field="command_name",
            value=command_name,
            validation_rule="type_check"
        )
    
    if not command_name:
        raise ValidationError(
            "Command name cannot be empty",
            field="command_name",
            value=command_name,
            validation_rule="not_empty"
        )
    
    if not COMMAND_NAME_PATTERN.match(command_name):
        raise ValidationError(
            "Invalid command name format",
            field="command_name",
            value=command_name,
            validation_rule="format_check"
        )
    
    return command_name.strip().lower()


def validate_permissions_list(permissions: List[str]) -> List[str]:
    """
    Validate a list of permissions.
    
    Args:
        permissions: List of permission strings
        
    Returns:
        List[str]: Validated permissions list
        
    Raises:
        ValidationError: If any permission is invalid
    """
    if not isinstance(permissions, list):
        raise ValidationError(
            "Permissions must be a list",
            field="permissions",
            value=permissions,
            validation_rule="type_check"
        )
    
    validated_permissions = []
    for i, permission in enumerate(permissions):
        try:
            validated_permission = validate_permission(permission)
            validated_permissions.append(validated_permission)
        except ValidationError as e:
            raise ValidationError(
                f"Invalid permission at index {i}: {e.message}",
                field="permissions",
                value=permissions,
                validation_rule="list_item_validation"
            )
    
    # Remove duplicates while preserving order
    seen = set()
    unique_permissions = []
    for perm in validated_permissions:
        if perm not in seen:
            seen.add(perm)
            unique_permissions.append(perm)
    
    return unique_permissions


def validate_user_input(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate user input data.
    
    Args:
        data: Dictionary containing user data
        
    Returns:
        Dict[str, Any]: Validated user data
        
    Raises:
        ValidationError: If any field is invalid
    """
    validated_data = {}
    
    # Required fields
    if "user_id" not in data:
        raise ValidationError(
            "user_id is required",
            field="user_id",
            validation_rule="required_field"
        )
    
    validated_data["user_id"] = validate_user_id(data["user_id"])
    
    # Optional fields
    if "username" in data and data["username"]:
        validated_data["username"] = validate_username(data["username"])
    
    if "email" in data and data["email"]:
        validated_data["email"] = validate_email(data["email"])
    
    if "display_name" in data:
        validated_data["display_name"] = validate_display_name(data["display_name"])
    
    if "permissions" in data:
        validated_data["permissions"] = validate_permissions_list(data["permissions"])
    
    if "groups" in data:
        validated_data["groups"] = validate_groups_list(data["groups"])
    
    if "is_admin" in data:
        validated_data["is_admin"] = validate_boolean(data["is_admin"], "is_admin")
    
    if "is_active" in data:
        validated_data["is_active"] = validate_boolean(data["is_active"], "is_active")
    
    if "metadata" in data:
        validated_data["metadata"] = validate_metadata(data["metadata"])
    
    return validated_data


def validate_command_input(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate command input data.
    
    Args:
        data: Dictionary containing command data
        
    Returns:
        Dict[str, Any]: Validated command data
        
    Raises:
        ValidationError: If any field is invalid
    """
    validated_data = {}
    
    # Required fields
    required_fields = ["name", "permission", "description"]
    for field in required_fields:
        if field not in data:
            raise ValidationError(
                f"{field} is required",
                field=field,
                validation_rule="required_field"
            )
    
    validated_data["name"] = validate_command_name(data["name"])
    validated_data["permission"] = validate_permission(data["permission"])
    validated_data["description"] = validate_description(data["description"])
    
    # Optional fields
    if "category" in data:
        validated_data["category"] = validate_category(data["category"])
    
    if "examples" in data:
        validated_data["examples"] = validate_examples_list(data["examples"])
    
    if "parameters" in data:
        validated_data["parameters"] = validate_parameters_list(data["parameters"])
    
    if "admin_only" in data:
        validated_data["admin_only"] = validate_boolean(data["admin_only"], "admin_only")
    
    if "hidden" in data:
        validated_data["hidden"] = validate_boolean(data["hidden"], "hidden")
    
    if "rate_limit" in data:
        validated_data["rate_limit"] = validate_rate_limit(data["rate_limit"])
    
    return validated_data


def validate_display_name(display_name: str) -> str:
    """Validate display name."""
    if not isinstance(display_name, str):
        raise ValidationError(
            "Display name must be a string",
            field="display_name",
            value=display_name,
            validation_rule="type_check"
        )
    
    if len(display_name) > 100:
        raise ValidationError(
            "Display name too long (max 100 characters)",
            field="display_name",
            value=display_name,
            validation_rule="length_check"
        )
    
    return display_name.strip()


def validate_groups_list(groups: List[str]) -> List[str]:
    """Validate list of group names."""
    if not isinstance(groups, list):
        raise ValidationError(
            "Groups must be a list",
            field="groups",
            value=groups,
            validation_rule="type_check"
        )
    
    validated_groups = []
    for i, group in enumerate(groups):
        if not isinstance(group, str):
            raise ValidationError(
                f"Group at index {i} must be a string",
                field="groups",
                value=groups,
                validation_rule="list_item_type"
            )
        
        if not group.strip():
            raise ValidationError(
                f"Group at index {i} cannot be empty",
                field="groups",
                value=groups,
                validation_rule="list_item_empty"
            )
        
        validated_groups.append(group.strip().lower())
    
    return list(set(validated_groups))  # Remove duplicates


def validate_boolean(value: Any, field_name: str) -> bool:
    """Validate boolean value."""
    if isinstance(value, bool):
        return value
    
    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        elif value.lower() in ("false", "0", "no", "off"):
            return False
    
    if isinstance(value, int):
        return bool(value)
    
    raise ValidationError(
        f"{field_name} must be a boolean value",
        field=field_name,
        value=value,
        validation_rule="boolean_check"
    )


def validate_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Validate metadata dictionary."""
    if not isinstance(metadata, dict):
        raise ValidationError(
            "Metadata must be a dictionary",
            field="metadata",
            value=metadata,
            validation_rule="type_check"
        )
    
    # Check for reasonable size limits
    if len(metadata) > 50:
        raise ValidationError(
            "Too many metadata fields (max 50)",
            field="metadata",
            value=metadata,
            validation_rule="size_limit"
        )
    
    # Validate keys and values
    validated_metadata = {}
    for key, value in metadata.items():
        if not isinstance(key, str):
            raise ValidationError(
                "Metadata keys must be strings",
                field="metadata",
                value=metadata,
                validation_rule="key_type"
            )
        
        if len(key) > 100:
            raise ValidationError(
                f"Metadata key '{key}' too long (max 100 characters)",
                field="metadata",
                value=metadata,
                validation_rule="key_length"
            )
        
        # Convert value to string if it's not a basic type
        if isinstance(value, (str, int, float, bool, type(None))):
            validated_metadata[key] = value
        else:
            validated_metadata[key] = str(value)
    
    return validated_metadata


def validate_description(description: str) -> str:
    """Validate description text."""
    if not isinstance(description, str):
        raise ValidationError(
            "Description must be a string",
            field="description",
            value=description,
            validation_rule="type_check"
        )
    
    if not description.strip():
        raise ValidationError(
            "Description cannot be empty",
            field="description",
            value=description,
            validation_rule="not_empty"
        )
    
    if len(description) > 500:
        raise ValidationError(
            "Description too long (max 500 characters)",
            field="description",
            value=description,
            validation_rule="length_check"
        )
    
    return description.strip()


def validate_category(category: str) -> str:
    """Validate category name."""
    if not isinstance(category, str):
        raise ValidationError(
            "Category must be a string",
            field="category",
            value=category,
            validation_rule="type_check"
        )
    
    if not category.strip():
        raise ValidationError(
            "Category cannot be empty",
            field="category",
            value=category,
            validation_rule="not_empty"
        )
    
    if len(category) > 50:
        raise ValidationError(
            "Category name too long (max 50 characters)",
            field="category",
            value=category,
            validation_rule="length_check"
        )
    
    return category.strip()


def validate_examples_list(examples: List[str]) -> List[str]:
    """Validate list of command examples."""
    if not isinstance(examples, list):
        raise ValidationError(
            "Examples must be a list",
            field="examples",
            value=examples,
            validation_rule="type_check"
        )
    
    if len(examples) > 10:
        raise ValidationError(
            "Too many examples (max 10)",
            field="examples",
            value=examples,
            validation_rule="size_limit"
        )
    
    validated_examples = []
    for i, example in enumerate(examples):
        if not isinstance(example, str):
            raise ValidationError(
                f"Example at index {i} must be a string",
                field="examples",
                value=examples,
                validation_rule="list_item_type"
            )
        
        if not example.strip():
            raise ValidationError(
                f"Example at index {i} cannot be empty",
                field="examples",
                value=examples,
                validation_rule="list_item_empty"
            )
        
        if len(example) > 200:
            raise ValidationError(
                f"Example at index {i} too long (max 200 characters)",
                field="examples",
                value=examples,
                validation_rule="list_item_length"
            )
        
        validated_examples.append(example.strip())
    
    return validated_examples


def validate_parameters_list(parameters: List[str]) -> List[str]:
    """Validate list of command parameters."""
    if not isinstance(parameters, list):
        raise ValidationError(
            "Parameters must be a list",
            field="parameters",
            value=parameters,
            validation_rule="type_check"
        )
    
    if len(parameters) > 20:
        raise ValidationError(
            "Too many parameters (max 20)",
            field="parameters",
            value=parameters,
            validation_rule="size_limit"
        )
    
    validated_parameters = []
    for i, param in enumerate(parameters):
        if not isinstance(param, str):
            raise ValidationError(
                f"Parameter at index {i} must be a string",
                field="parameters",
                value=parameters,
                validation_rule="list_item_type"
            )
        
        if not param.strip():
            raise ValidationError(
                f"Parameter at index {i} cannot be empty",
                field="parameters",
                value=parameters,
                validation_rule="list_item_empty"
            )
        
        validated_parameters.append(param.strip())
    
    return validated_parameters


def validate_rate_limit(rate_limit: int) -> int:
    """Validate rate limit value."""
    if not isinstance(rate_limit, int):
        raise ValidationError(
            "Rate limit must be an integer",
            field="rate_limit",
            value=rate_limit,
            validation_rule="type_check"
        )
    
    if rate_limit < 1:
        raise ValidationError(
            "Rate limit must be positive",
            field="rate_limit",
            value=rate_limit,
            validation_rule="positive_check"
        )
    
    if rate_limit > 1000:
        raise ValidationError(
            "Rate limit too high (max 1000)",
            field="rate_limit",
            value=rate_limit,
            validation_rule="max_value"
        )
    
    return rate_limit


def sanitize_input(text: str) -> str:
    """
    Sanitize text input to prevent injection attacks.
    
    Args:
        text: Text to sanitize
        
    Returns:
        str: Sanitized text
    """
    if not isinstance(text, str):
        return str(text)
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Limit length
    if len(text) > 10000:
        text = text[:10000]
    
    # Strip whitespace
    text = text.strip()
    
    return text
