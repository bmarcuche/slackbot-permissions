"""
Test fixtures and configuration for Slack Permission System tests.

This module provides common fixtures and test utilities used across
all test modules.
"""

import pytest
from unittest.mock import Mock, MagicMock
from datetime import datetime
from typing import Dict, Any, List

from slack_permissions import (
    PermissionManager,
    CommandRegistry,
    UserManager,
    AccessControlEngine,
    SlackGroupsIntegration
)
from slack_permissions.core.user_manager import UserProfile
from slack_permissions.core.command_registry import CommandDefinition


@pytest.fixture
def mock_slack_client():
    """Mock Slack WebClient for testing."""
    client = Mock()
    
    # Mock common Slack API responses
    client.chat_postEphemeral.return_value = {"ok": True}
    client.users_info.return_value = {
        "ok": True,
        "user": {
            "id": "U123456",
            "name": "testuser",
            "profile": {
                "email": "test@example.com",
                "display_name": "Test User",
                "real_name": "Test User"
            }
        }
    }
    client.users_list.return_value = {
        "ok": True,
        "members": [
            {
                "id": "U123456",
                "name": "testuser",
                "is_bot": False,
                "deleted": False,
                "profile": {
                    "email": "test@example.com",
                    "display_name": "Test User"
                }
            }
        ],
        "response_metadata": {"next_cursor": ""}
    }
    client.usergroups_list.return_value = {
        "ok": True,
        "usergroups": [
            {
                "id": "S123456",
                "name": "developers",
                "description": "Development team"
            }
        ]
    }
    client.usergroups_users_list.return_value = {
        "ok": True,
        "users": ["U123456"]
    }
    
    return client


@pytest.fixture
def command_registry():
    """Fresh command registry for testing."""
    registry = CommandRegistry()
    
    # Add some test commands
    registry.register_command(
        name="test command",
        permission="test_permission",
        description="A test command",
        category="Testing",
        examples=["test command example"]
    )
    
    registry.register_command(
        name="admin command",
        permission="admin_permission",
        description="An admin command",
        category="Admin",
        admin_only=True
    )
    
    registry.register_command(
        name="delete user",
        permission="user_management",
        description="Delete a user",
        category="User Management",
        examples=["delete user john.doe"]
    )
    
    return registry


@pytest.fixture
def user_manager():
    """Fresh user manager for testing."""
    manager = UserManager()
    
    # Add some test users
    manager.create_user(
        user_id="U123456",
        username="testuser",
        email="test@example.com",
        display_name="Test User",
        permissions=["test_permission"],
        groups=["developers"]
    )
    
    manager.create_user(
        user_id="U789012",
        username="adminuser",
        email="admin@example.com",
        display_name="Admin User",
        permissions=["admin_permission", "user_management"],
        is_admin=True
    )
    
    manager.create_user(
        user_id="U345678",
        username="inactiveuser",
        email="inactive@example.com",
        display_name="Inactive User",
        is_active=False
    )
    
    # Create test groups
    manager.create_group("developers", ["test_permission", "code_review"])
    manager.create_group("admins", ["admin_permission", "user_management"])
    
    return manager


@pytest.fixture
def access_control_engine(command_registry, user_manager):
    """Access control engine with test data."""
    return AccessControlEngine(
        command_registry=command_registry,
        user_manager=user_manager,
        enable_caching=True,
        default_deny=True
    )


@pytest.fixture
def slack_integration(mock_slack_client, user_manager):
    """Slack integration with mocked client."""
    return SlackGroupsIntegration(
        slack_client=mock_slack_client,
        user_manager=user_manager,
        group_permission_mapping={
            "S123456": ["test_permission", "code_review"]
        }
    )


@pytest.fixture
def permission_manager(command_registry, user_manager, access_control_engine, slack_integration):
    """Complete permission manager with all components."""
    return PermissionManager(
        command_registry=command_registry,
        user_manager=user_manager,
        slack_integration=slack_integration
    )


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "user_id": "U123456",
        "username": "testuser",
        "email": "test@example.com",
        "display_name": "Test User",
        "permissions": ["test_permission"],
        "groups": ["developers"],
        "is_admin": False,
        "is_active": True,
        "metadata": {"test": "data"}
    }


@pytest.fixture
def sample_command_data():
    """Sample command data for testing."""
    return {
        "name": "test command",
        "permission": "test_permission",
        "description": "A test command",
        "category": "Testing",
        "examples": ["test command example"],
        "parameters": ["param1", "param2"]
    }


@pytest.fixture
def mock_slack_message():
    """Mock Slack message data."""
    return {
        "user": "U123456",
        "channel": "C123456",
        "text": "test command with parameters",
        "ts": "1234567890.123456"
    }


@pytest.fixture
def mock_slack_context():
    """Mock Slack context data."""
    return {
        "matches": ["test command", "with parameters"]
    }


class MockSlackResponse:
    """Mock Slack API response."""
    
    def __init__(self, data: Dict[str, Any], ok: bool = True):
        self.data = data
        self.data["ok"] = ok
    
    def __getitem__(self, key):
        return self.data[key]
    
    def get(self, key, default=None):
        return self.data.get(key, default)


@pytest.fixture
def mock_slack_responses():
    """Factory for creating mock Slack responses."""
    def _create_response(data: Dict[str, Any], ok: bool = True):
        return MockSlackResponse(data, ok)
    
    return _create_response


# Test data factories
def create_test_user(
    user_id: str = "U123456",
    username: str = "testuser",
    permissions: List[str] = None,
    is_admin: bool = False,
    is_active: bool = True
) -> UserProfile:
    """Create a test user profile."""
    return UserProfile(
        user_id=user_id,
        username=username,
        email=f"{username}@example.com",
        display_name=username.title(),
        permissions=set(permissions or []),
        is_admin=is_admin,
        is_active=is_active
    )


def create_test_command(
    name: str = "test command",
    permission: str = "test_permission",
    description: str = "A test command",
    admin_only: bool = False
) -> CommandDefinition:
    """Create a test command definition."""
    return CommandDefinition(
        name=name,
        permission=permission,
        description=description,
        admin_only=admin_only
    )


# Pytest markers for test organization
pytestmark = [
    pytest.mark.unit,
]


# Test utilities
def assert_validation_result(result, expected_success: bool, expected_user_id: str = None):
    """Assert validation result properties."""
    assert result.success == expected_success
    assert result.access_granted == expected_success
    if expected_user_id:
        assert result.user_id == expected_user_id
    assert result.timestamp is not None


def assert_user_has_permissions(user: UserProfile, expected_permissions: List[str]):
    """Assert user has expected permissions."""
    for permission in expected_permissions:
        assert user.has_permission(permission), f"User missing permission: {permission}"


def assert_command_matches_text(command: CommandDefinition, text: str):
    """Assert command matches given text."""
    assert command.matches(text), f"Command '{command.name}' should match '{text}'"
