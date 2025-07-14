"""
Unit tests for PermissionManager.

This module tests the main orchestrator class that coordinates
all permission-related operations.
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime

from slack_permissions.core.permission_manager import PermissionManager, ValidationResult
from slack_permissions.utils.exceptions import PermissionError, CommandNotFoundError
from tests.conftest import assert_validation_result, create_test_user


class TestPermissionManager:
    """Test cases for PermissionManager class."""
    
    def test_initialization(self):
        """Test PermissionManager initialization."""
        manager = PermissionManager()
        
        assert manager.command_registry is not None
        assert manager.user_manager is not None
        assert manager.access_control is not None
        assert manager.default_deny is True
        assert manager._validation_count == 0
        assert manager._permission_grants == 0
        assert manager._permission_denials == 0
    
    def test_initialization_with_custom_components(self, command_registry, user_manager, slack_integration):
        """Test initialization with custom components."""
        manager = PermissionManager(
            command_registry=command_registry,
            user_manager=user_manager,
            slack_integration=slack_integration,
            default_deny=False
        )
        
        assert manager.command_registry is command_registry
        assert manager.user_manager is user_manager
        assert manager.slack_integration is slack_integration
        assert manager.default_deny is False
    
    def test_validate_request_success(self, permission_manager):
        """Test successful permission validation."""
        result = permission_manager.validate_request(
            user_id="U123456",
            command="test command"
        )
        
        assert_validation_result(result, expected_success=True, expected_user_id="U123456")
        assert result.command == "test command"
        assert result.permission == "test_permission"
        assert result.error_message is None
        assert permission_manager._permission_grants == 1
        assert permission_manager._validation_count == 1
    
    def test_validate_request_permission_denied(self, permission_manager):
        """Test permission denied scenario."""
        result = permission_manager.validate_request(
            user_id="U123456",
            command="admin command"  # User doesn't have admin_permission
        )
        
        assert_validation_result(result, expected_success=False, expected_user_id="U123456")
        assert result.command == "admin command"
        assert result.permission == "admin_permission"
        assert result.error_code == "PERMISSION_DENIED"
        assert permission_manager._permission_denials == 1
    
    def test_validate_request_command_not_found(self, permission_manager):
        """Test validation with non-existent command."""
        result = permission_manager.validate_request(
            user_id="U123456",
            command="nonexistent command"
        )
        
        assert_validation_result(result, expected_success=False, expected_user_id="U123456")
        assert result.error_code == "COMMAND_NOT_FOUND"
        assert "not found" in result.error_message.lower()
    
    def test_validate_request_user_not_found(self, permission_manager):
        """Test validation with non-existent user."""
        result = permission_manager.validate_request(
            user_id="U999999",  # Non-existent user
            command="test command"
        )
        
        assert_validation_result(result, expected_success=False, expected_user_id="U999999")
        assert result.error_code == "USER_NOT_FOUND"
    
    def test_validate_request_inactive_user(self, permission_manager):
        """Test validation with inactive user."""
        result = permission_manager.validate_request(
            user_id="U345678",  # Inactive user from fixture
            command="test command"
        )
        
        assert_validation_result(result, expected_success=False, expected_user_id="U345678")
        assert result.error_code == "USER_INACTIVE"
    
    def test_validate_request_admin_bypass(self, permission_manager):
        """Test admin user bypassing permission checks."""
        result = permission_manager.validate_request(
            user_id="U789012",  # Admin user from fixture
            command="test command"  # Admin doesn't have test_permission but should bypass
        )
        
        assert_validation_result(result, expected_success=True, expected_user_id="U789012")
    
    def test_validate_request_with_slack_client(self, permission_manager, mock_slack_client):
        """Test validation with Slack client for error messaging."""
        result = permission_manager.validate_request(
            user_id="U123456",
            command="admin command",
            client=mock_slack_client,
            channel_id="C123456"
        )
        
        assert_validation_result(result, expected_success=False)
        
        # Verify error message was sent
        mock_slack_client.chat_postEphemeral.assert_called_once()
        call_args = mock_slack_client.chat_postEphemeral.call_args
        assert call_args[1]["user"] == "U123456"
        assert call_args[1]["channel"] == "C123456"
        assert "permission" in call_args[1]["text"].lower()
    
    def test_validate_request_with_message_text_matching(self, permission_manager):
        """Test validation using message text pattern matching."""
        result = permission_manager.validate_request(
            user_id="U789012",  # Admin user
            command="unknown",  # Command name doesn't exist
            message_text="delete user john.doe"  # But message matches pattern
        )
        
        assert_validation_result(result, expected_success=True)
        assert result.command == "delete user"
        assert result.permission == "user_management"
    
    def test_get_user_commands(self, permission_manager):
        """Test getting commands available to a user."""
        commands = permission_manager.get_user_commands("U123456")
        
        # User should only see commands they have permission for
        command_names = [cmd.name for cmd in commands]
        assert "test command" in command_names
        assert "admin command" not in command_names  # No admin permission
        assert "delete user" not in command_names    # No user_management permission
    
    def test_get_user_commands_admin_user(self, permission_manager):
        """Test getting commands for admin user."""
        commands = permission_manager.get_user_commands("U789012")  # Admin user
        
        # Admin should see all commands
        command_names = [cmd.name for cmd in commands]
        assert "test command" in command_names
        assert "admin command" in command_names
        assert "delete user" in command_names
    
    def test_get_user_commands_with_category_filter(self, permission_manager):
        """Test getting commands filtered by category."""
        commands = permission_manager.get_user_commands("U789012", category="Admin")
        
        command_names = [cmd.name for cmd in commands]
        assert "admin command" in command_names
        assert "test command" not in command_names  # Different category
    
    def test_get_user_commands_nonexistent_user(self, permission_manager):
        """Test getting commands for non-existent user."""
        commands = permission_manager.get_user_commands("U999999")
        assert commands == []
    
    def test_sync_user_from_slack(self, permission_manager, mock_slack_client):
        """Test syncing user from Slack."""
        user = permission_manager.sync_user_from_slack("U123456")
        
        assert user is not None
        assert user.user_id == "U123456"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
    
    def test_sync_user_from_slack_no_integration(self):
        """Test syncing when no Slack integration configured."""
        manager = PermissionManager()  # No slack_integration
        user = manager.sync_user_from_slack("U123456")
        assert user is None
    
    def test_register_command_delegation(self, permission_manager):
        """Test command registration delegates to registry."""
        cmd = permission_manager.register_command(
            name="new command",
            permission="new_permission",
            description="A new command"
        )
        
        assert cmd.name == "new command"
        assert cmd.permission == "new_permission"
        
        # Verify it's in the registry
        retrieved_cmd = permission_manager.command_registry.get_command("new command")
        assert retrieved_cmd.name == "new command"
    
    def test_create_user_delegation(self, permission_manager):
        """Test user creation delegates to user manager."""
        user = permission_manager.create_user(
            user_id="U999999",
            username="newuser",
            permissions=["test_permission"]
        )
        
        assert user.user_id == "U999999"
        assert user.username == "newuser"
        
        # Verify it's in the user manager
        retrieved_user = permission_manager.user_manager.get_user("U999999")
        assert retrieved_user.username == "newuser"
    
    def test_get_stats(self, permission_manager):
        """Test getting comprehensive statistics."""
        # Perform some operations to generate stats
        permission_manager.validate_request("U123456", "test command")
        permission_manager.validate_request("U123456", "admin command")
        
        stats = permission_manager.get_stats()
        
        assert "validation_stats" in stats
        assert "command_stats" in stats
        assert "user_stats" in stats
        assert "access_control_stats" in stats
        
        validation_stats = stats["validation_stats"]
        assert validation_stats["total_validations"] == 2
        assert validation_stats["permission_grants"] == 1
        assert validation_stats["permission_denials"] == 1
        assert 0 <= validation_stats["grant_rate"] <= 1
    
    def test_clear_all(self, permission_manager):
        """Test clearing all data."""
        # Perform some operations first
        permission_manager.validate_request("U123456", "test command")
        
        # Clear all data
        permission_manager.clear_all()
        
        # Verify stats are reset
        assert permission_manager._validation_count == 0
        assert permission_manager._permission_grants == 0
        assert permission_manager._permission_denials == 0
    
    @patch('slack_permissions.core.permission_manager.logger')
    def test_validate_request_exception_handling(self, mock_logger, permission_manager):
        """Test exception handling in validate_request."""
        # Mock an exception in the access control engine
        with patch.object(permission_manager.access_control, 'check_permission', side_effect=Exception("Test error")):
            result = permission_manager.validate_request("U123456", "test command")
            
            assert_validation_result(result, expected_success=False)
            assert result.error_code == "VALIDATION_ERROR"
            assert result.error_message == "Internal validation error"
            
            # Verify error was logged
            mock_logger.error.assert_called()


class TestValidationResult:
    """Test cases for ValidationResult class."""
    
    def test_initialization(self):
        """Test ValidationResult initialization."""
        result = ValidationResult(
            success=True,
            user_id="U123456",
            command="test command",
            permission="test_permission"
        )
        
        assert result.success is True
        assert result.access_granted is True  # Alias
        assert result.user_id == "U123456"
        assert result.command == "test command"
        assert result.permission == "test_permission"
        assert result.error_message is None
        assert result.error_code is None
        assert result.context == {}
        assert isinstance(result.timestamp, datetime)
    
    def test_initialization_with_error(self):
        """Test ValidationResult initialization with error."""
        result = ValidationResult(
            success=False,
            user_id="U123456",
            error_message="Access denied",
            error_code="PERMISSION_DENIED",
            context={"test": "data"}
        )
        
        assert result.success is False
        assert result.access_granted is False
        assert result.error_message == "Access denied"
        assert result.error_code == "PERMISSION_DENIED"
        assert result.context == {"test": "data"}
    
    def test_to_dict(self):
        """Test converting ValidationResult to dictionary."""
        result = ValidationResult(
            success=True,
            user_id="U123456",
            command="test command",
            permission="test_permission",
            context={"key": "value"}
        )
        
        result_dict = result.to_dict()
        
        assert result_dict["success"] is True
        assert result_dict["user_id"] == "U123456"
        assert result_dict["command"] == "test command"
        assert result_dict["permission"] == "test_permission"
        assert result_dict["context"] == {"key": "value"}
        assert "timestamp" in result_dict
        assert isinstance(result_dict["timestamp"], str)  # ISO format


@pytest.mark.integration
class TestPermissionManagerIntegration:
    """Integration tests for PermissionManager with real components."""
    
    def test_full_permission_flow(self):
        """Test complete permission validation flow."""
        manager = PermissionManager()
        
        # Register a command
        manager.register_command(
            name="integration test",
            permission="integration_permission",
            description="Integration test command"
        )
        
        # Create a user
        manager.create_user(
            user_id="U_INTEGRATION",
            username="integration_user",
            permissions=["integration_permission"]
        )
        
        # Validate permission
        result = manager.validate_request(
            user_id="U_INTEGRATION",
            command="integration test"
        )
        
        assert_validation_result(result, expected_success=True)
        assert result.command == "integration test"
        assert result.permission == "integration_permission"
    
    def test_permission_caching_behavior(self):
        """Test that permission caching works correctly."""
        manager = PermissionManager()
        
        # Register command and create user
        manager.register_command(
            name="cached test",
            permission="cache_permission",
            description="Cache test command"
        )
        manager.create_user(
            user_id="U_CACHE",
            username="cache_user",
            permissions=["cache_permission"]
        )
        
        # First validation (cache miss)
        result1 = manager.validate_request("U_CACHE", "cached test")
        assert result1.success is True
        
        # Second validation (cache hit)
        result2 = manager.validate_request("U_CACHE", "cached test")
        assert result2.success is True
        
        # Both should succeed, demonstrating caching doesn't break functionality
        assert result1.success == result2.success
