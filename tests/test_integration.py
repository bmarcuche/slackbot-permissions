"""
Integration tests for Slack Permission System.

This module tests the complete system integration including all components
working together in realistic scenarios.
"""

import pytest
from unittest.mock import Mock, patch
import os
import tempfile
import json

from slack_permissions import (
    PermissionManager,
    CommandRegistry,
    UserManager,
    SlackGroupsIntegration,
    require_permission,
    command,
    admin_only
)
from slack_permissions.utils.decorators import set_global_permission_manager
from tests.conftest import assert_validation_result


@pytest.mark.integration
class TestFullSystemIntegration:
    """Test complete system integration scenarios."""
    
    def test_complete_permission_workflow(self):
        """Test a complete permission workflow from registration to validation."""
        # Initialize system
        manager = PermissionManager()
        
        # Step 1: Register commands
        manager.register_command(
            name="deploy app",
            permission="deployment",
            description="Deploy application to production",
            category="DevOps",
            examples=["deploy app to production", "deploy app staging"],
            admin_only=False
        )
        
        manager.register_command(
            name="delete database",
            permission="database_admin",
            description="Delete a database",
            category="Database",
            admin_only=True
        )
        
        # Step 2: Create users with different permission levels
        # Regular developer
        dev_user = manager.create_user(
            user_id="U_DEV_001",
            username="john.developer",
            email="john@company.com",
            display_name="John Developer",
            permissions=["deployment", "code_review"],
            groups=["developers"]
        )
        
        # Database admin
        dba_user = manager.create_user(
            user_id="U_DBA_001",
            username="jane.dba",
            email="jane@company.com",
            display_name="Jane DBA",
            permissions=["database_admin", "deployment"],
            groups=["dba", "developers"]
        )
        
        # System admin
        admin_user = manager.create_user(
            user_id="U_ADMIN_001",
            username="admin",
            email="admin@company.com",
            display_name="System Admin",
            is_admin=True
        )
        
        # Step 3: Test permission validations
        test_cases = [
            # Developer can deploy
            ("U_DEV_001", "deploy app", True, "Developer deploying app"),
            # Developer cannot delete database
            ("U_DEV_001", "delete database", False, "Developer accessing admin command"),
            # DBA can delete database
            ("U_DBA_001", "delete database", True, "DBA accessing database command"),
            # Admin can do everything
            ("U_ADMIN_001", "delete database", True, "Admin accessing any command"),
            ("U_ADMIN_001", "deploy app", True, "Admin accessing regular command"),
            # Non-existent user
            ("U_UNKNOWN", "deploy app", False, "Unknown user"),
        ]
        
        for user_id, command, expected_success, description in test_cases:
            result = manager.validate_request(user_id=user_id, command=command)
            assert result.success == expected_success, f"Failed: {description}"
            print(f"✅ {description}: {'GRANTED' if result.success else 'DENIED'}")
        
        # Step 4: Test command discovery
        dev_commands = manager.get_user_commands("U_DEV_001")
        dev_command_names = [cmd.name for cmd in dev_commands]
        assert "deploy app" in dev_command_names
        assert "delete database" not in dev_command_names
        
        admin_commands = manager.get_user_commands("U_ADMIN_001")
        admin_command_names = [cmd.name for cmd in admin_commands]
        assert "deploy app" in admin_command_names
        assert "delete database" in admin_command_names
        
        # Step 5: Verify statistics
        stats = manager.get_stats()
        assert stats["validation_stats"]["total_validations"] == len(test_cases)
        assert stats["command_stats"]["total_commands"] == 2
        assert stats["user_stats"]["total_users"] == 3
        
        print("✅ Complete permission workflow test passed")
    
    def test_slack_integration_workflow(self, mock_slack_client):
        """Test Slack integration workflow."""
        # Initialize system with Slack integration
        user_manager = UserManager()
        slack_integration = SlackGroupsIntegration(
            slack_client=mock_slack_client,
            user_manager=user_manager,
            group_permission_mapping={
                "S_DEVELOPERS": ["code_review", "deployment"],
                "S_ADMINS": ["user_management", "system_admin"]
            }
        )
        
        manager = PermissionManager(
            user_manager=user_manager,
            slack_integration=slack_integration
        )
        
        # Register commands
        manager.register_command(
            name="code review",
            permission="code_review",
            description="Review code changes"
        )
        
        # Mock Slack API responses for user sync
        mock_slack_client.users_info.return_value = {
            "ok": True,
            "user": {
                "id": "U_SLACK_001",
                "name": "slack.user",
                "profile": {
                    "email": "slack.user@company.com",
                    "display_name": "Slack User",
                    "real_name": "Slack User"
                }
            }
        }
        
        mock_slack_client.usergroups_list.return_value = {
            "ok": True,
            "usergroups": [
                {"id": "S_DEVELOPERS", "name": "developers"}
            ]
        }
        
        mock_slack_client.usergroups_users_list.return_value = {
            "ok": True,
            "users": ["U_SLACK_001"]
        }
        
        # Sync user from Slack
        synced_user = manager.sync_user_from_slack("U_SLACK_001")
        assert synced_user is not None
        assert synced_user.user_id == "U_SLACK_001"
        assert synced_user.username == "slack.user"
        assert "code_review" in synced_user.permissions
        
        # Test permission validation for synced user
        result = manager.validate_request("U_SLACK_001", "code review")
        assert result.success is True
        
        print("✅ Slack integration workflow test passed")
    
    def test_decorator_integration(self):
        """Test decorator integration with permission system."""
        # Initialize system
        manager = PermissionManager()
        set_global_permission_manager(manager)
        
        # Register commands and users
        manager.register_command(
            name="test decorator",
            permission="decorator_test",
            description="Test decorator functionality"
        )
        
        manager.create_user(
            user_id="U_DECORATOR_001",
            username="decorator.user",
            permissions=["decorator_test"]
        )
        
        manager.create_user(
            user_id="U_NO_PERM_001",
            username="no.perm.user",
            permissions=[]
        )
        
        # Mock Slack client
        mock_client = Mock()
        
        # Test function with permission decorator
        @require_permission("decorator_test")
        def test_function(message, client):
            return "Function executed successfully"
        
        # Test with authorized user
        authorized_message = {
            "user": "U_DECORATOR_001",
            "channel": "C123456",
            "text": "test decorator"
        }
        
        result = test_function(authorized_message, mock_client)
        assert result == "Function executed successfully"
        
        # Test with unauthorized user
        unauthorized_message = {
            "user": "U_NO_PERM_001",
            "channel": "C123456",
            "text": "test decorator"
        }
        
        result = test_function(unauthorized_message, mock_client)
        assert result is None  # Function should not execute
        
        # Verify error message was sent
        mock_client.chat_postEphemeral.assert_called()
        
        print("✅ Decorator integration test passed")
    
    def test_command_decorator_integration(self):
        """Test command decorator integration."""
        manager = PermissionManager()
        set_global_permission_manager(manager)
        
        # Create user
        manager.create_user(
            user_id="U_CMD_001",
            username="cmd.user",
            permissions=["auto_registered"]
        )
        
        # Mock client
        mock_client = Mock()
        
        # Function with command decorator (auto-registers command)
        @command(
            name="auto command",
            permission="auto_registered",
            description="Auto-registered command",
            category="Auto"
        )
        def auto_command_handler(message, client):
            return "Auto command executed"
        
        # Verify command was registered
        cmd = manager.command_registry.get_command("auto command")
        assert cmd.name == "auto command"
        assert cmd.permission == "auto_registered"
        assert cmd.category == "Auto"
        
        # Test execution
        message = {
            "user": "U_CMD_001",
            "channel": "C123456",
            "text": "auto command"
        }
        
        result = auto_command_handler(message, mock_client)
        assert result == "Auto command executed"
        
        print("✅ Command decorator integration test passed")
    
    def test_admin_decorator_integration(self):
        """Test admin decorator integration."""
        manager = PermissionManager()
        set_global_permission_manager(manager)
        
        # Create regular and admin users
        manager.create_user(
            user_id="U_REGULAR_001",
            username="regular.user",
            is_admin=False
        )
        
        manager.create_user(
            user_id="U_ADMIN_001",
            username="admin.user",
            is_admin=True
        )
        
        mock_client = Mock()
        
        @admin_only()
        def admin_function(message, client):
            return "Admin function executed"
        
        # Test with regular user
        regular_message = {
            "user": "U_REGULAR_001",
            "channel": "C123456",
            "text": "admin command"
        }
        
        result = admin_function(regular_message, mock_client)
        assert result is None  # Should not execute
        
        # Test with admin user
        admin_message = {
            "user": "U_ADMIN_001",
            "channel": "C123456",
            "text": "admin command"
        }
        
        result = admin_function(admin_message, mock_client)
        assert result == "Admin function executed"
        
        print("✅ Admin decorator integration test passed")
    
    def test_caching_and_performance(self):
        """Test caching behavior and performance characteristics."""
        manager = PermissionManager(enable_caching=True)
        
        # Register command and create user
        manager.register_command(
            name="cached command",
            permission="cache_test",
            description="Test caching"
        )
        
        manager.create_user(
            user_id="U_CACHE_001",
            username="cache.user",
            permissions=["cache_test"]
        )
        
        # First validation (cache miss)
        result1 = manager.validate_request("U_CACHE_001", "cached command")
        assert result1.success is True
        
        # Second validation (cache hit)
        result2 = manager.validate_request("U_CACHE_001", "cached command")
        assert result2.success is True
        
        # Verify cache statistics
        stats = manager.get_stats()
        cache_stats = stats["access_control_stats"]["cache"]
        assert cache_stats["total_requests"] >= 2
        
        print("✅ Caching and performance test passed")
    
    def test_error_handling_and_recovery(self):
        """Test error handling and system recovery."""
        manager = PermissionManager()
        
        # Test with invalid inputs
        with pytest.raises(Exception):
            manager.register_command(
                name="",  # Invalid empty name
                permission="test",
                description="Test"
            )
        
        # Test validation with non-existent command
        result = manager.validate_request("U_TEST", "nonexistent command")
        assert result.success is False
        assert result.error_code == "COMMAND_NOT_FOUND"
        
        # Test validation with non-existent user
        manager.register_command(
            name="test command",
            permission="test_perm",
            description="Test"
        )
        
        result = manager.validate_request("U_NONEXISTENT", "test command")
        assert result.success is False
        assert result.error_code == "USER_NOT_FOUND"
        
        # System should still be functional after errors
        manager.create_user(
            user_id="U_RECOVERY_001",
            username="recovery.user",
            permissions=["test_perm"]
        )
        
        result = manager.validate_request("U_RECOVERY_001", "test command")
        assert result.success is True
        
        print("✅ Error handling and recovery test passed")
    
    def test_concurrent_operations(self):
        """Test system behavior under concurrent operations."""
        import threading
        import time
        
        manager = PermissionManager()
        
        # Register command
        manager.register_command(
            name="concurrent test",
            permission="concurrent_perm",
            description="Test concurrent access"
        )
        
        # Create multiple users
        for i in range(10):
            manager.create_user(
                user_id=f"U_CONCURRENT_{i:03d}",
                username=f"concurrent.user.{i}",
                permissions=["concurrent_perm"]
            )
        
        results = []
        errors = []
        
        def validate_permission(user_id):
            try:
                result = manager.validate_request(user_id, "concurrent test")
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        # Create and start threads
        threads = []
        for i in range(10):
            thread = threading.Thread(
                target=validate_permission,
                args=(f"U_CONCURRENT_{i:03d}",)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify results
        assert len(errors) == 0, f"Concurrent operations failed: {errors}"
        assert len(results) == 10
        assert all(result.success for result in results)
        
        print("✅ Concurrent operations test passed")


@pytest.mark.integration
@pytest.mark.slow
class TestRealWorldScenarios:
    """Test real-world usage scenarios."""
    
    def test_devops_team_scenario(self):
        """Test a realistic DevOps team permission scenario."""
        manager = PermissionManager()
        
        # Register DevOps commands
        commands = [
            ("deploy staging", "deployment_staging", "Deploy to staging environment"),
            ("deploy production", "deployment_production", "Deploy to production environment"),
            ("restart service", "service_management", "Restart system services"),
            ("view logs", "log_access", "View application logs"),
            ("database backup", "database_admin", "Create database backup"),
            ("user management", "user_admin", "Manage user accounts"),
        ]
        
        for name, permission, description in commands:
            manager.register_command(
                name=name,
                permission=permission,
                description=description,
                category="DevOps"
            )
        
        # Create team structure
        # Junior DevOps - limited permissions
        manager.create_user(
            user_id="U_JUNIOR_001",
            username="junior.devops",
            permissions=["deployment_staging", "log_access"],
            groups=["junior-devops"]
        )
        
        # Senior DevOps - more permissions
        manager.create_user(
            user_id="U_SENIOR_001",
            username="senior.devops",
            permissions=["deployment_staging", "deployment_production", "service_management", "log_access"],
            groups=["senior-devops"]
        )
        
        # DevOps Lead - admin privileges
        manager.create_user(
            user_id="U_LEAD_001",
            username="devops.lead",
            permissions=["database_admin", "user_admin"],
            is_admin=True,
            groups=["devops-leads"]
        )
        
        # Test realistic scenarios
        scenarios = [
            # Junior can deploy to staging
            ("U_JUNIOR_001", "deploy staging", True),
            # Junior cannot deploy to production
            ("U_JUNIOR_001", "deploy production", False),
            # Senior can deploy to production
            ("U_SENIOR_001", "deploy production", True),
            # Senior cannot manage users
            ("U_SENIOR_001", "user management", False),
            # Lead can do everything (admin)
            ("U_LEAD_001", "user management", True),
            ("U_LEAD_001", "deploy production", True),
        ]
        
        for user_id, command, expected in scenarios:
            result = manager.validate_request(user_id, command)
            assert result.success == expected, f"Scenario failed: {user_id} -> {command}"
        
        print("✅ DevOps team scenario test passed")
    
    def test_multi_tenant_scenario(self):
        """Test multi-tenant permission scenario."""
        manager = PermissionManager()
        
        # Register tenant-specific commands
        manager.register_command(
            name="access tenant data",
            permission="tenant_access",
            description="Access tenant-specific data"
        )
        
        # Create users for different tenants
        manager.create_user(
            user_id="U_TENANT_A_001",
            username="user.tenant.a",
            permissions=["tenant_access"],
            metadata={"tenant_id": "tenant_a"}
        )
        
        manager.create_user(
            user_id="U_TENANT_B_001",
            username="user.tenant.b",
            permissions=["tenant_access"],
            metadata={"tenant_id": "tenant_b"}
        )
        
        # Both users have the permission, but in a real scenario,
        # you'd add tenant-specific validation in the command handler
        result_a = manager.validate_request("U_TENANT_A_001", "access tenant data")
        result_b = manager.validate_request("U_TENANT_B_001", "access tenant data")
        
        assert result_a.success is True
        assert result_b.success is True
        
        # Verify tenant metadata is preserved
        user_a = manager.user_manager.get_user("U_TENANT_A_001")
        user_b = manager.user_manager.get_user("U_TENANT_B_001")
        
        assert user_a.metadata["tenant_id"] == "tenant_a"
        assert user_b.metadata["tenant_id"] == "tenant_b"
        
        print("✅ Multi-tenant scenario test passed")


if __name__ == "__main__":
    # Run integration tests
    pytest.main([__file__, "-v", "--tb=short"])
