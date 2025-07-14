#!/usr/bin/env python3
"""
Basic Usage Example for Slack Permission System.

This example demonstrates the core functionality of the permission system
including command registration, user management, and permission validation.
"""

import os
from slack_bolt import App
from slack_sdk import WebClient

from slack_permissions import (
    PermissionManager,
    CommandRegistry,
    UserManager,
    SlackGroupsIntegration,
    require_permission
)


def main():
    """Demonstrate basic usage of the Slack Permission System."""
    
    print("🚀 Slack Permission System - Basic Usage Example")
    print("=" * 50)
    
    # Initialize the permission system
    print("\n1. Initializing Permission System...")
    permission_manager = PermissionManager()
    
    # Register some commands
    print("\n2. Registering Commands...")
    
    # Basic command
    permission_manager.register_command(
        name="hello",
        permission="basic_commands",
        description="Say hello to the bot",
        category="General",
        examples=["hello", "hello world"]
    )
    
    # Admin command
    permission_manager.register_command(
        name="delete user",
        permission="user_management",
        description="Delete a user account",
        category="Administration",
        examples=["delete user john.doe"],
        admin_only=True
    )
    
    # DevOps command
    permission_manager.register_command(
        name="restart service",
        permission="service_management",
        description="Restart a system service",
        category="DevOps",
        examples=["restart service nginx", "restart service mysql"],
        parameters=["service_name"]
    )
    
    print(f"   ✅ Registered {len(permission_manager.command_registry.get_all_commands())} commands")
    
    # Create some users
    print("\n3. Creating Users...")
    
    # Regular user
    permission_manager.create_user(
        user_id="U123456",
        username="john.doe",
        email="john.doe@company.com",
        display_name="John Doe",
        permissions=["basic_commands"],
        groups=["developers"]
    )
    
    # DevOps user
    permission_manager.create_user(
        user_id="U789012",
        username="jane.smith",
        email="jane.smith@company.com",
        display_name="Jane Smith",
        permissions=["basic_commands", "service_management"],
        groups=["devops", "developers"]
    )
    
    # Admin user
    permission_manager.create_user(
        user_id="U345678",
        username="admin",
        email="admin@company.com",
        display_name="System Admin",
        is_admin=True
    )
    
    print(f"   ✅ Created {len(permission_manager.user_manager.get_all_users())} users")
    
    # Demonstrate permission validation
    print("\n4. Testing Permission Validation...")
    
    test_cases = [
        ("U123456", "hello", "Regular user accessing basic command"),
        ("U123456", "restart service", "Regular user accessing restricted command"),
        ("U789012", "restart service", "DevOps user accessing service command"),
        ("U789012", "delete user", "DevOps user accessing admin command"),
        ("U345678", "delete user", "Admin user accessing admin command"),
        ("U999999", "hello", "Non-existent user"),
    ]
    
    for user_id, command, description in test_cases:
        result = permission_manager.validate_request(user_id=user_id, command=command)
        status = "✅ GRANTED" if result.success else "❌ DENIED"
        print(f"   {status} - {description}")
        if not result.success:
            print(f"      Reason: {result.error_message}")
    
    # Show user capabilities
    print("\n5. User Command Access...")
    
    users_to_check = ["U123456", "U789012", "U345678"]
    for user_id in users_to_check:
        try:
            user = permission_manager.user_manager.get_user(user_id)
            commands = permission_manager.get_user_commands(user_id)
            command_names = [cmd.name for cmd in commands]
            
            print(f"   👤 {user.display_name} ({user.username}):")
            print(f"      Permissions: {list(user.permissions)}")
            print(f"      Available Commands: {command_names}")
            print(f"      Is Admin: {user.is_admin}")
            
        except Exception as e:
            print(f"   ❌ Error checking user {user_id}: {e}")
    
    # Display system statistics
    print("\n6. System Statistics...")
    stats = permission_manager.get_stats()
    
    print(f"   📊 Validation Stats:")
    print(f"      Total Validations: {stats['validation_stats']['total_validations']}")
    print(f"      Grants: {stats['validation_stats']['permission_grants']}")
    print(f"      Denials: {stats['validation_stats']['permission_denials']}")
    print(f"      Grant Rate: {stats['validation_stats']['grant_rate']:.2%}")
    
    print(f"   📋 Command Stats:")
    print(f"      Total Commands: {stats['command_stats']['total_commands']}")
    print(f"      Categories: {stats['command_stats']['total_categories']}")
    print(f"      Permissions: {stats['command_stats']['total_permissions']}")
    
    print(f"   👥 User Stats:")
    print(f"      Total Users: {stats['user_stats']['total_users']}")
    print(f"      Active Users: {stats['user_stats']['active_users']}")
    print(f"      Admin Users: {stats['user_stats']['admin_users']}")
    
    print("\n✨ Basic usage demonstration complete!")


def slack_bot_example():
    """Example of integrating with a Slack bot."""
    
    print("\n🤖 Slack Bot Integration Example")
    print("=" * 40)
    
    # Initialize Slack app (requires SLACK_BOT_TOKEN environment variable)
    if not os.getenv("SLACK_BOT_TOKEN"):
        print("⚠️  SLACK_BOT_TOKEN not set - skipping Slack integration example")
        return
    
    app = App(token=os.environ.get("SLACK_BOT_TOKEN"))
    
    # Initialize permission system
    permission_manager = PermissionManager()
    
    # Register commands
    permission_manager.register_command(
        name="deploy",
        permission="deployment",
        description="Deploy application to environment",
        category="DevOps"
    )
    
    # Create users (in practice, these would be synced from Slack)
    permission_manager.create_user(
        user_id="U123456",
        username="developer",
        permissions=["deployment"]
    )
    
    @app.message("deploy")
    def handle_deploy(message, say, client):
        """Handle deploy command with permission checking."""
        user_id = message["user"]
        
        # Validate permissions
        result = permission_manager.validate_request(
            user_id=user_id,
            command="deploy",
            client=client,
            channel_id=message["channel"]
        )
        
        if not result.success:
            # Error message already sent by permission system
            return
        
        # Execute the actual command
        say(f"🚀 Deploying application... (authorized by <@{user_id}>)")
        
        # Your deployment logic here
        # deploy_application()
        
        say("✅ Deployment completed successfully!")
    
    print("   ✅ Slack bot handlers configured with permission checking")
    print("   💡 Use @require_permission decorator for cleaner code:")
    print("""
    @app.message("deploy")
    @require_permission("deployment")
    def handle_deploy(message, say):
        say("🚀 Deploying...")
    """)


def advanced_features_example():
    """Demonstrate advanced features."""
    
    print("\n🔧 Advanced Features Example")
    print("=" * 35)
    
    # Initialize with custom configuration
    permission_manager = PermissionManager(
        enable_caching=True,
        default_deny=True
    )
    
    # Group-based permissions
    print("\n   👥 Group-based Permissions:")
    
    # Create groups with permissions
    permission_manager.user_manager.create_group(
        "senior-devs", 
        ["code_review", "deployment", "database_access"]
    )
    permission_manager.user_manager.create_group(
        "junior-devs",
        ["code_review"]
    )
    
    # Create user and add to group
    user = permission_manager.create_user(
        user_id="U111111",
        username="senior.dev",
        groups=["senior-devs"]
    )
    
    # Check effective permissions (direct + group)
    effective_perms = permission_manager.user_manager.get_user_effective_permissions("U111111")
    print(f"      User effective permissions: {list(effective_perms)}")
    
    # Audit user permissions
    print("\n   🔍 Permission Auditing:")
    audit_report = permission_manager.access_control.audit_user_permissions("U111111")
    print(f"      Audit report generated for user: {audit_report['user_id']}")
    print(f"      Direct permissions: {audit_report['direct_permissions']}")
    print(f"      Group permissions: {audit_report['effective_permissions']}")
    
    # Security policies
    print("\n   🔒 Security Policies:")
    policies = permission_manager.access_control.get_security_policies()
    print(f"      Active policies: {list(policies.keys())}")
    
    # Update a policy
    permission_manager.access_control.update_security_policy("require_active_user", True)
    print("      ✅ Updated security policy")
    
    print("\n   ✨ Advanced features demonstration complete!")


if __name__ == "__main__":
    main()
    slack_bot_example()
    advanced_features_example()
