#!/usr/bin/env python3
"""
Command Line Interface for Slack Permission System.

This module provides a CLI for managing permissions, users, and commands
without requiring a full Slack bot setup.
"""

import argparse
import json
import sys
import logging
from typing import Dict, Any, List
from pathlib import Path

from . import PermissionManager, __version__
from .utils.exceptions import SlackPermissionSystemError


def setup_logging(level: str = "INFO"):
    """Setup logging configuration."""
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )


def create_permission_manager() -> PermissionManager:
    """Create and return a permission manager instance."""
    return PermissionManager()


def command_register_command(args, manager: PermissionManager):
    """Register a new command."""
    try:
        cmd = manager.register_command(
            name=args.name,
            permission=args.permission,
            description=args.description,
            category=args.category or "General",
            examples=args.examples or [],
            admin_only=args.admin_only
        )
        print(f"✅ Command '{cmd.name}' registered successfully")
        print(f"   Permission: {cmd.permission}")
        print(f"   Category: {cmd.category}")
        
    except Exception as e:
        print(f"❌ Failed to register command: {e}")
        sys.exit(1)


def command_list_commands(args, manager: PermissionManager):
    """List all registered commands."""
    try:
        commands = manager.command_registry.get_all_commands(include_hidden=args.include_hidden)
        
        if not commands:
            print("No commands registered")
            return
        
        print(f"📋 Registered Commands ({len(commands)} total):")
        print()
        
        # Group by category
        by_category = {}
        for cmd in commands:
            if cmd.category not in by_category:
                by_category[cmd.category] = []
            by_category[cmd.category].append(cmd)
        
        for category, cmds in sorted(by_category.items()):
            print(f"📁 {category}:")
            for cmd in sorted(cmds, key=lambda x: x.name):
                admin_flag = " [ADMIN]" if cmd.admin_only else ""
                hidden_flag = " [HIDDEN]" if cmd.hidden else ""
                print(f"   • {cmd.name}{admin_flag}{hidden_flag}")
                print(f"     Permission: {cmd.permission}")
                print(f"     Description: {cmd.description}")
                if cmd.examples:
                    print(f"     Examples: {', '.join(cmd.examples)}")
                print()
        
    except Exception as e:
        print(f"❌ Failed to list commands: {e}")
        sys.exit(1)


def command_create_user(args, manager: PermissionManager):
    """Create a new user."""
    try:
        user = manager.create_user(
            user_id=args.user_id,
            username=args.username,
            email=args.email,
            display_name=args.display_name,
            permissions=args.permissions or [],
            groups=args.groups or [],
            is_admin=args.admin
        )
        
        print(f"✅ User '{user.username}' created successfully")
        print(f"   User ID: {user.user_id}")
        print(f"   Email: {user.email}")
        print(f"   Permissions: {list(user.permissions)}")
        print(f"   Groups: {list(user.groups)}")
        print(f"   Admin: {user.is_admin}")
        
    except Exception as e:
        print(f"❌ Failed to create user: {e}")
        sys.exit(1)


def command_list_users(args, manager: PermissionManager):
    """List all users."""
    try:
        users = manager.user_manager.get_all_users(active_only=not args.include_inactive)
        
        if not users:
            print("No users found")
            return
        
        print(f"👥 Users ({len(users)} total):")
        print()
        
        for user in sorted(users, key=lambda x: x.username or x.user_id):
            status = "✅ Active" if user.is_active else "❌ Inactive"
            admin_flag = " 👑 ADMIN" if user.is_admin else ""
            
            print(f"• {user.username or user.user_id}{admin_flag}")
            print(f"  Status: {status}")
            print(f"  User ID: {user.user_id}")
            if user.email:
                print(f"  Email: {user.email}")
            print(f"  Permissions: {list(user.permissions)}")
            print(f"  Groups: {list(user.groups)}")
            print()
        
    except Exception as e:
        print(f"❌ Failed to list users: {e}")
        sys.exit(1)


def command_check_permission(args, manager: PermissionManager):
    """Check if a user has permission for a command."""
    try:
        result = manager.validate_request(
            user_id=args.user_id,
            command=args.command
        )
        
        if result.success:
            print(f"✅ Permission GRANTED")
            print(f"   User: {args.user_id}")
            print(f"   Command: {result.command}")
            print(f"   Required Permission: {result.permission}")
        else:
            print(f"❌ Permission DENIED")
            print(f"   User: {args.user_id}")
            print(f"   Command: {args.command}")
            print(f"   Reason: {result.error_message}")
            print(f"   Error Code: {result.error_code}")
        
    except Exception as e:
        print(f"❌ Failed to check permission: {e}")
        sys.exit(1)


def command_user_commands(args, manager: PermissionManager):
    """List commands available to a user."""
    try:
        commands = manager.get_user_commands(
            user_id=args.user_id,
            category=args.category,
            include_hidden=args.include_hidden
        )
        
        if not commands:
            print(f"No commands available to user {args.user_id}")
            return
        
        print(f"🔑 Commands available to user {args.user_id} ({len(commands)} total):")
        print()
        
        # Group by category
        by_category = {}
        for cmd in commands:
            if cmd.category not in by_category:
                by_category[cmd.category] = []
            by_category[cmd.category].append(cmd)
        
        for category, cmds in sorted(by_category.items()):
            print(f"📁 {category}:")
            for cmd in sorted(cmds, key=lambda x: x.name):
                print(f"   • {cmd.name}")
                print(f"     {cmd.description}")
                if cmd.examples:
                    print(f"     Examples: {', '.join(cmd.examples)}")
                print()
        
    except Exception as e:
        print(f"❌ Failed to get user commands: {e}")
        sys.exit(1)


def command_stats(args, manager: PermissionManager):
    """Show system statistics."""
    try:
        stats = manager.get_stats()
        
        print("📊 System Statistics:")
        print()
        
        # Validation stats
        val_stats = stats["validation_stats"]
        print("🔍 Validation Statistics:")
        print(f"   Total Validations: {val_stats['total_validations']}")
        print(f"   Permissions Granted: {val_stats['permission_grants']}")
        print(f"   Permissions Denied: {val_stats['permission_denials']}")
        print(f"   Grant Rate: {val_stats['grant_rate']:.2%}")
        print()
        
        # Command stats
        cmd_stats = stats["command_stats"]
        print("📋 Command Statistics:")
        print(f"   Total Commands: {cmd_stats['total_commands']}")
        print(f"   Categories: {cmd_stats['total_categories']}")
        print(f"   Unique Permissions: {cmd_stats['total_permissions']}")
        print(f"   Hidden Commands: {cmd_stats['hidden_commands']}")
        print(f"   Admin Commands: {cmd_stats['admin_commands']}")
        print()
        
        # User stats
        user_stats = stats["user_stats"]
        print("👥 User Statistics:")
        print(f"   Total Users: {user_stats['total_users']}")
        print(f"   Active Users: {user_stats['active_users']}")
        print(f"   Admin Users: {user_stats['admin_users']}")
        print(f"   Total Groups: {user_stats['total_groups']}")
        print()
        
        # Access control stats
        if "access_control_stats" in stats:
            ac_stats = stats["access_control_stats"]
            print("🔒 Access Control Statistics:")
            perm_checks = ac_stats["permission_checks"]
            print(f"   Permission Checks: {perm_checks['total']}")
            print(f"   Grants: {perm_checks['grants']}")
            print(f"   Denials: {perm_checks['denials']}")
            print(f"   Grant Rate: {perm_checks['grant_rate']:.2%}")
            
            if "cache" in ac_stats:
                cache_stats = ac_stats["cache"]
                print(f"   Cache Hit Rate: {cache_stats['hit_rate']:.2%}")
                print(f"   Cache Size: {cache_stats['cache_size']}")
        
    except Exception as e:
        print(f"❌ Failed to get statistics: {e}")
        sys.exit(1)


def command_export(args, manager: PermissionManager):
    """Export system configuration to JSON."""
    try:
        # Export commands
        commands = []
        for cmd in manager.command_registry.get_all_commands(include_hidden=True):
            commands.append({
                "name": cmd.name,
                "permission": cmd.permission,
                "description": cmd.description,
                "category": cmd.category,
                "examples": cmd.examples,
                "parameters": cmd.parameters,
                "admin_only": cmd.admin_only,
                "hidden": cmd.hidden
            })
        
        # Export users
        users = []
        for user in manager.user_manager.get_all_users(active_only=False):
            users.append(user.to_dict())
        
        # Create export data
        export_data = {
            "version": __version__,
            "export_timestamp": manager.get_stats()["validation_stats"].get("timestamp"),
            "commands": commands,
            "users": users,
            "stats": manager.get_stats()
        }
        
        # Write to file
        output_file = Path(args.output)
        with open(output_file, 'w') as f:
            json.dump(export_data, f, indent=2, default=str)
        
        print(f"✅ System configuration exported to {output_file}")
        print(f"   Commands: {len(commands)}")
        print(f"   Users: {len(users)}")
        
    except Exception as e:
        print(f"❌ Failed to export configuration: {e}")
        sys.exit(1)


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Slack Permission System CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Register a command
  slack-permissions register-command --name "deploy app" --permission "deployment" --description "Deploy application"
  
  # Create a user
  slack-permissions create-user --user-id U123456 --username john.doe --permissions deployment code_review
  
  # Check permission
  slack-permissions check-permission --user-id U123456 --command "deploy app"
  
  # List user's available commands
  slack-permissions user-commands --user-id U123456
  
  # Show system statistics
  slack-permissions stats
        """
    )
    
    parser.add_argument("--version", action="version", version=f"slack-permission-system {__version__}")
    parser.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO",
                       help="Set logging level")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Register command
    register_parser = subparsers.add_parser("register-command", help="Register a new command")
    register_parser.add_argument("--name", required=True, help="Command name")
    register_parser.add_argument("--permission", required=True, help="Required permission")
    register_parser.add_argument("--description", required=True, help="Command description")
    register_parser.add_argument("--category", help="Command category")
    register_parser.add_argument("--examples", nargs="*", help="Usage examples")
    register_parser.add_argument("--admin-only", action="store_true", help="Admin-only command")
    
    # List commands
    list_cmd_parser = subparsers.add_parser("list-commands", help="List all commands")
    list_cmd_parser.add_argument("--include-hidden", action="store_true", help="Include hidden commands")
    
    # Create user
    create_user_parser = subparsers.add_parser("create-user", help="Create a new user")
    create_user_parser.add_argument("--user-id", required=True, help="User ID")
    create_user_parser.add_argument("--username", help="Username")
    create_user_parser.add_argument("--email", help="Email address")
    create_user_parser.add_argument("--display-name", help="Display name")
    create_user_parser.add_argument("--permissions", nargs="*", help="User permissions")
    create_user_parser.add_argument("--groups", nargs="*", help="User groups")
    create_user_parser.add_argument("--admin", action="store_true", help="Admin user")
    
    # List users
    list_users_parser = subparsers.add_parser("list-users", help="List all users")
    list_users_parser.add_argument("--include-inactive", action="store_true", help="Include inactive users")
    
    # Check permission
    check_perm_parser = subparsers.add_parser("check-permission", help="Check user permission")
    check_perm_parser.add_argument("--user-id", required=True, help="User ID")
    check_perm_parser.add_argument("--command", required=True, help="Command to check")
    
    # User commands
    user_cmd_parser = subparsers.add_parser("user-commands", help="List user's available commands")
    user_cmd_parser.add_argument("--user-id", required=True, help="User ID")
    user_cmd_parser.add_argument("--category", help="Filter by category")
    user_cmd_parser.add_argument("--include-hidden", action="store_true", help="Include hidden commands")
    
    # Statistics
    subparsers.add_parser("stats", help="Show system statistics")
    
    # Export
    export_parser = subparsers.add_parser("export", help="Export system configuration")
    export_parser.add_argument("--output", default="permission_system_export.json", help="Output file")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Create permission manager
    try:
        manager = create_permission_manager()
    except Exception as e:
        print(f"❌ Failed to initialize permission system: {e}")
        sys.exit(1)
    
    # Execute command
    command_map = {
        "register-command": command_register_command,
        "list-commands": command_list_commands,
        "create-user": command_create_user,
        "list-users": command_list_users,
        "check-permission": command_check_permission,
        "user-commands": command_user_commands,
        "stats": command_stats,
        "export": command_export,
    }
    
    if args.command in command_map:
        command_map[args.command](args, manager)
    else:
        print(f"❌ Unknown command: {args.command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
