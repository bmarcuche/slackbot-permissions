# Getting Started with Slack Permission System

This guide will help you get up and running with the Slack Permission System quickly.

## Installation

### From PyPI (Recommended)

```bash
pip install slackbot-permissions
```

### From Source

```bash
git clone https://github.com/your-org/slackbot-permissions.git
cd slackbot-permissions
pip install -e .
```

### Development Installation

```bash
git clone https://github.com/your-org/slackbot-permissions.git
cd slackbot-permissions
pip install -e ".[dev]"
```

## Quick Start

### 1. Basic Setup

```python
from slack_permissions import PermissionManager

# Initialize the permission system
permission_manager = PermissionManager()

# Register a command
permission_manager.register_command(
    name="deploy app",
    permission="deployment",
    description="Deploy application to production",
    category="DevOps"
)

# Create a user
permission_manager.create_user(
    user_id="U123456",
    username="john.doe",
    permissions=["deployment"]
)

# Validate permission
result = permission_manager.validate_request(
    user_id="U123456",
    command="deploy app"
)

if result.success:
    print("Permission granted!")
else:
    print(f"Permission denied: {result.error_message}")
```

### 2. Slack Bot Integration

```python
from slack_bolt import App
from slack_permissions import PermissionManager, require_permission

app = App(token="your-slack-bot-token")
permission_manager = PermissionManager()

# Register commands
permission_manager.register_command(
    name="restart service",
    permission="service_management",
    description="Restart a system service"
)

# Create users (typically synced from Slack)
permission_manager.create_user(
    user_id="U123456",
    username="devops.engineer",
    permissions=["service_management"]
)

@app.message("restart service")
def handle_restart_service(message, say, client):
    """Handle service restart with permission checking."""
    user_id = message["user"]
    
    # Validate permissions
    result = permission_manager.validate_request(
        user_id=user_id,
        command="restart service",
        client=client,
        channel_id=message["channel"]
    )
    
    if not result.success:
        # Error message already sent by permission system
        return
    
    # Execute the command
    say("🔄 Restarting service...")
    # Your service restart logic here
    say("✅ Service restarted successfully!")

# Start the app
if __name__ == "__main__":
    app.start(port=int(os.environ.get("PORT", 3000)))
```

### 3. Using Decorators (Cleaner Approach)

```python
from slack_permissions import require_permission, command, set_global_permission_manager

# Set global permission manager
set_global_permission_manager(permission_manager)

@app.message("deploy")
@require_permission("deployment")
def handle_deploy(message, say):
    """Deploy with automatic permission checking."""
    say("🚀 Deploying application...")
    # Your deployment logic here

@app.message("backup database")
@command(
    name="backup database",
    permission="database_admin",
    description="Create database backup",
    admin_only=True
)
def handle_backup(message, say):
    """Auto-registered command with permission checking."""
    say("💾 Creating database backup...")
    # Your backup logic here
```

## Core Concepts

### Commands

Commands represent actions that users can perform. Each command has:

- **Name**: Human-readable command name
- **Permission**: Required permission string
- **Description**: What the command does
- **Category**: Organizational grouping
- **Examples**: Usage examples for help

### Users

Users represent people who can execute commands. Users have:

- **User ID**: Unique identifier (typically Slack user ID)
- **Permissions**: Set of permission strings
- **Groups**: Group memberships for inherited permissions
- **Admin Status**: Whether user bypasses all permission checks

### Permissions

Permissions are simple strings that grant access to commands:

- Use descriptive names: `"deployment"`, `"user_management"`
- Follow consistent naming: `"service_restart"`, `"service_status"`
- Group related permissions: `"database_read"`, `"database_write"`

## Configuration Options

### Permission Manager Options

```python
permission_manager = PermissionManager(
    enable_caching=True,        # Cache permission checks
    default_deny=True,          # Deny by default (fail-safe)
    cache_ttl=300              # Cache TTL in seconds
)
```

### Security Policies

```python
# Update security policies
permission_manager.access_control.update_security_policy(
    "require_active_user", True
)
permission_manager.access_control.update_security_policy(
    "admin_bypass_all", True
)
```

## Environment Variables

The system respects these environment variables:

```bash
# Slack configuration
SLACK_BOT_TOKEN=xoxb-replace-with-your-actual-token
SLACK_SIGNING_SECRET=your-signing-secret

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Cache configuration
PERMISSION_CACHE_TTL=300
ENABLE_PERMISSION_CACHING=true
```

## Best Practices

### 1. Permission Naming

```python
# Good - descriptive and consistent
"user_management"
"deployment_production"
"database_read"
"service_restart"

# Bad - unclear or inconsistent
"admin"
"do_stuff"
"permission1"
```

### 2. User Management

```python
# Create users with minimal required permissions
permission_manager.create_user(
    user_id="U123456",
    username="john.doe",
    permissions=["basic_commands"],  # Start minimal
    groups=["developers"]           # Use groups for common permissions
)

# Use groups for role-based permissions
permission_manager.user_manager.create_group(
    "senior_developers",
    ["deployment_staging", "code_review", "log_access"]
)
```

### 3. Command Registration

```python
# Provide comprehensive command information
permission_manager.register_command(
    name="deploy to staging",
    permission="deployment_staging",
    description="Deploy application to staging environment",
    category="Deployment",
    examples=[
        "deploy to staging",
        "deploy to staging --branch feature-123"
    ],
    parameters=["environment", "branch (optional)"]
)
```

### 4. Error Handling

```python
@app.message("sensitive command")
def handle_sensitive_command(message, say, client):
    try:
        result = permission_manager.validate_request(
            user_id=message["user"],
            command="sensitive command",
            client=client,
            channel_id=message["channel"]
        )
        
        if not result.success:
            # Permission system already sent error message
            return
        
        # Execute command
        execute_sensitive_operation()
        say("✅ Operation completed successfully")
        
    except Exception as e:
        logger.error(f"Command execution failed: {e}")
        say("❌ Operation failed. Please try again or contact support.")
```

## Next Steps

- Read the [API Reference](api-reference.md) for detailed documentation
- Check out [Examples](../examples/) for more usage patterns
- Review [Security Guide](security.md) for production deployment

## Troubleshooting

### Common Issues

**Permission always denied**
- Check user exists: `permission_manager.user_manager.get_user(user_id)`
- Verify user has permission: `user.has_permission("permission_name")`
- Check command exists: `permission_manager.command_registry.get_command("command_name")`

**Commands not found**
- Verify command registration: `permission_manager.command_registry.get_all_commands()`
- Check command name matches exactly
- Ensure regex pattern matching works

**Slack integration issues**
- Verify Slack tokens are correct
- Check bot has necessary scopes
- Ensure user IDs are valid Slack user IDs

### Debug Mode

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Enable detailed logging
logger = logging.getLogger('slack_permissions')
logger.setLevel(logging.DEBUG)
```

### Getting Help

- Review [GitHub Issues](https://github.com/your-org/slackbot-permissions/issues)
- Create an issue for bugs or feature requests

## Next Steps

You now have a working Slack Permission System! Here are some useful resources:

- **[API Reference](api-reference.md)** - Complete API documentation and examples
- **[Security Guide](security.md)** - Production security best practices and checklist

For production deployment, consider:

- Setting up proper logging and monitoring
- Configuring user groups and permissions based on your team structure
- Testing your permission logic thoroughly
- Following the security guidelines in the Security Guide
