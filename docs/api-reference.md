# API Reference

Quick reference for the most commonly used classes and methods in the Slack Permission System.

## Core Classes

### PermissionManager

The main orchestrator for permission management.

```python
from slack_permissions import PermissionManager

manager = PermissionManager()
```

#### Key Methods

**`check_permission(user_id: str, permission: str) -> bool`**
```python
# Check if user has specific permission
has_access = manager.check_permission("U123456", "deploy_app")
```

**`grant_permission(user_id: str, permission: str) -> bool`**
```python
# Grant permission to user
manager.grant_permission("U123456", "deploy_app")
```

**`revoke_permission(user_id: str, permission: str) -> bool`**
```python
# Remove permission from user
manager.revoke_permission("U123456", "deploy_app")
```

**`validate_request(user_id: str, command: str, client=None) -> bool`**
```python
# Complete validation pipeline
is_valid = manager.validate_request(
    user_id="U123456",
    command="deploy_app",
    client=slack_client
)
```

### CommandRegistry

Manages command registration and metadata.

```python
from slack_permissions import CommandRegistry

registry = CommandRegistry()
```

#### Key Methods

**`register_command(name: str, permission: str, description: str, category: str = None)`**
```python
registry.register_command(
    name="deploy_app",
    permission="deployment",
    description="Deploy application to production",
    category="DevOps"
)
```

**`get_available_commands(user_id: str) -> List[Dict]`**
```python
# Get commands user can execute
commands = registry.get_available_commands("U123456")
```

### UserManager

Handles user and group management.

```python
from slack_permissions import UserManager

user_manager = UserManager()
```

#### Key Methods

**`create_user(user_id: str, username: str, email: str = None) -> bool`**
```python
user_manager.create_user(
    user_id="U123456",
    username="john.doe",
    email="john@company.com"
)
```

**`add_user_to_group(user_id: str, group_name: str) -> bool`**
```python
user_manager.add_user_to_group("U123456", "developers")
```

## Decorators

### @require_permission

Decorator for protecting functions with permission checks.

```python
from slack_permissions.utils import require_permission

@require_permission("deploy_app")
def deploy_application(user_id, **kwargs):
    # Function only executes if user has permission
    return "Deployment started"
```

### @command

Register a function as a bot command.

```python
from slack_permissions.utils import command

@command(
    name="status",
    permission="read_status",
    description="Check application status"
)
def check_status(user_id, **kwargs):
    return "Application is running"
```

### @admin_only

Restrict function to admin users only.

```python
from slack_permissions.utils import admin_only

@admin_only
def delete_all_data(user_id, **kwargs):
    # Only admins can execute this
    return "Data deleted"
```

## Exceptions

### SlackPermissionSystemError
Base exception for all permission system errors.

### PermissionError
Raised when permission checks fail.

### ValidationError
Raised when input validation fails.

### ConfigurationError
Raised when system configuration is invalid.

```python
from slack_permissions.utils.exceptions import PermissionError

try:
    manager.check_permission("U123456", "admin_command")
except PermissionError as e:
    print(f"Permission denied: {e}")
```

## Configuration

### Environment Variables

```bash
# Required
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_SIGNING_SECRET=your-signing-secret

# Optional
PERMISSION_CACHE_TTL=300
LOG_LEVEL=INFO
ADMIN_USERS=U123456,U789012
```

### Initialization Options

```python
manager = PermissionManager(
    cache_ttl=300,  # Permission cache time-to-live
    strict_mode=True,  # Fail on validation errors
    admin_bypass=False,  # Disable admin permission bypass
    audit_logging=True  # Enable comprehensive logging
)
```

## Integration Examples

### Slack Bolt Integration

```python
from slack_bolt import App
from slack_permissions import PermissionManager

app = App(token="your-token")
permission_manager = PermissionManager()

@app.command("/deploy")
def handle_deploy(ack, command, client):
    ack()
    
    if not permission_manager.validate_request(
        user_id=command['user_id'],
        command="deploy_app",
        client=client
    ):
        return
    
    # Execute deployment
    client.chat_postMessage(
        channel=command['channel_id'],
        text="Deployment started!"
    )
```

### Flask Integration

```python
from flask import Flask, request
from slack_permissions import PermissionManager

app = Flask(__name__)
permission_manager = PermissionManager()

@app.route('/api/deploy', methods=['POST'])
def deploy():
    user_id = request.json.get('user_id')
    
    if not permission_manager.check_permission(user_id, "deploy_app"):
        return {"error": "Permission denied"}, 403
    
    # Execute deployment
    return {"status": "Deployment started"}
```

## Best Practices

1. **Always validate requests** before executing commands
2. **Use descriptive permission names** like "deploy_production" vs "deploy"
3. **Group related permissions** using consistent naming patterns
4. **Cache permission results** for better performance
5. **Log all permission decisions** for audit trails
6. **Handle exceptions gracefully** without exposing sensitive information

## Performance Considerations

- Permission checks are cached by default (TTL: 5 minutes)
- Bulk operations are optimized for multiple users
- Database queries are minimized through intelligent caching
- Consider using Redis for distributed caching in multi-instance deployments
