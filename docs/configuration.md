# Configuration Guide

This document describes how to configure the slackbot-permissions package for different environments and use cases.

## Environment Variables

The package uses environment variables for configuration to follow security best practices and enable flexible deployment across different environments.

### Package Metadata Configuration

These variables configure package metadata and are primarily used during build and publishing:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `PACKAGE_AUTHOR` | Package author name | "Slackbot Permissions Contributors" | No |
| `PACKAGE_AUTHOR_EMAIL` | Author email address | "contributors@example.com" | No |
| `PACKAGE_URL` | Main repository URL | "https://github.com/your-org/slackbot-permissions" | No |
| `PACKAGE_BUG_REPORTS` | Bug reports URL | "https://github.com/your-org/slackbot-permissions/issues" | No |
| `PACKAGE_SOURCE` | Source code URL | "https://github.com/your-org/slackbot-permissions" | No |
| `PACKAGE_DOCS` | Documentation URL | "https://slackbot-permissions.readthedocs.io/" | No |

### CI/CD Configuration

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `DOCKER_REGISTRY` | Docker registry organization/user | "your-org" | No |

### Runtime Configuration

These variables configure the package behavior during runtime:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SLACK_BOT_TOKEN` | Slack bot token (xoxb-...) | None | Yes* |
| `SLACK_SIGNING_SECRET` | Slack signing secret | None | Yes* |
| `SLACK_APP_TOKEN` | Slack app token (xapp-...) | None | No |
| `DATABASE_URL` | Database connection URL | "sqlite:///:memory:" | No |
| `LOG_LEVEL` | Logging level | "INFO" | No |
| `DEBUG` | Enable debug mode | "false" | No |
| `RATE_LIMIT_ENABLED` | Enable rate limiting | "true" | No |
| `RATE_LIMIT_REQUESTS` | Max requests per window | "100" | No |
| `RATE_LIMIT_WINDOW` | Rate limit window (seconds) | "3600" | No |
| `METRICS_ENABLED` | Enable metrics collection | "true" | No |
| `METRICS_PORT` | Metrics server port | "8080" | No |

*Required when using Slack integration features

## Configuration Files

### .env File

Create a `.env` file in your project root for local development:

```bash
# Copy the example file
cp .env.example .env

# Edit with your values
nano .env
```

### Environment-Specific Configuration

#### Development
```bash
# .env.development
DEBUG=true
LOG_LEVEL=DEBUG
RATE_LIMIT_ENABLED=false
METRICS_ENABLED=true
DATABASE_URL=sqlite:///dev_permissions.db
```

#### Testing
```bash
# .env.test
DEBUG=false
LOG_LEVEL=WARNING
DATABASE_URL=sqlite:///:memory:
RATE_LIMIT_ENABLED=false
METRICS_ENABLED=false
```

#### Production
```bash
# .env.production
DEBUG=false
LOG_LEVEL=INFO
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=50
RATE_LIMIT_WINDOW=3600
METRICS_ENABLED=true
DATABASE_URL=postgresql://user:pass@host:5432/permissions
```

## Security Best Practices

### Secrets Management

1. **Never commit secrets to version control**
   ```bash
   # Add to .gitignore
   .env
   .env.local
   .env.production
   ```

2. **Use environment-specific files**
   ```bash
   .env.example      # Template (safe to commit)
   .env              # Local development (never commit)
   .env.production   # Production secrets (never commit)
   ```

3. **Use secret management services in production**
   - AWS Secrets Manager
   - Azure Key Vault
   - HashiCorp Vault
   - Kubernetes Secrets

### Environment Variable Validation

The package validates environment variables at startup:

```python
from slack_permissions import PermissionManager

# Will validate required environment variables
manager = PermissionManager()
```

### Docker Configuration

#### Using Environment Files
```bash
# Run with environment file
docker run --env-file .env.production your-app

# Docker Compose
services:
  slackbot:
    image: your-app
    env_file:
      - .env.production
```

#### Using Environment Variables
```bash
# Pass individual variables
docker run \
  -e SLACK_BOT_TOKEN=xoxb-... \
  -e SLACK_SIGNING_SECRET=... \
  your-app
```

### Kubernetes Configuration

```yaml
# ConfigMap for non-sensitive config
apiVersion: v1
kind: ConfigMap
metadata:
  name: slackbot-config
data:
  LOG_LEVEL: "INFO"
  DEBUG: "false"
  METRICS_ENABLED: "true"

---
# Secret for sensitive data
apiVersion: v1
kind: Secret
metadata:
  name: slackbot-secrets
type: Opaque
data:
  SLACK_BOT_TOKEN: <base64-encoded-token>
  SLACK_SIGNING_SECRET: <base64-encoded-secret>

---
# Deployment using both
apiVersion: apps/v1
kind: Deployment
metadata:
  name: slackbot
spec:
  template:
    spec:
      containers:
      - name: slackbot
        image: your-org/slackbot-permissions:latest
        envFrom:
        - configMapRef:
            name: slackbot-config
        - secretRef:
            name: slackbot-secrets
```

## Configuration Validation

The package includes built-in configuration validation:

```python
from slack_permissions.utils.config import validate_config

# Validate current configuration
try:
    validate_config()
    print("✅ Configuration is valid")
except ConfigurationError as e:
    print(f"❌ Configuration error: {e}")
```

## Troubleshooting

### Common Configuration Issues

1. **Missing required environment variables**
   ```
   Error: SLACK_BOT_TOKEN is required but not set
   Solution: Set the SLACK_BOT_TOKEN environment variable
   ```

2. **Invalid token format**
   ```
   Error: SLACK_BOT_TOKEN must start with 'xoxb-'
   Solution: Verify your bot token from Slack app settings
   ```

3. **Database connection issues**
   ```
   Error: Could not connect to database
   Solution: Check DATABASE_URL format and connectivity
   ```

### Debug Configuration

Enable debug mode to see configuration details:

```bash
DEBUG=true python your_app.py
```

This will log:
- All loaded environment variables (secrets are masked)
- Configuration validation results
- Database connection status
- Slack API connection status

## Migration Guide

### From Hardcoded Values

If you're migrating from hardcoded configuration values:

1. **Identify hardcoded values**
   ```bash
   grep -r "your-hardcoded-value" src/
   ```

2. **Replace with environment variables**
   ```python
   # Before
   SLACK_TOKEN = "xoxb-example-hardcoded-token"  # DON'T DO THIS
   
   # After
   SLACK_TOKEN = os.getenv("SLACK_BOT_TOKEN")
   ```

3. **Update deployment scripts**
   ```bash
   # Add environment variables to deployment
   export SLACK_BOT_TOKEN="xoxb-replace-with-your-actual-token"
   ```

### Version Compatibility

| Version | Configuration Method | Notes |
|---------|---------------------|-------|
| 1.0.x | Environment variables | Current recommended approach |
| 0.x.x | Hardcoded values | Deprecated, migrate to env vars |

---

For more information, see:
- [Security Guide](security.md)
- [Deployment Guide](deployment.md)
- [API Reference](api-reference.md)
