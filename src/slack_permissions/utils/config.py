"""
Configuration utilities for secure environment variable handling.

This module provides utilities for loading and validating configuration
from environment variables while following security best practices.
"""

import os
import re
from typing import Dict, Any, Optional, List
from ..utils.exceptions import ConfigurationError


class ConfigValidator:
    """Validates configuration values and ensures security best practices."""
    
    # Patterns for sensitive data that should never be logged
    SENSITIVE_PATTERNS = [
        r'token',
        r'secret',
        r'password',
        r'key',
        r'auth',
        r'credential'
    ]
    
    # Required environment variables for Slack integration
    REQUIRED_SLACK_VARS = [
        'SLACK_BOT_TOKEN',
        'SLACK_SIGNING_SECRET'
    ]
    
    @classmethod
    def validate_slack_token(cls, token: str) -> bool:
        """Validate Slack bot token format."""
        if not token:
            return False
        return token.startswith('xoxb-') and len(token) > 20
    
    @classmethod
    def validate_slack_secret(cls, secret: str) -> bool:
        """Validate Slack signing secret format."""
        if not secret:
            return False
        return len(secret) >= 32  # Slack secrets are typically 32+ chars
    
    @classmethod
    def is_sensitive_key(cls, key: str) -> bool:
        """Check if a configuration key contains sensitive data."""
        key_lower = key.lower()
        return any(re.search(pattern, key_lower) for pattern in cls.SENSITIVE_PATTERNS)
    
    @classmethod
    def mask_sensitive_value(cls, key: str, value: str) -> str:
        """Mask sensitive values for logging."""
        if not value:
            return value
        
        if cls.is_sensitive_key(key):
            if len(value) <= 8:
                return '*' * len(value)
            return value[:4] + '*' * (len(value) - 8) + value[-4:]
        
        return value
    
    @classmethod
    def validate_config(cls, config: Dict[str, Any]) -> List[str]:
        """
        Validate configuration and return list of errors.
        
        Args:
            config: Configuration dictionary
            
        Returns:
            List of validation error messages
        """
        errors = []
        
        # Check required Slack variables
        for var in cls.REQUIRED_SLACK_VARS:
            if var not in config or not config[var]:
                errors.append(f"Required environment variable {var} is not set")
                continue
            
            # Validate token format
            if var == 'SLACK_BOT_TOKEN':
                if not cls.validate_slack_token(config[var]):
                    errors.append(f"{var} must start with 'xoxb-' and be valid format")
            
            # Validate secret format
            elif var == 'SLACK_SIGNING_SECRET':
                if not cls.validate_slack_secret(config[var]):
                    errors.append(f"{var} must be at least 32 characters long")
        
        return errors


def load_config() -> Dict[str, str]:
    """
    Load configuration from environment variables.
    
    Returns:
        Dictionary of configuration values
    """
    config = {}
    
    # Load all environment variables
    for key, value in os.environ.items():
        if key.startswith(('SLACK_', 'PACKAGE_', 'DATABASE_', 'LOG_', 'DEBUG', 'METRICS_', 'RATE_LIMIT_')):
            config[key] = value
    
    return config


def get_config_value(key: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """
    Get a configuration value from environment variables.
    
    Args:
        key: Environment variable name
        default: Default value if not found
        required: Whether the value is required
        
    Returns:
        Configuration value or default
        
    Raises:
        ConfigurationError: If required value is missing
    """
    value = os.getenv(key, default)
    
    if required and not value:
        raise ConfigurationError(f"Required configuration value {key} is not set")
    
    return value


def validate_config() -> None:
    """
    Validate current configuration.
    
    Raises:
        ConfigurationError: If configuration is invalid
    """
    config = load_config()
    errors = ConfigValidator.validate_config(config)
    
    if errors:
        error_msg = "Configuration validation failed:\n" + "\n".join(f"  - {error}" for error in errors)
        raise ConfigurationError(error_msg)


def get_safe_config_for_logging() -> Dict[str, str]:
    """
    Get configuration with sensitive values masked for safe logging.
    
    Returns:
        Dictionary with sensitive values masked
    """
    config = load_config()
    safe_config = {}
    
    for key, value in config.items():
        safe_config[key] = ConfigValidator.mask_sensitive_value(key, value)
    
    return safe_config


def is_development_mode() -> bool:
    """Check if running in development mode."""
    return get_config_value('DEBUG', 'false').lower() in ('true', '1', 'yes', 'on')


def get_log_level() -> str:
    """Get configured log level."""
    return get_config_value('LOG_LEVEL', 'INFO').upper()


def get_database_url() -> str:
    """Get database URL with fallback to in-memory SQLite."""
    return get_config_value('DATABASE_URL', 'sqlite:///:memory:')


# Configuration constants with secure defaults
DEFAULT_CONFIG = {
    'LOG_LEVEL': 'INFO',
    'DEBUG': 'false',
    'RATE_LIMIT_ENABLED': 'true',
    'RATE_LIMIT_REQUESTS': '100',
    'RATE_LIMIT_WINDOW': '3600',
    'METRICS_ENABLED': 'true',
    'METRICS_PORT': '8080',
    'DATABASE_URL': 'sqlite:///:memory:',
    'PACKAGE_AUTHOR': 'Slackbot Permissions Contributors',
    'PACKAGE_AUTHOR_EMAIL': 'contributors@example.com',
    'PACKAGE_URL': 'https://github.com/your-org/slackbot-permissions',
}
