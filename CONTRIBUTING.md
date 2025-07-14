# Contributing to Slackbot Permissions

Thank you for your interest in contributing to the Slackbot Permissions project! This guide will help you get started with development and understand our contribution process.

## 🚀 Quick Start

### Prerequisites

- Python 3.8 or higher
- Git
- A Slack workspace for testing (optional but recommended)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/YOUR_USERNAME/slackbot-permissions.git
   cd slackbot-permissions
   ```

2. **Create Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Development Dependencies**
   ```bash
   pip install -e ".[dev]"
   ```

4. **Verify Installation**
   ```bash
   pytest --version
   black --version
   flake8 --version
   mypy --version
   ```

## 🛠️ Development Workflow

### 1. Create a Feature Branch
```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/issue-description
```

### 2. Make Your Changes
- Write clean, readable code
- Follow existing code style and patterns
- Add tests for new functionality
- Update documentation as needed

### 3. Run Tests and Checks
```bash
# Run all tests
pytest

# Run tests with coverage
pytest --cov=slack_permissions --cov-report=html

# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/slack_permissions
```

### 4. Commit Your Changes
```bash
git add .
git commit -m "feat: add new permission validation feature

- Add support for time-based permissions
- Include comprehensive tests
- Update documentation"
```

### 5. Push and Create Pull Request
```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

## 📝 Code Style Guidelines

### Python Style
- Follow [PEP 8](https://pep8.org/)
- Use [Black](https://black.readthedocs.io/) for code formatting
- Maximum line length: 88 characters (Black default)
- Use type hints for all function parameters and return values

### Code Organization
```python
# Good: Clear imports and organization
from typing import Dict, List, Optional
from slack_permissions.core.permission_manager import PermissionManager
from slack_permissions.utils.exceptions import PermissionError

class MyClass:
    """Clear docstring explaining the class purpose."""
    
    def __init__(self, config: Dict[str, str]) -> None:
        self.config = config
    
    def process_request(self, user_id: str) -> Optional[Dict[str, str]]:
        """Process user request with proper error handling."""
        try:
            return self._validate_and_process(user_id)
        except PermissionError as e:
            logger.error(f"Permission error for user {user_id}: {e}")
            return None
```

### Documentation
- Use clear, descriptive docstrings
- Include type information in docstrings
- Provide examples for complex functions
- Update README.md for significant changes

## 🧪 Testing Guidelines

### Test Structure
```
tests/
├── conftest.py              # Shared fixtures
├── test_permission_manager.py
├── test_integration.py
└── unit/
    ├── test_user_manager.py
    └── test_validators.py
```

### Writing Tests
```python
import pytest
from slack_permissions import PermissionManager
from slack_permissions.utils.exceptions import PermissionError

class TestPermissionManager:
    """Test suite for PermissionManager."""
    
    def test_grant_permission_success(self, permission_manager):
        """Test successful permission grant."""
        result = permission_manager.grant_permission("U123", "deploy")
        assert result is True
        assert permission_manager.check_permission("U123", "deploy")
    
    def test_invalid_permission_raises_error(self, permission_manager):
        """Test that invalid permissions raise appropriate errors."""
        with pytest.raises(PermissionError):
            permission_manager.grant_permission("U123", "")
```

### Test Coverage
- Aim for 90%+ test coverage
- Test both success and failure cases
- Include edge cases and error conditions
- Mock external dependencies (Slack API calls)

## 🐛 Bug Reports

When reporting bugs, please include:

1. **Environment Information**
   - Python version
   - Package version
   - Operating system

2. **Steps to Reproduce**
   ```
   1. Initialize PermissionManager with config X
   2. Call method Y with parameters Z
   3. Observe error/unexpected behavior
   ```

3. **Expected vs Actual Behavior**
   - What you expected to happen
   - What actually happened

4. **Code Sample**
   ```python
   # Minimal code that reproduces the issue
   from slack_permissions import PermissionManager
   
   manager = PermissionManager()
   # ... rest of reproduction code
   ```

## 💡 Feature Requests

For new features, please:

1. **Check existing issues** to avoid duplicates
2. **Describe the use case** - why is this needed?
3. **Propose an API** - how should it work?
4. **Consider backwards compatibility**

Example:
```markdown
## Feature: Time-based Permissions

### Use Case
Need to grant temporary permissions that automatically expire.

### Proposed API
```python
manager.grant_permission(
    user_id="U123",
    permission="deploy",
    expires_at=datetime.now() + timedelta(hours=2)
)
```

### Implementation Notes
- Should integrate with existing permission checking
- Needs background cleanup of expired permissions
```

## 🔄 Pull Request Process

### Before Submitting
- [ ] Tests pass locally
- [ ] Code is formatted with Black
- [ ] No linting errors
- [ ] Type checking passes
- [ ] Documentation updated if needed
- [ ] CHANGELOG.md updated (if applicable)

### PR Description Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No breaking changes (or clearly documented)
```

### Review Process
1. Automated checks must pass (CI/CD)
2. At least one maintainer review required
3. Address feedback and update PR
4. Maintainer will merge when approved

## 🏗️ Project Structure

```
slackbot-permissions/
├── src/slack_permissions/          # Main package
│   ├── core/                      # Core functionality
│   ├── integrations/              # External integrations
│   └── utils/                     # Utilities and helpers
├── tests/                         # Test suite
├── docs/                          # Documentation
├── examples/                      # Usage examples
├── scripts/                       # Development scripts
└── .github/workflows/             # CI/CD workflows
```

## 🎯 Development Focus Areas

We're particularly interested in contributions for:

- **Performance improvements** - Caching, optimization
- **New integrations** - Other chat platforms, identity providers
- **Security enhancements** - Additional validation, audit features
- **Documentation** - Examples, tutorials, API docs
- **Testing** - Edge cases, integration scenarios

## 📞 Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Code Review**: Tag maintainers in PRs for review

## 🏆 Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes for significant contributions
- Invited to join the maintainer team for sustained contributions

## 📜 Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold this code.

---

Thank you for contributing to Slackbot Permissions! 🎉
