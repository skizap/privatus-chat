# Contributing to Privatus-chat

Thank you for your interest in contributing to Privatus-chat! We welcome contributions from everyone who shares our vision of private, secure communication.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Style Guidelines](#style-guidelines)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Security](#security)
- [Community](#community)

## Code of Conduct

### Our Pledge

We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Examples of positive behavior:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Examples of unacceptable behavior:**
- Trolling, insulting/derogatory comments, and personal attacks
- Public or private harassment
- Publishing others' private information
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Instances of abusive, harassing, or otherwise unacceptable behavior may be reported to the project team at conduct@privatus-chat.org. All complaints will be reviewed and investigated promptly and fairly.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

**Bug Report Template:**
```markdown
**Description**
A clear and concise description of the bug.

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened.

**Screenshots**
If applicable, add screenshots.

**Environment**
- OS: [e.g. Windows 11]
- Version: [e.g. 1.0.0]
- Python version: [e.g. 3.11]

**Additional Context**
Any other relevant information.
```

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

**Feature Request Template:**
```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
A clear description of what you want.

**Describe alternatives you've considered**
Other solutions or features you've considered.

**Additional context**
Any other context or screenshots.
```

### Code Contributions

Areas where we especially welcome contributions:
- 🐛 Bug fixes
- ✨ New features
- 📝 Documentation improvements
- 🌐 Translations
- 🧪 Test coverage
- 🔒 Security enhancements
- ⚡ Performance optimizations

### Documentation

Documentation is crucial! You can help by:
- Improving existing documentation
- Writing tutorials
- Creating examples
- Translating documentation
- Fixing typos and clarifying language

## Getting Started

### Prerequisites

- Python 3.8+
- Git
- GitHub account
- Basic knowledge of Python and Git

### Setting Up Development Environment

1. **Fork the Repository**
   - Go to https://github.com/privatus-chat/privatus-chat
   - Click "Fork" button

2. **Clone Your Fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/privatus-chat.git
   cd privatus-chat
   ```

3. **Add Upstream Remote**
   ```bash
   git remote add upstream https://github.com/privatus-chat/privatus-chat.git
   ```

4. **Create Virtual Environment**
   ```bash
   python -m venv venv
   # On Windows:
   venv\Scripts\activate
   # On Unix/macOS:
   source venv/bin/activate
   ```

5. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

6. **Run Tests**
   ```bash
   pytest
   ```

## Development Process

### 1. Find or Create an Issue

- Check [existing issues](https://github.com/privatus-chat/privatus-chat/issues)
- If none exist, create a new one
- Comment that you're working on it

### 2. Create a Branch

```bash
# Update your fork
git checkout main
git pull upstream main
git push origin main

# Create feature branch
git checkout -b feature/issue-number-description
# Example: git checkout -b feature/123-add-emoji-support
```

### 3. Make Your Changes

- Write clean, readable code
- Add tests for new functionality
- Update documentation
- Ensure all tests pass

### 4. Test Your Changes

```bash
# Run tests
pytest

# Check code style
black src/ tests/
pylint src/

# Type checking
mypy src/

# Security check
bandit -r src/
```

### 5. Commit Your Changes

Follow our commit message conventions (see below).

### 6. Push and Create PR

```bash
git push origin feature/issue-number-description
```

Then create a Pull Request on GitHub.

## Style Guidelines

### Python Style

We follow PEP 8 with these additions:

```python
# Good: Type hints
def encrypt_message(plaintext: str, key: bytes) -> bytes:
    """Encrypt a message using the provided key."""
    pass

# Good: Descriptive names
def validate_public_key(key: str) -> bool:
    """Validate that the key is a valid public key."""
    pass

# Good: Error handling
try:
    result = risky_operation()
except SpecificError as e:
    logger.error(f"Operation failed: {e}")
    raise
```

### Documentation Style

```python
def complex_function(param1: str, param2: int = 10) -> dict:
    """
    Brief description of function.
    
    Longer description if needed, explaining the purpose
    and any important details.
    
    Args:
        param1: Description of param1
        param2: Description of param2 (default: 10)
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: When param1 is invalid
        
    Example:
        >>> result = complex_function("test", 20)
        >>> print(result)
        {'status': 'success'}
    """
```

### Test Style

```python
class TestFeature:
    """Test suite for Feature."""
    
    def test_normal_case(self):
        """Test normal operation."""
        # Arrange
        obj = Feature()
        
        # Act
        result = obj.method()
        
        # Assert
        assert result == expected_value
    
    def test_edge_case(self):
        """Test edge case handling."""
        pass
    
    def test_error_condition(self):
        """Test error conditions."""
        with pytest.raises(ExpectedError):
            Feature().method_that_errors()
```

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation only
- **style**: Code style (formatting, missing semicolons, etc)
- **refactor**: Code change that neither fixes a bug nor adds a feature
- **perf**: Performance improvement
- **test**: Adding missing tests
- **chore**: Changes to build process or auxiliary tools

### Examples

```bash
# Good
git commit -m "feat(crypto): add support for Ed448 keys

- Implement Ed448 key generation
- Add tests for new key type
- Update documentation

Closes #456"

# Good
git commit -m "fix(network): resolve connection timeout issue

The connection timeout was too short for slow networks.
Increased from 5s to 30s.

Fixes #789"

# Bad
git commit -m "fixed stuff"
git commit -m "update"
```

## Pull Request Process

### Before Submitting

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Commit messages follow format
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] No merge conflicts

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass
- [ ] New tests added
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No new warnings

## Related Issues
Closes #XXX
```

### Review Process

1. **Automated Checks**: CI/CD runs tests
2. **Code Review**: At least one maintainer review
3. **Security Review**: For security-related changes
4. **Final Approval**: Maintainer approves and merges

### After Your PR is Merged

- Delete your feature branch
- Update your local main branch
- Celebrate! 🎉

## Security

### Reporting Security Issues

**DO NOT** create public issues for security vulnerabilities. Instead:

1. Email security@privatus-chat.org
2. Include:
   - Description of vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Security Best Practices

When contributing:
- Never commit secrets or credentials
- Always validate user input
- Use cryptographically secure random
- Follow principle of least privilege
- Implement proper error handling

## Community

### Communication Channels

- **GitHub Issues**: Bug reports, feature requests
- **GitHub Discussions**: General questions, ideas
- **IRC**: #privatus-chat on Libera.Chat
- **Matrix**: #privatus-chat:matrix.org
- **Email**: dev@privatus-chat.org

### Getting Help

- Read the [documentation](docs/)
- Search existing issues
- Ask in discussions
- Join our chat channels

### Recognition

Contributors are recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project website
- Annual contributor report

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to Privatus-chat! Together, we're building a more private and secure future for digital communications.** 