# Contributing to Behaviour-Based Adaptive Authentication System

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## Code of Conduct

- Be respectful and inclusive
- Focus on security-first principles
- Test all changes thoroughly
- Document your code and changes

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/YOUR-USERNAME/adaptive-authentication-system.git
cd adaptive-authentication-system
```

### 2. Create a Feature Branch

```bash
git checkout -b feature/your-feature-name
```

### 3. Set Up Development Environment

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 4. Make Changes

- Follow PEP 8 style guide
- Add type hints to function signatures
- Write docstrings for all functions
- Add test cases for new features

### 5. Test Your Changes

```bash
# Run existing tests
python tests/auth_failure_demo.py
python tests/simulate_attacks.py
python tests/test_edge_cases.py

# Start the server
.venv\Scripts\python -m uvicorn app.main:app --reload
```

### 6. Commit and Push

```bash
git add .
git commit -m "Add feature: description"
git push origin feature/your-feature-name
```

### 7. Create a Pull Request

- Provide a clear description of changes
- Reference any related issues
- Include security considerations
- Add test results

## Development Best Practices

### Security

- ✅ Always validate user input (Pydantic handles this)
- ✅ Use bcrypt for password hashing (never plain text)
- ✅ Hash tokens with HMAC-SHA256
- ✅ Handle exceptions gracefully without leaking sensitive info
- ✅ Red team: think like an attacker

### Code Quality

- Add meaningful commit messages
- Keep functions small and focused
- Use type hints throughout
- Add logging for debugging
- Document complex logic with comments

### Testing

New features should include tests covering:
- Normal cases (happy path)
- Edge cases
- Error conditions
- Security vulnerabilities

## Project Areas

### High Priority Issues

- Redis failover improvements
- Database connection pooling
- Performance optimizations for high-traffic scenarios

### Documentation

- API usage examples
- Deployment guides (Docker, Kubernetes)
- Security best practices for integrating into systems
- Video tutorials

### Feature Ideas

- TOTP 2FA integration
- Biometric authentication
- Single Sign-On (SSO/OIDC)
- Advanced analytics dashboard
- Machine learning risk scoring

## Reporting Issues

Found a bug or vulnerability?

1. **Security Issues**: Email security@example.com with details (do NOT create public issue)
2. **Bugs**: Create an issue with:
   - Steps to reproduce
   - Expected vs actual behaviour
   - Environment (Python version, OS, etc.)
3. **Feature Requests**: Use issue template with clear use case

## Style Guide

### Python

```python
# Type hints are required
def authenticate_user(
    username: str,
    password: str,
    db: Session
) -> tuple[User | None, str]:
    """Authenticate user credentials.
    
    Args:
        username: User's username
        password: User's plain-text password
        db: Database session
        
    Returns:
        Tuple of (User object, status_string)
    """
    # Implementation
    pass
```

### Naming Conventions

- `_private_function()`: Private functions
- `PascalCase`: Classes
- `snake_case`: Functions, variables, modules
- `UPPER_CASE`: Constants
- `is_active`, `has_expired`: Boolean properties

### Docstrings

Use Google-style docstrings:

```python
def validate_token(token: str) -> dict:
    """Validate and decode a JWT token.
    
    Args:
        token: JWT token string
        
    Returns:
        Decoded token payload as dictionary
        
    Raises:
        JWTError: If token is invalid or expired
    """
```

## Review Process

All PRs require:
1. At least one code review approval
2. All tests passing
3. No security issues
4. Updated documentation if applicable

## Questions?

- Check [README.md](README.md) for detailed documentation
- See [SETUP.md](SETUP.md) for installation help
- Review [TESTING.md](TESTING.md) for testing information

---

**Thank you for contributing to security! 🔐**
