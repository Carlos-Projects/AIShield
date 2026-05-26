# Contributing to AIShield

Thank you for contributing to AIShield!

## Development Setup

```bash
git clone https://github.com/Carlos-Projects/AIShield.git
cd AIShield
pip install -e ".[dev]"
```

## Running Tests

```bash
python -m pytest tests/ -v
python -m pytest tests/ -v --cov
```

## Linting

```bash
ruff check .
ruff format --check .
```

## Type Checking

```bash
mypy src/
```

## Code Style

- Follow existing conventions in the codebase
- Type hints on all public functions
- Docstrings with Args/Returns for all public functions
- Line length: 100 characters
- Use `from __future__ import annotations` at top of all files

## Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass and lint is clean
5. Submit a pull request

## Commit Messages

Follow conventional commits:
- `feat:` new feature
- `fix:` bug fix
- `docs:` documentation changes
- `test:` test additions/changes
- `refactor:` code refactoring
- `chore:` maintenance tasks
