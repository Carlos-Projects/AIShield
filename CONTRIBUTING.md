# Contributing to AIShield

👋 **Welcome to AIShield!**

Thank you for contributing to security scanning for the LLM fine-tuning lifecycle. Every detector, test, or documentation improvement you contribute strengthens the safety of the AI supply chain. We're thrilled to have you onboard!

## First Time Contributor?

New to AI security scanning? Great place to start:

- Look for `good first issue` or `help wanted` labels
- Add a new detector — follow the patterns in the existing detectors
- Improve test coverage or add edge cases
- Write documentation or improve existing docs

We believe everyone has something valuable to contribute. Don't hesitate to jump in!

## Need Help?

Questions or stuck on something?

- Open a [GitHub Issue](https://github.com/Carlos-Projects/AIShield/issues)
- Check existing issues for answers
- Share your environment: Python version, OS, and what you tried

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

---

💡 This project is governed by a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its principles.
