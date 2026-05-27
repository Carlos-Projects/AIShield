# Development

## Setup

```bash
git clone https://github.com/Carlos-Projects/AIShield.git
cd AIShield
pip install -e ".[dev]"
```

## Commands

```bash
make test       # Run 212 tests
make lint       # ruff check (0 errors)
make typecheck  # mypy check (0 errors)
make coverage   # test + coverage report
make check      # all checks
make build      # build package
make docker     # build Docker image
```

## Project Standards

- Python 3.11+
- ruff for linting (0 errors required)
- mypy for type checking (0 errors required)
- pytest for testing (all tests must pass)
- 89%+ test coverage

## CI/CD

Three GitHub Actions workflows:

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| CI | push/PR | Lint + test (3 Python versions) |
| CodeQL | push/PR/schedule | Security vulnerability scanning |
| OpenSSF Scorecard | push/schedule | Supply chain security posture |
| Publish | release | Build and publish to PyPI |

## Docker

```bash
make docker
docker run aishield:latest scan /mnt/model/
```
