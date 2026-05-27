.PHONY: install dev test coverage lint typecheck clean build docker

install:
	pip install -e .

dev:
	pip install -e ".[dev]"

test:
	python -m pytest tests/ -v

coverage:
	python -m pytest tests/ -v --cov --cov-report=term --cov-report=xml

lint:
	ruff check src/ tests/

lint-fix:
	ruff check src/ tests/ --fix

typecheck:
	mypy src/aishield/

check: lint typecheck test

clean:
	rm -rf dist/ build/ *.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -rf .pytest_cache .ruff_cache .mypy_cache
	rm -rf htmlcov coverage.xml

build:
	python -m build

docker:
	docker build -t aishield:latest .
