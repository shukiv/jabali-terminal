.PHONY: test lint typecheck format clean all

all: test lint typecheck

test:
	pytest -v --tb=short

lint:
	ruff check daemon/

typecheck:
	mypy daemon/ --strict

format:
	ruff check --fix daemon/
	black daemon/

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache build dist *.egg-info

help:
	@echo "Available targets:"
	@echo "  test       - Run pytest"
	@echo "  lint       - Run ruff linter"
	@echo "  typecheck  - Run mypy type checker"
	@echo "  format     - Format code with ruff and black"
	@echo "  clean      - Remove build artifacts"
	@echo "  all        - Run test, lint, typecheck"
