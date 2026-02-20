# Harbour Credentials Makefile
# ============================

.PHONY: setup install install-dev generate lint format test test-cov test-ts build-ts test-all all clean help

TS_DIR := src/typescript/harbour

# Use parent venv if it exists, otherwise local venv, otherwise system python
ifneq ($(wildcard ../../.venv/bin/python3),)
    VENV := ../../.venv
    PYTHON := $(VENV)/bin/python3
    PIP := $(VENV)/bin/pip
    PRECOMMIT := $(VENV)/bin/pre-commit
    PYTEST := $(VENV)/bin/pytest
else ifneq ($(wildcard .venv/bin/python3),)
    VENV := .venv
    PYTHON := $(VENV)/bin/python3
    PIP := $(VENV)/bin/pip
    PRECOMMIT := $(VENV)/bin/pre-commit
    PYTEST := $(VENV)/bin/pytest
else
    VENV :=
    PYTHON := python3
    PIP := python3 -m pip
    PRECOMMIT := pre-commit
    PYTEST := pytest
endif

# Check if dev environment is set up
define check_dev_setup
	@if [ -z "$(VENV)" ]; then \
		echo ""; \
		echo "❌ Development environment not set up."; \
		echo ""; \
		echo "Please run first:"; \
		echo "  make setup"; \
		echo ""; \
		exit 1; \
	fi
	@if ! $(PYTHON) -c "import pre_commit" 2>/dev/null; then \
		echo ""; \
		echo "❌ Dev dependencies not installed."; \
		echo ""; \
		echo "Please run:"; \
		echo "  source $(VENV)/bin/activate"; \
		echo "  make install-dev"; \
		echo ""; \
		exit 1; \
	fi
endef

# LinkML schema files
LINKML_SCHEMAS := $(wildcard linkml/*.yaml)
DOMAINS := harbour core

# Default target
help:
	@echo "Harbour Credentials - Available Commands"
	@echo ""
	@echo "Installation:"
	@echo "  make setup       - Create venv and install dev dependencies"
	@echo "  make install     - Install package (user mode)"
	@echo "  make install-dev - Install with dev dependencies + pre-commit"
	@echo ""
	@echo "Artifacts:"
	@echo "  make generate    - Generate OWL/SHACL/context from LinkML"
	@echo ""
	@echo "Linting:"
	@echo "  make lint        - Run pre-commit checks (Python)"
	@echo "  make lint-ts     - Run TypeScript linting"
	@echo "  make format      - Format Python code with black/isort"
	@echo ""
	@echo "Testing:"
	@echo "  make test        - Run Python pytest suite"
	@echo "  make test-ts     - Run TypeScript vitest suite"
	@echo "  make test-all    - Run all tests (Python + TypeScript)"
	@echo "  make test-cov    - Run Python tests with coverage report"
	@echo ""
	@echo "TypeScript:"
	@echo "  make build-ts    - Build TypeScript package"
	@echo ""
	@echo "Cleaning:"
	@echo "  make clean       - Remove build artifacts and caches"
	@echo ""

# Create virtual environment and install dependencies
setup: $(VENV)/bin/activate
$(VENV)/bin/activate:
	@$(PYTHON) -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@$(PIP) install -e ".[dev]"
	@$(PIP) install linkml
	@$(PYTHON) -m pre_commit install
	@echo ""
	@echo "✅ Setup complete. Activate with: source $(VENV)/bin/activate"

# Install package (user mode)
install:
	@$(PIP) install -e .

# Install with dev dependencies
install-dev:
	@$(PIP) install -e ".[dev]"
	@$(PIP) install linkml
	@$(PYTHON) -m pre_commit install

# Generate artifacts from LinkML models
generate:
	$(call check_dev_setup)
	@echo "🔧 Generating artifacts from LinkML schemas..."
	@for domain in $(DOMAINS); do \
		echo "  Processing $$domain..."; \
		mkdir -p artifacts/$$domain; \
		gen-owl linkml/$$domain.yaml > artifacts/$$domain/$$domain.owl.ttl; \
		gen-shacl linkml/$$domain.yaml > artifacts/$$domain/$$domain.shacl.ttl; \
		gen-jsonld-context linkml/$$domain.yaml > artifacts/$$domain/$$domain.context.jsonld; \
	done
	@echo ""
	@echo "✅ Artifacts generated in artifacts/"

# Run pre-commit hooks on all files
lint:
	$(call check_dev_setup)
	@$(PYTHON) -m pre_commit run --all-files

# Auto-format code
format:
	$(call check_dev_setup)
	@$(PYTHON) -m black src/python/ tests/
	@$(PYTHON) -m isort src/python/ tests/

# Run tests
test:
	$(call check_dev_setup)
	@PYTHONPATH=src/python:$$PYTHONPATH $(PYTEST) tests/ -v

# Run tests with coverage
test-cov:
	$(call check_dev_setup)
	@PYTHONPATH=src/python:$$PYTHONPATH $(PYTEST) tests/ --cov=src/python/harbour --cov=src/python/credentials --cov-report=html --cov-report=term

# TypeScript targets
build-ts:
	@echo "🔧 Building TypeScript..."
	@cd $(TS_DIR) && corepack enable && yarn install && yarn build
	@echo "✅ TypeScript build complete"

test-ts:
	@echo "🧪 Running TypeScript tests..."
	@cd $(TS_DIR) && corepack enable && yarn test
	@echo "✅ TypeScript tests complete"

lint-ts:
	@echo "🔍 Linting TypeScript..."
	@cd $(TS_DIR) && corepack enable && yarn lint
	@echo "✅ TypeScript lint complete"

# Compound targets
all: lint test

# Run all tests (Python + TypeScript)
test-all: test test-ts

# Clean generated files
clean:
	@rm -rf $(VENV)
	@rm -rf build/ dist/ *.egg-info/
	@rm -rf .pytest_cache .coverage htmlcov
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "✅ Cleaned"
