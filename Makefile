# Harbour Credentials Makefile
# ============================

.PHONY: setup install install-dev submodule-setup ts-bootstrap generate validate validate-shacl lint format test test-cov test-ts test-interop build-ts lint-ts test-all all clean help

TS_DIR := src/typescript/harbour
OMB_SUBMODULE_DIR := submodules/ontology-management-base

# In CI, use system Python; locally, prefer parent venv then local .venv
ifdef CI
    VENV := $(dir $(shell which python3))..
    PYTHON := python3
else
    ifneq ($(wildcard ../../.venv/bin/python3),)
        VENV := ../../.venv
    else
        VENV := .venv
    endif
    PYTHON := $(VENV)/bin/python3
endif

# Bootstrap interpreter used only to create the venv
BOOTSTRAP_PYTHON := python3

# Tooling inside the selected virtual environment
PIP := $(PYTHON) -m pip
PRECOMMIT := $(PYTHON) -m pre_commit
PYTEST := $(PYTHON) -m pytest

# Check if dev environment is set up (skipped in CI)
define check_dev_setup
	@if [ -z "$$CI" ] && [ ! -x "$(PYTHON)" ]; then \
		echo ""; \
		echo "ERROR: Development environment not set up."; \
		echo ""; \
		echo "Please run first:"; \
		echo "  make setup"; \
		echo ""; \
		exit 1; \
	fi
	@if ! $(PYTHON) -c "import linkml" 2>/dev/null; then \
		echo ""; \
		echo "ERROR: Dev dependencies not installed."; \
		echo ""; \
		echo "Please run:"; \
		echo "  make setup"; \
		echo ""; \
		exit 1; \
	fi
endef

# LinkML schema files
LINKML_SCHEMAS := $(wildcard linkml/*.yaml)
DOMAINS := harbour gaiax-domain
ifdef CI
    GEN_OWL := gen-owl
    GEN_SHACL := gen-shacl
    GEN_JSONLD_CONTEXT := gen-jsonld-context
else
    GEN_OWL := $(VENV)/bin/gen-owl
    GEN_SHACL := $(VENV)/bin/gen-shacl
    GEN_JSONLD_CONTEXT := $(VENV)/bin/gen-jsonld-context
endif

# Default target
help:
	@echo "Harbour Credentials - Available Commands"
	@echo ""
	@echo "Installation:"
	@echo "  make setup        - Create venv, install dev dependencies, setup ontology submodule, and bootstrap TypeScript"
	@echo "  make install      - Install package (user mode)"
	@echo "  make install-dev  - Install with dev dependencies + pre-commit"
	@echo "  make ts-bootstrap - Enable corepack and install TypeScript dependencies"
	@echo ""
	@echo "Artifacts:"
	@echo "  make generate       - Generate OWL/SHACL/context from LinkML"
	@echo "  make validate       - Validate credentials against SHACL shapes"
	@echo "  make validate-shacl - Run SHACL conformance on examples (via ontology-management-base)"
	@echo ""
	@echo "Linting:"
	@echo "  make lint    - Run pre-commit checks (Python)"
	@echo "  make lint-ts - Run TypeScript linting"
	@echo "  make format  - Format Python code with black/isort"
	@echo ""
	@echo "Testing:"
	@echo "  make test         - Run Python pytest suite"
	@echo "  make test-ts      - Run TypeScript vitest suite"
	@echo "  make test-interop - Run cross-runtime interop tests (Python + TypeScript)"
	@echo "  make test-all     - Run Python tests + SHACL conformance + TypeScript tests"
	@echo "  make test-cov     - Run Python tests with coverage report"
	@echo ""
	@echo "TypeScript:"
	@echo "  make build-ts - Build TypeScript package"
	@echo ""
	@echo "Cleaning:"
	@echo "  make clean - Remove build artifacts and caches"

# Create virtual environment and install dependencies
setup:
	@echo "Setting up development environment..."
	@echo "Checking Python virtual environment and dependencies..."
	@set -e; \
	if [ ! -x "$(PYTHON)" ]; then \
		echo "Python virtual environment not found; bootstrapping..."; \
		$(MAKE) --no-print-directory $(VENV)/bin/activate; \
	elif $(PYTHON) -c "import pre_commit, linkml" >/dev/null 2>&1; then \
		echo "OK: Python virtual environment and dependencies are ready at $(VENV)"; \
	else \
		echo "Python virtual environment found but dependencies are missing; bootstrapping..."; \
		$(MAKE) --no-print-directory -B $(VENV)/bin/activate; \
	fi
	@$(MAKE) --no-print-directory submodule-setup
	@$(MAKE) --no-print-directory ts-bootstrap
	@echo ""
	@echo "Setup complete. Activate with: source $(VENV)/bin/activate"

$(VENV)/bin/python3:
	@echo "Creating Python virtual environment at $(VENV)..."
	@$(BOOTSTRAP_PYTHON) -m venv $(VENV)
	@$(PIP) install --upgrade pip
	@echo "OK: Python virtual environment ready"

$(VENV)/bin/activate: $(VENV)/bin/python3
	@echo "Installing Python dependencies..."
	@$(PIP) install -e ".[dev]"
	@$(PIP) install linkml
	@$(PRECOMMIT) install
	@echo "OK: Python development environment ready"

# Setup ontology-management-base submodule using the same active venv
submodule-setup:
	@echo "Setting up ontology-management-base submodule..."
	@set -e; \
	if [ -f "$(OMB_SUBMODULE_DIR)/setup.py" ] || [ -f "$(OMB_SUBMODULE_DIR)/pyproject.toml" ]; then \
		$(PIP) install -e "$(OMB_SUBMODULE_DIR)"; \
		echo "OK: ontology-management-base submodule setup complete"; \
	elif [ -f "$(OMB_SUBMODULE_DIR)/Makefile" ]; then \
		$(MAKE) --no-print-directory -C $(OMB_SUBMODULE_DIR) setup \
			VENV="$(abspath $(VENV))" \
			PYTHON="$(abspath $(PYTHON))" \
			PIP="$(abspath $(PYTHON)) -m pip" \
			PRECOMMIT="$(abspath $(PYTHON)) -m pre_commit" \
			PYTEST="$(abspath $(PYTHON)) -m pytest"; \
		echo "OK: ontology-management-base submodule setup complete"; \
	else \
		echo "WARNING: Skipping ontology-management-base submodule setup (not found)"; \
	fi

# Bootstrap TypeScript toolchain
ts-bootstrap:
	@echo "Bootstrapping TypeScript dependencies..."
	@cd $(TS_DIR) && corepack enable && yarn install
	@echo "OK: TypeScript bootstrap complete"

# Install package (user mode)
install:
	@echo "Installing package in editable mode..."
ifndef CI
	@$(MAKE) --no-print-directory $(VENV)/bin/python3
endif
	@$(PIP) install -e .
	@echo "OK: Package installation complete"

# Install with dev dependencies (works in CI without venv creation)
install-dev:
	@echo "Installing development dependencies..."
ifndef CI
	@$(MAKE) --no-print-directory $(VENV)/bin/python3
endif
	@$(PIP) install -e ".[dev]"
	@$(PIP) install linkml
ifndef CI
	@$(PRECOMMIT) install
endif
	@echo "OK: Development dependencies installed"

# Generate artifacts from LinkML models
generate:
	$(call check_dev_setup)
	@echo "Generating artifacts from LinkML schemas..."
	@for domain in $(DOMAINS); do \
		echo "  Processing $$domain..."; \
		mkdir -p artifacts/$$domain; \
		$(GEN_OWL) linkml/$$domain.yaml > artifacts/$$domain/$$domain.owl.ttl; \
		$(GEN_SHACL) linkml/$$domain.yaml > artifacts/$$domain/$$domain.shacl.ttl; \
		$(GEN_JSONLD_CONTEXT) linkml/$$domain.yaml > artifacts/$$domain/$$domain.context.jsonld; \
	done
	@echo ""
	@echo "OK: Artifacts generated in artifacts/"

# Validate credentials against generated SHACL shapes and JSON-LD syntax
validate:
	$(call check_dev_setup)
	@echo "Validating harbour credentials..."
	@PYTHONPATH=src/python:$$PYTHONPATH $(PYTEST) tests/python/credentials/test_validation.py -v
	@echo "OK: Validation complete"

# Validate example credentials against SHACL shapes via ontology-management-base
validate-shacl:
	$(call check_dev_setup)
	@echo "Running SHACL data conformance check on examples..."
	@cd $(OMB_SUBMODULE_DIR) && \
		tmp_output=$$(mktemp) && \
		$(PYTHON) -m src.tools.validators.validation_suite \
			--run check-data-conformance \
			--data-paths ../../examples/ ../../examples/gaiax/ ../../tests/validation-probe/ontology-loading-probe.json \
			--artifacts ../../artifacts > $$tmp_output 2>&1 ; \
		status=$$? ; \
		cat $$tmp_output ; \
		if [ $$status -ne 0 ]; then \
			rm -f $$tmp_output ; \
			exit $$status ; \
		fi ; \
		for required in \
			"imports/cs/cs.owl.ttl" \
			"imports/cred/cred.owl.ttl" \
			"../../artifacts/harbour/harbour.owl.ttl" \
			"artifacts/gx/gx.owl.ttl" ; do \
			if ! grep -q "$$required" $$tmp_output ; then \
				echo "ERROR: Required ontology not loaded by validation suite: $$required" >&2 ; \
				rm -f $$tmp_output ; \
				exit 1 ; \
			fi ; \
		done ; \
		rm -f $$tmp_output
	@echo "OK: SHACL validation complete"

# Run pre-commit hooks on all files
lint:
	$(call check_dev_setup)
	@echo "Running pre-commit checks..."
	@$(PYTHON) -m pre_commit run --all-files
	@echo "OK: Pre-commit checks complete"

# Auto-format code
format:
	$(call check_dev_setup)
	@echo "Formatting Python code..."
	@$(PYTHON) -m black src/python/ tests/
	@$(PYTHON) -m isort src/python/ tests/
	@echo "OK: Python formatting complete"

# Run tests
test:
	$(call check_dev_setup)
	@echo "Running Python tests..."
	@PYTHONPATH=src/python:$$PYTHONPATH $(PYTEST) tests/ -v
	@echo "OK: Python tests complete"

# Run tests with coverage
test-cov:
	$(call check_dev_setup)
	@echo "Running Python tests with coverage..."
	@PYTHONPATH=src/python:$$PYTHONPATH $(PYTEST) tests/ --cov=src/python/harbour --cov=src/python/credentials --cov-report=html --cov-report=term
	@echo "OK: Coverage run complete"

# TypeScript targets
build-ts:
	@echo "Building TypeScript..."
	@cd $(TS_DIR) && corepack enable && yarn install && yarn build
	@echo "OK: TypeScript build complete"

test-ts:
	@echo "Running TypeScript tests..."
	@cd $(TS_DIR) && corepack enable && yarn test
	@echo "OK: TypeScript tests complete"

lint-ts:
	@echo "Linting TypeScript..."
	@cd $(TS_DIR) && corepack enable && yarn lint
	@echo "OK: TypeScript lint complete"

# Cross-runtime interop tests (requires both Python + TypeScript)
test-interop:
	$(call check_dev_setup)
	@echo "Running cross-runtime interop tests..."
	@PYTHONPATH=src/python:$$PYTHONPATH $(PYTEST) tests/interop/ -v
	@echo "OK: Interop tests complete"

# Compound targets
all:
	@echo "Running default quality pipeline (lint + test)..."
	@$(MAKE) --no-print-directory lint
	@$(MAKE) --no-print-directory test
	@echo "OK: Default quality pipeline complete"

# Run all tests (Python + TypeScript)
test-all:
	@echo "Running all tests (Python + SHACL + TypeScript)..."
	@$(MAKE) --no-print-directory build-ts
	@$(MAKE) --no-print-directory test
	@$(MAKE) --no-print-directory validate-shacl
	@$(MAKE) --no-print-directory test-ts
	@echo "OK: All tests complete"

# Clean generated files
clean:
	@echo "Cleaning generated files and caches..."
	@if [ "$(VENV)" = ".venv" ]; then \
		rm -rf $(VENV); \
		echo "OK: Removed local virtual environment $(VENV)"; \
	else \
		echo "OK: Skipping shared virtual environment $(VENV)"; \
	fi
	@rm -rf build/ dist/ *.egg-info/
	@rm -rf .pytest_cache .coverage htmlcov
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "OK: Cleaned"
