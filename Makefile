# Harbour Credentials Makefile
# ============================

.PHONY: setup install generate validate lint format test build story all clean help \
	release-artifacts \
	_help_general _help_setup _help_install _help_validate _help_lint _help_format _help_test _help_story _help_build \
	_setup_default _setup_submodules _setup_ts _install_default _install_dev \
	_validate_default _validate_shacl \
	_lint_default _lint_md _lint_ts \
	_format_default _format_md \
	_test_default _test_cov _test_ts _test_interop _test_all \
	_story_default _story_sign _story_verify \
	_build_ts

TS_DIR := src/typescript/harbour
OMB_SUBMODULE_DIR := submodules/ontology-management-base

# Allow callers to override the venv path/tooling.
VENV ?= .venv

# OS detection for cross-platform support (Windows vs Unix)
ifeq ($(OS),Windows_NT)
    ifndef CI
        ifneq ($(wildcard ../../.venv/Scripts/python.exe),)
            VENV := ../../.venv
        endif
    endif
    VENV_BIN := $(VENV)/Scripts
    VENV_PYTHON := $(VENV_BIN)/python.exe
    ifdef CI
        PYTHON ?= python
    else
        PYTHON ?= $(VENV_PYTHON)
    endif
    BOOTSTRAP_PYTHON ?= python
    ACTIVATE_SCRIPT := $(VENV_BIN)/activate
    ACTIVATE_HINT := PowerShell: $(subst /,\,$(VENV_BIN))\Activate.ps1; Git Bash: source $(ACTIVATE_SCRIPT)
    PYTHONPATH_SEP := ;
else
    ifneq ($(wildcard ../../.venv/bin/python3),)
        VENV := ../../.venv
    endif
    VENV_BIN := $(VENV)/bin
    VENV_PYTHON := $(VENV_BIN)/python3
    ifdef CI
        PYTHON ?= python3
    else
        PYTHON ?= $(VENV_PYTHON)
    endif
    BOOTSTRAP_PYTHON ?= python3
    ACTIVATE_SCRIPT := $(VENV_BIN)/activate
    ACTIVATE_HINT := source $(ACTIVATE_SCRIPT)
    PYTHONPATH_SEP := :
endif

# Absolute path to Python (for use after cd into subdirectories).
# In CI, PYTHON is a bare command ('python3') so resolve via PATH;
# locally it is a relative venv path so abspath works.
# When a parent Makefile passes an already-absolute Windows path
# (containing ':'), $(abspath) would mangle it — skip in that case.
ifdef CI
    PYTHON_ABS := $(shell command -v $(PYTHON))
else ifneq ($(findstring :,$(PYTHON)),)
    PYTHON_ABS := $(PYTHON)
else
    PYTHON_ABS := $(abspath $(PYTHON))
endif

# Tooling inside the selected virtual environment
PIP := "$(PYTHON)" -m pip
PRECOMMIT := "$(PYTHON)" -m pre_commit
PYTEST := "$(PYTHON)" -m pytest
YARN := corepack yarn

# Check if dev environment is set up (skipped in CI)
define check_dev_setup
	@if [ -z "$$CI" ] && [ ! -f "$(PYTHON)" ]; then \
		echo ""; \
		echo "ERROR: Development environment not set up."; \
		echo ""; \
		echo "Please run first:"; \
		echo "  make setup"; \
		echo ""; \
		exit 1; \
	fi
	@if ! "$(PYTHON)" -c "import linkml" 2>/dev/null; then \
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
DOMAINS := harbour-core-credential harbour-gx-credential harbour-core-delegation
HARBOUR_EXAMPLE_FILES := $(wildcard examples/*.json) $(wildcard examples/gaiax/*.json)
HARBOUR_VALIDATE_PATH ?=
HARBOUR_VALIDATE_ALLOW_ONLINE ?= 1
HARBOUR_VALIDATE_ENFORCE_REQUIRED_ONTOLOGIES ?= $(if $(strip $(HARBOUR_VALIDATE_PATH)),0,1)
GROUPED_COMMANDS := setup install validate lint format test story build
PRIMARY_GOAL := $(firstword $(MAKECMDGOALS))
SUBCOMMAND_GOALS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))

# Grouped command mode: treat trailing goals as subcommands
ifneq ($(filter $(PRIMARY_GOAL),$(GROUPED_COMMANDS)),)
.PHONY: $(SUBCOMMAND_GOALS)

$(SUBCOMMAND_GOALS):
	@:
else
help:
	@"$(MAKE)" --no-print-directory _help_general
endif

# Default target
_help_general:
	@echo "Harbour Credentials - Available Commands"
	@echo ""
	@echo "Installation:"
	@echo "  make setup        - Create venv, install dev dependencies, setup ontology submodule, and bootstrap TypeScript"
	@echo "  make setup help   - Show setup subcommands"
	@echo "  make install      - Install package (user mode)"
	@echo "  make install help - Show install subcommands"
	@echo ""
	@echo "Artifacts:"
	@echo "  make generate       - Generate OWL/SHACL/context from LinkML"
	@echo "  make validate       - Validate credentials against SHACL shapes"
	@echo "  make validate help  - Show validate subcommands"
	@echo ""
	@echo "Linting:"
	@echo "  make lint         - Run pre-commit checks (Python + Markdown)"
	@echo "  make lint help    - Show lint subcommands"
	@echo "  make format       - Format Python code with ruff"
	@echo "  make format help  - Show format subcommands"
	@echo ""
	@echo "Testing:"
	@echo "  make test         - Run Python pytest suite"
	@echo "  make test help    - Show test subcommands"
	@echo "  make story        - Generate, sign, verify, and SHACL-validate example storylines"
	@echo "  make story help   - Show story subcommands"
	@echo ""
	@echo "TypeScript:"
	@echo "  make build       - Build TypeScript package"
	@echo "  make build help  - Show build subcommands"
	@echo ""
	@echo "Cleaning:"
	@echo "  make clean - Remove build artifacts and caches"

_help_setup:
	@echo "Setup subcommands:"
	@echo "  make setup             - Create venv, install dev dependencies, setup ontology submodule, and bootstrap TypeScript"
	@echo "  make setup submodules  - Setup the ontology-management-base submodule in the active environment"
	@echo "  make setup ts          - Bootstrap TypeScript dependencies"

_help_install:
	@echo "Install subcommands:"
	@echo "  make install      - Install package (user mode)"
	@echo "  make install dev  - Install with dev dependencies + pre-commit"

_help_validate:
	@echo "Validate subcommands:"
	@echo "  make validate        - Run structural validation tests"
	@echo "  make validate shacl  - Run SHACL conformance on examples via OMB"
	@echo "  make validate shacl HARBOUR_VALIDATE_PATH=examples/... - Validate one Harbour .json/.jsonld file or folder"
	@echo "  make validate shacl HARBOUR_VALIDATE_ALLOW_ONLINE=0 - Disable OMB online fallback for did:web/http(s)"

_help_lint:
	@echo "Lint subcommands:"
	@echo "  make lint      - Run pre-commit checks"
	@echo "  make lint md   - Lint Markdown files with markdownlint-cli2"
	@echo "  make lint ts   - Run TypeScript linting"

_help_format:
	@echo "Format subcommands:"
	@echo "  make format      - Format Python code with ruff"
	@echo "  make format md   - Auto-fix Markdown lint violations"

_help_test:
	@echo "Test subcommands:"
	@echo "  make test          - Run Python pytest suite"
	@echo "  make test cov      - Run Python tests with coverage"
	@echo "  make test ts       - Run TypeScript vitest suite"
	@echo "  make test interop  - Run cross-runtime interop tests"
	@echo "  make test full     - Run Python + SHACL + TypeScript tests"

_help_story:
	@echo "Story subcommands:"
	@echo "  make story         - Generate, sign, verify, and SHACL-validate examples"
	@echo "  make story sign    - Write ignored signed example artifacts under examples/**/signed/"
	@echo "  make story verify  - Verify the signed example artifacts with the real verifier"

_help_build:
	@echo "Build subcommands:"
	@echo "  make build      - Build the TypeScript package"
	@echo "  make build ts   - Build the TypeScript package"

# Create virtual environment and install dependencies
setup:
	@set -- $(filter-out $@,$(MAKECMDGOALS)); \
	subcommand="$${1:-default}"; \
	if [ "$$#" -gt 1 ]; then \
		echo "ERROR: Too many subcommands for 'make setup': $(filter-out $@,$(MAKECMDGOALS))"; \
		echo "Run 'make setup help' for available options."; \
		exit 1; \
	fi; \
	case "$$subcommand" in \
		default) "$(MAKE)" --no-print-directory _setup_default ;; \
		submodules) "$(MAKE)" --no-print-directory _setup_submodules ;; \
		ts) "$(MAKE)" --no-print-directory _setup_ts ;; \
		help) "$(MAKE)" --no-print-directory _help_setup ;; \
		*) echo "ERROR: Unknown setup subcommand '$$subcommand'"; echo "Run 'make setup help' for available options."; exit 1 ;; \
	esac

_setup_default:
	@echo "Setting up development environment..."
	@echo "Checking Python virtual environment and dependencies..."
ifdef CI
	@set -e; \
	if "$(PYTHON)" -c "import pre_commit, linkml" >/dev/null 2>&1; then \
		echo "OK: Python environment and dependencies are ready via $(PYTHON)"; \
	else \
		echo "CI environment missing dependencies; bootstrapping..."; \
		$(PIP) install -e ".[dev]"; \
		$(PIP) install linkml; \
		$(PRECOMMIT) install; \
	fi
else
	@set -e; \
	if [ ! -f "$(PYTHON)" ]; then \
		echo "Python virtual environment not found; bootstrapping..."; \
		"$(MAKE)" --no-print-directory "$(ACTIVATE_SCRIPT)"; \
	elif "$(PYTHON)" -c "import pre_commit, linkml" >/dev/null 2>&1; then \
		echo "OK: Python virtual environment and dependencies are ready at $(VENV)"; \
	else \
		echo "Python virtual environment found but dependencies are missing; bootstrapping..."; \
		"$(MAKE)" --no-print-directory -B "$(ACTIVATE_SCRIPT)"; \
	fi
endif
	@"$(MAKE)" --no-print-directory setup submodules
	@"$(MAKE)" --no-print-directory setup ts
	@echo ""
	@echo "Setup complete. Activate with: $(ACTIVATE_HINT)"

$(VENV_PYTHON):
	@echo "Creating Python virtual environment at $(VENV)..."
	@"$(BOOTSTRAP_PYTHON)" -m venv "$(VENV)"
	@$(PIP) install --upgrade pip
	@echo "OK: Python virtual environment ready"

$(ACTIVATE_SCRIPT): $(VENV_PYTHON)
	@echo "Installing Python dependencies..."
	@$(PIP) install -e ".[dev]"
	@$(PIP) install linkml
	@$(PRECOMMIT) install
	@echo "OK: Python development environment ready"

# Setup ontology-management-base submodule using the same active venv
_setup_submodules:
	@echo "Setting up ontology-management-base submodule..."
	@set -e; \
	if [ -f "$(OMB_SUBMODULE_DIR)/setup.py" ] || [ -f "$(OMB_SUBMODULE_DIR)/pyproject.toml" ]; then \
		$(PIP) install -e "$(OMB_SUBMODULE_DIR)"; \
		echo "OK: ontology-management-base submodule setup complete"; \
	elif [ -f "$(OMB_SUBMODULE_DIR)/Makefile" ]; then \
		"$(MAKE)" --no-print-directory -C "$(OMB_SUBMODULE_DIR)" setup \
			VENV="$(abspath $(VENV))" \
			PYTHON="$(PYTHON_ABS)"; \
		echo "OK: ontology-management-base submodule setup complete"; \
	else \
		echo "WARNING: Skipping ontology-management-base submodule setup (not found)"; \
	fi

# Bootstrap TypeScript toolchain
_setup_ts:
	@echo "Bootstrapping TypeScript dependencies..."
	@cd "$(TS_DIR)" && $(YARN) install
	@echo "OK: TypeScript bootstrap complete"

# Install package (user mode)
install:
	@set -- $(filter-out $@,$(MAKECMDGOALS)); \
	subcommand="$${1:-default}"; \
	if [ "$$#" -gt 1 ]; then \
		echo "ERROR: Too many subcommands for 'make install': $(filter-out $@,$(MAKECMDGOALS))"; \
		echo "Run 'make install help' for available options."; \
		exit 1; \
	fi; \
	case "$$subcommand" in \
		default) "$(MAKE)" --no-print-directory _install_default ;; \
		dev) "$(MAKE)" --no-print-directory _install_dev ;; \
		help) "$(MAKE)" --no-print-directory _help_install ;; \
		*) echo "ERROR: Unknown install subcommand '$$subcommand'"; echo "Run 'make install help' for available options."; exit 1 ;; \
	esac

_install_default:
	@echo "Installing package in editable mode..."
ifndef CI
	@"$(MAKE)" --no-print-directory "$(VENV_PYTHON)"
endif
	@$(PIP) install -e .
	@echo "OK: Package installation complete"

# Install with dev dependencies (works in CI without venv creation)
_install_dev:
	@echo "Installing development dependencies..."
ifndef CI
	@"$(MAKE)" --no-print-directory "$(VENV_PYTHON)"
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
	@PYTHONPATH="src/python$(PYTHONPATH_SEP)$$PYTHONPATH" "$(PYTHON)" src/python/harbour/generate_artifacts.py
	@echo ""
	@echo "OK: Artifacts generated in artifacts/"

# Validate credentials against generated SHACL shapes and JSON-LD syntax
validate:
	@set -- $(filter-out $@,$(MAKECMDGOALS)); \
	subcommand="$${1:-default}"; \
	if [ "$$#" -gt 1 ]; then \
		echo "ERROR: Too many subcommands for 'make validate': $(filter-out $@,$(MAKECMDGOALS))"; \
		echo "Run 'make validate help' for available options."; \
		exit 1; \
	fi; \
	case "$$subcommand" in \
		default) "$(MAKE)" --no-print-directory _validate_default ;; \
		shacl) "$(MAKE)" --no-print-directory _validate_shacl ;; \
		help) "$(MAKE)" --no-print-directory _help_validate ;; \
		*) echo "ERROR: Unknown validate subcommand '$$subcommand'"; echo "Run 'make validate help' for available options."; exit 1 ;; \
	esac

_validate_default:
	$(call check_dev_setup)
	@echo "Validating harbour credentials..."
	@PYTHONPATH="src/python$(PYTHONPATH_SEP)$$PYTHONPATH" $(PYTEST) tests/python/credentials/test_validation.py -v
	@echo "OK: Validation complete"

# Validate example credentials against SHACL shapes via ontology-management-base
_validate_shacl:
	$(call check_dev_setup)
	@echo "Running SHACL data conformance check on examples..."
	@cd "$(OMB_SUBMODULE_DIR)" && \
		tmp_output=$$(mktemp) && \
		allow_online_flag="" ; \
		if [ "$(HARBOUR_VALIDATE_ALLOW_ONLINE)" = "0" ]; then \
			allow_online_flag="--offline" ; \
		fi ; \
		if [ -n "$(HARBOUR_VALIDATE_PATH)" ]; then \
			target_path="../../$(HARBOUR_VALIDATE_PATH)" ; \
			if [ -d "$$target_path" ]; then \
				json_count=$$(find "$$target_path" -maxdepth 1 -type f \( -name '*.json' -o -name '*.jsonld' \) | wc -l) ; \
				if [ "$$json_count" -eq 0 ]; then \
					echo "ERROR: No .json or .jsonld files found under $$target_path" >&2 ; \
					rm -f $$tmp_output ; \
					exit 1 ; \
				fi ; \
			elif [ -f "$$target_path" ]; then \
				case "$$target_path" in \
					*.json|*.jsonld) ;; \
					*) echo "ERROR: Harbour SHACL validation only supports .json/.jsonld files or directories: $$target_path" >&2 ; rm -f $$tmp_output ; exit 1 ;; \
				esac ; \
			else \
				echo "ERROR: Validation path not found: $$target_path" >&2 ; \
				rm -f $$tmp_output ; \
				exit 1 ; \
			fi ; \
			"$(PYTHON_ABS)" -m src.tools.validators.validation_suite \
				--run check-data-conformance \
				$$allow_online_flag \
				--data-paths "$$target_path" ../../examples/did-ethr/ ../../tests/validation-probe/ontology-loading-probe.json \
				--artifacts ../../artifacts > $$tmp_output 2>&1 ; \
		else \
			"$(PYTHON_ABS)" -m src.tools.validators.validation_suite \
				--run check-data-conformance \
				$$allow_online_flag \
				--data-paths $(addprefix ../../,$(HARBOUR_EXAMPLE_FILES)) ../../examples/did-ethr/ ../../tests/validation-probe/ontology-loading-probe.json \
				--artifacts ../../artifacts > $$tmp_output 2>&1 ; \
		fi ; \
		status=$$? ; \
		cat $$tmp_output ; \
		if [ $$status -ne 0 ]; then \
			rm -f $$tmp_output ; \
			exit $$status ; \
		fi ; \
		if [ "$(HARBOUR_VALIDATE_ENFORCE_REQUIRED_ONTOLOGIES)" = "1" ]; then \
			for required in \
				"imports/cs/cs.owl.ttl" \
				"imports/cred/cred.owl.ttl" \
				"../../artifacts/harbour-gx-credential/harbour-gx-credential.owl.ttl" \
				"artifacts/gx/gx.owl.ttl" ; do \
				if ! grep -q "$$required" $$tmp_output ; then \
					echo "ERROR: Required ontology not loaded by validation suite: $$required" >&2 ; \
					rm -f $$tmp_output ; \
					exit 1 ; \
				fi ; \
			done ; \
		fi ; \
		rm -f $$tmp_output
	@echo "OK: SHACL validation complete"

# Run pre-commit hooks on all files
lint:
	@set -- $(filter-out $@,$(MAKECMDGOALS)); \
	subcommand="$${1:-default}"; \
	if [ "$$#" -gt 1 ]; then \
		echo "ERROR: Too many subcommands for 'make lint': $(filter-out $@,$(MAKECMDGOALS))"; \
		echo "Run 'make lint help' for available options."; \
		exit 1; \
	fi; \
	case "$$subcommand" in \
		default) "$(MAKE)" --no-print-directory _lint_default ;; \
		md) "$(MAKE)" --no-print-directory _lint_md ;; \
		ts) "$(MAKE)" --no-print-directory _lint_ts ;; \
		help) "$(MAKE)" --no-print-directory _help_lint ;; \
		*) echo "ERROR: Unknown lint subcommand '$$subcommand'"; echo "Run 'make lint help' for available options."; exit 1 ;; \
	esac

_lint_default:
	$(call check_dev_setup)
	@echo "Running pre-commit checks..."
	@"$(PYTHON)" -m pre_commit run --all-files
	@echo "OK: Pre-commit checks complete"

# Lint Markdown files
_lint_md: ## Lint Markdown files with markdownlint-cli2
	@echo "Linting Markdown files..."
	@npx --yes markdownlint-cli2
	@echo "OK: Markdown lint complete"

# Auto-format code
format:
	@set -- $(filter-out $@,$(MAKECMDGOALS)); \
	subcommand="$${1:-default}"; \
	if [ "$$#" -gt 1 ]; then \
		echo "ERROR: Too many subcommands for 'make format': $(filter-out $@,$(MAKECMDGOALS))"; \
		echo "Run 'make format help' for available options."; \
		exit 1; \
	fi; \
	case "$$subcommand" in \
		default) "$(MAKE)" --no-print-directory _format_default ;; \
		md) "$(MAKE)" --no-print-directory _format_md ;; \
		help) "$(MAKE)" --no-print-directory _help_format ;; \
		*) echo "ERROR: Unknown format subcommand '$$subcommand'"; echo "Run 'make format help' for available options."; exit 1 ;; \
	esac

_format_default:
	$(call check_dev_setup)
	@echo "Formatting Python code..."
	@"$(PYTHON)" -m ruff format src/python/ tests/
	@"$(PYTHON)" -m ruff check --fix src/python/ tests/
	@echo "OK: Python formatting complete"

# Auto-fix Markdown lint violations
_format_md: ## Auto-fix Markdown lint violations
	@echo "Fixing Markdown files..."
	@npx --yes markdownlint-cli2 --fix
	@echo "OK: Markdown formatting complete"

# Run tests
test:
	@set -- $(filter-out $@,$(MAKECMDGOALS)); \
	subcommand="$${1:-default}"; \
	if [ "$$#" -gt 1 ]; then \
		echo "ERROR: Too many subcommands for 'make test': $(filter-out $@,$(MAKECMDGOALS))"; \
		echo "Run 'make test help' for available options."; \
		exit 1; \
	fi; \
	case "$$subcommand" in \
		default) "$(MAKE)" --no-print-directory _test_default ;; \
		cov) "$(MAKE)" --no-print-directory _test_cov ;; \
		ts) "$(MAKE)" --no-print-directory _test_ts ;; \
		interop) "$(MAKE)" --no-print-directory _test_interop ;; \
		full) "$(MAKE)" --no-print-directory _test_all ;; \
		help) "$(MAKE)" --no-print-directory _help_test ;; \
		*) echo "ERROR: Unknown test subcommand '$$subcommand'"; echo "Run 'make test help' for available options."; exit 1 ;; \
	esac

_test_default:
	$(call check_dev_setup)
	@echo "Running Python tests..."
	@PYTHONPATH="src/python$(PYTHONPATH_SEP)$$PYTHONPATH" $(PYTEST) tests/ -v
	@echo "OK: Python tests complete"

# Run tests with coverage
_test_cov:
	$(call check_dev_setup)
	@echo "Running Python tests with coverage..."
	@PYTHONPATH="src/python$(PYTHONPATH_SEP)$$PYTHONPATH" $(PYTEST) tests/ --cov=src/python/harbour --cov=src/python/credentials --cov-report=html --cov-report=term
	@echo "OK: Coverage run complete"

# TypeScript targets
build:
	@set -- $(filter-out $@,$(MAKECMDGOALS)); \
	subcommand="$${1:-default}"; \
	if [ "$$#" -gt 1 ]; then \
		echo "ERROR: Too many subcommands for 'make build': $(filter-out $@,$(MAKECMDGOALS))"; \
		echo "Run 'make build help' for available options."; \
		exit 1; \
	fi; \
	case "$$subcommand" in \
		default|ts) "$(MAKE)" --no-print-directory _build_ts ;; \
		help) "$(MAKE)" --no-print-directory _help_build ;; \
		*) echo "ERROR: Unknown build subcommand '$$subcommand'"; echo "Run 'make build help' for available options."; exit 1 ;; \
	esac

_build_ts:
	@echo "Building TypeScript..."
	@cd "$(TS_DIR)" && $(YARN) install && $(YARN) build
	@echo "OK: TypeScript build complete"

_test_ts:
	@echo "Running TypeScript tests..."
	@cd "$(TS_DIR)" && $(YARN) install && $(YARN) test
	@echo "OK: TypeScript tests complete"

_lint_ts:
	@echo "Linting TypeScript..."
	@cd "$(TS_DIR)" && $(YARN) install && $(YARN) lint
	@echo "OK: TypeScript lint complete"

# Cross-runtime interop tests (requires both Python + TypeScript)
_test_interop:
	$(call check_dev_setup)
	@echo "Running cross-runtime interop tests..."
	@PYTHONPATH="src/python$(PYTHONPATH_SEP)$$PYTHONPATH" $(PYTEST) tests/interop/ -v
	@echo "OK: Interop tests complete"

story:
	@set -- $(filter-out $@,$(MAKECMDGOALS)); \
	subcommand="$${1:-default}"; \
	if [ "$$#" -gt 1 ]; then \
		echo "ERROR: Too many subcommands for 'make story': $(filter-out $@,$(MAKECMDGOALS))"; \
		echo "Run 'make story help' for available options."; \
		exit 1; \
	fi; \
	case "$$subcommand" in \
		default) "$(MAKE)" --no-print-directory _story_default ;; \
		sign) "$(MAKE)" --no-print-directory _story_sign ;; \
		verify) "$(MAKE)" --no-print-directory _story_verify ;; \
		help) "$(MAKE)" --no-print-directory _help_story ;; \
		*) echo "ERROR: Unknown story subcommand '$$subcommand'"; echo "Run 'make story help' for available options."; exit 1 ;; \
	esac

_story_sign:
	$(call check_dev_setup)
	@echo "Signing Harbour example storylines..."
	@rm -rf examples/signed examples/gaiax/signed
	@PYTHONPATH="src/python$(PYTHONPATH_SEP)$$PYTHONPATH" "$(PYTHON)" -m credentials.example_signer examples/
	@echo "OK: Signed example artifacts written to ignored signed/ directories"

_story_verify:
	$(call check_dev_setup)
	@echo "Verifying Harbour signed example storylines..."
	@PYTHONPATH="src/python$(PYTHONPATH_SEP)$$PYTHONPATH" "$(PYTHON)" -m credentials.verify_signed_examples
	@echo "OK: Signed Harbour example artifacts verified"

_story_default:
	@echo "Running Harbour storyline (generate + sign + verify + SHACL validate)..."
	@"$(MAKE)" --no-print-directory generate
	@"$(MAKE)" --no-print-directory _story_sign
	@"$(MAKE)" --no-print-directory _story_verify
	@"$(MAKE)" --no-print-directory _validate_shacl
	@echo "OK: Harbour storyline complete"

# ---------- Release Artifacts ----------

RELEASE_DIR ?= site/w3id/reachhaven/harbour

release-artifacts: ## Copy artifacts to w3id directory structure for GitHub Pages publishing
	@echo "Preparing w3id artifact structure..."
	@mkdir -p "$(RELEASE_DIR)/core/v1"
	@mkdir -p "$(RELEASE_DIR)/gx/v1"
	@mkdir -p "$(RELEASE_DIR)/delegate/v1"
	@cp artifacts/harbour-core-credential/harbour-core-credential.owl.ttl "$(RELEASE_DIR)/core/v1/ontology.ttl"
	@cp artifacts/harbour-core-credential/harbour-core-credential.shacl.ttl "$(RELEASE_DIR)/core/v1/shapes.ttl"
	@cp artifacts/harbour-core-credential/harbour-core-credential.context.jsonld "$(RELEASE_DIR)/core/v1/context.jsonld"
	@cp artifacts/harbour-gx-credential/harbour-gx-credential.owl.ttl "$(RELEASE_DIR)/gx/v1/ontology.ttl"
	@cp artifacts/harbour-gx-credential/harbour-gx-credential.shacl.ttl "$(RELEASE_DIR)/gx/v1/shapes.ttl"
	@cp artifacts/harbour-gx-credential/harbour-gx-credential.context.jsonld "$(RELEASE_DIR)/gx/v1/context.jsonld"
	@cp artifacts/harbour-core-delegation/harbour-core-delegation.owl.ttl "$(RELEASE_DIR)/delegate/v1/ontology.ttl"
	@cp artifacts/harbour-core-delegation/harbour-core-delegation.context.jsonld "$(RELEASE_DIR)/delegate/v1/context.jsonld"
	@echo "OK: Artifacts prepared in $(RELEASE_DIR)/"

# Compound targets
all:
	@echo "Running default quality pipeline (lint + test)..."
	@"$(MAKE)" --no-print-directory lint
	@"$(MAKE)" --no-print-directory test
	@echo "OK: Default quality pipeline complete"

# Run all tests (Python + TypeScript)
_test_all:
	@echo "Running all tests (Python + SHACL + TypeScript)..."
	@"$(MAKE)" --no-print-directory _build_ts
	@"$(MAKE)" --no-print-directory _test_default
	@"$(MAKE)" --no-print-directory _validate_shacl
	@"$(MAKE)" --no-print-directory _test_ts
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
