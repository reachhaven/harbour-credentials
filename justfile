# Harbour Credentials — task runner.
#
# One command runner (replaces the old Makefile). Python recipes run through `uv`,
# which creates/syncs an isolated `.venv` from pyproject.toml + uv.lock and fetches
# a compatible Python (>=3.12) on demand — no manual venv creation or activation
# needed. TypeScript recipes run through `corepack yarn`.
#
# Quick start:
#   just setup      # init submodules + create the dev environment + hooks + TS deps
#   just --list     # see every recipe
#
# Requires `uv` (https://docs.astral.sh/uv/), `just` (https://just.systems) and,
# for the TypeScript recipes, Node.js 22 with Corepack on PATH.

# Run a Python command inside the project's dev environment. `--frozen` uses the
# committed uv.lock as-is (no re-resolution — the dev extra pins linkml from a git
# branch, which uv would otherwise re-check on every call), syncing `.venv` from
# the lock; `--extra dev` selects the dev dependencies (ruff, pytest, linkml, the
# editable `omb` submodule, …) from the locked graph.
run := "uv run --frozen --extra dev"

# TypeScript toolchain (Yarn via Corepack — never a bare `yarn`).
yarn := "corepack yarn"

TS_DIR := "src/typescript/harbour"
OMB_SUBMODULE_DIR := "submodules/ontology-management-base"
SVC_SUBMODULE_DIR := "submodules/service-characteristics"
RELEASE_DIR := "site/w3id/reachhaven/harbour"

export PYTHONUTF8 := "1"
export PYTHONIOENCODING := "utf-8"

# Default: list all recipes.
default:
    @just --list

# ===== Setup / install =====

# Init flat submodules + create the dev env (.venv, dev deps, editable omb) + hooks + TS deps.
setup: setup-submodules
    uv sync --extra dev
    {{run}} pre-commit install
    cd {{TS_DIR}} && {{yarn}} install
    @echo "[OK] Dev environment ready. Run recipes with: just <recipe>"

# Initialise the direct submodules FLAT (never recursively).
setup-submodules:
    #!/usr/bin/env bash
    set -euo pipefail
    # Direct submodules of this repo (no nesting):
    #   - ontology-management-base : installable `omb` package + committed Gaia-X
    #     artifacts/gx/* shapes (installed editable by `uv sync --extra dev`).
    #   - service-characteristics  : Gaia-X LinkML schema source imported by
    #     `just generate` via linkml/importmap.json; pinned to the commit OMB's gx
    #     artifacts were generated from — deliberately NOT shallow.
    #   - w3id.org                 : W3ID context redirects.
    # The LinkML compiler fork is NOT a submodule: it is a git dependency in the
    # [dev] extra of pyproject.toml, so no recursive submodule clone is required.
    echo "Setting up submodules (flat, non-recursive)..."
    if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
        git submodule update --init {{OMB_SUBMODULE_DIR}} {{SVC_SUBMODULE_DIR}} submodules/w3id.org
    fi
    if [ -f "{{SVC_SUBMODULE_DIR}}/linkml/gaia-x.yaml" ]; then
        echo "OK: service-characteristics schemas present (gaia-x import source)"
    else
        echo "WARNING: service-characteristics not initialized at {{SVC_SUBMODULE_DIR}}" >&2
        echo "         Run: git submodule update --init {{SVC_SUBMODULE_DIR}}" >&2
        exit 1
    fi

# Bootstrap the TypeScript toolchain only.
setup-ts:
    cd {{TS_DIR}} && {{yarn}} install
    @echo "OK: TypeScript bootstrap complete"

# Install the package with runtime dependencies only.
install:
    uv sync

# Install the package with dev dependencies (env for every other recipe).
install-dev:
    uv sync --extra dev

# ===== Generate artifacts (OWL / SHACL / JSON-LD context) =====

# Generate OWL / SHACL / JSON-LD context artifacts from the Harbour LinkML schemas.
generate:
    {{run}} python src/python/harbour/generate_artifacts.py
    @echo "OK: Artifacts generated in artifacts/"

# ===== Validation =====

# Structural validation tests for the Harbour credential examples.
validate:
    {{run}} python -m pytest tests/python/credentials/test_validation.py -v
    @echo "OK: Validation complete"

# Validate example credentials (or a given .json/.jsonld path) against SHACL shapes via omb.
validate-shacl path="":
    #!/usr/bin/env bash
    set -euo pipefail
    # Optional path validates a single Harbour .json/.jsonld file or folder, e.g.
    #   just validate-shacl examples/gaiax/legal-person-credential.json
    # Env: HARBOUR_VALIDATE_ALLOW_ONLINE=0 -> --offline (no did:web/http(s) fallback);
    #      HARBOUR_VALIDATE_ENFORCE_REQUIRED_ONTOLOGIES overrides the required-ontology
    #      gate (default 1 for the full example set, 0 when a path is given).
    echo "Running SHACL data conformance check on examples..."
    allow_online="${HARBOUR_VALIDATE_ALLOW_ONLINE:-1}"
    enforce="${HARBOUR_VALIDATE_ENFORCE_REQUIRED_ONTOLOGIES:-}"
    target_path="{{path}}"
    allow_online_flag=""
    if [ "$allow_online" = "0" ]; then allow_online_flag="--offline"; fi
    if [ -n "$target_path" ]; then
        if [ -d "$target_path" ]; then
            json_count=$(find "$target_path" -maxdepth 1 -type f \( -name '*.json' -o -name '*.jsonld' \) | wc -l)
            if [ "$json_count" -eq 0 ]; then
                echo "ERROR: No .json or .jsonld files found under $target_path" >&2
                exit 1
            fi
        elif [ -f "$target_path" ]; then
            case "$target_path" in
                *.json|*.jsonld) ;;
                *) echo "ERROR: Harbour SHACL validation only supports .json/.jsonld files or directories: $target_path" >&2; exit 1 ;;
            esac
        else
            echo "ERROR: Validation path not found: $target_path" >&2
            exit 1
        fi
        : "${enforce:=0}"
        data_paths=( "$target_path" examples/did-ethr/ tests/validation-probe/ontology-loading-probe.json )
    else
        : "${enforce:=1}"
        data_paths=( examples/*.json examples/gaiax/*.json examples/did-ethr/ tests/validation-probe/ontology-loading-probe.json )
    fi
    tmp_output=$(mktemp)
    if {{run}} python -m omb.validators.validation_suite \
            --run check-data-conformance \
            $allow_online_flag \
            --data-paths "${data_paths[@]}" \
            --artifacts artifacts > "$tmp_output" 2>&1; then
        status=0
    else
        status=$?
    fi
    cat "$tmp_output"
    if [ "$status" -ne 0 ]; then
        rm -f "$tmp_output"
        exit "$status"
    fi
    if [ "$enforce" = "1" ]; then
        for required in \
            "imports/cs/cs.owl.ttl" \
            "imports/cred/cred.owl.ttl" \
            "artifacts/harbour-gx-credential/harbour-gx-credential.owl.ttl" \
            "artifacts/gx/gx.owl.ttl" ; do
            if ! grep -q "$required" "$tmp_output" ; then
                echo "ERROR: Required ontology not loaded by validation suite: $required" >&2
                rm -f "$tmp_output"
                exit 1
            fi
        done
    fi
    rm -f "$tmp_output"
    echo "OK: SHACL validation complete"

# ===== Lint / format =====

# Run all pre-commit checks (Python + Markdown + JSON-LD/Turtle) across the repo.
lint:
    {{run}} pre-commit run --all-files

# Lint Markdown files with markdownlint-cli2.
lint-md:
    npx --yes markdownlint-cli2

# Lint the TypeScript package (tsc --noEmit).
lint-ts:
    cd {{TS_DIR}} && {{yarn}} install && {{yarn}} lint

# Auto-format Python with ruff (format, then check --fix).
format:
    {{run}} ruff format src/python/ tests/
    {{run}} ruff check --fix src/python/ tests/

# Auto-fix Markdown lint violations.
format-md:
    npx --yes markdownlint-cli2 --fix

# ===== Tests =====

# Run the Python pytest suite (excludes interop — use `just test-full`/`test-interop`).
test:
    {{run}} python -m pytest tests/ -v --ignore=tests/interop

# Run the Python tests with coverage (HTML + terminal report).
test-cov:
    {{run}} python -m pytest tests/ --cov=src/python/harbour --cov=src/python/credentials --cov-report=html --cov-report=term

# Run the TypeScript vitest suite.
test-ts:
    cd {{TS_DIR}} && {{yarn}} install && {{yarn}} test

# Run the cross-runtime interop tests (requires both Python + TypeScript).
test-interop:
    {{run}} python -m pytest tests/interop/ -v

# Full test suite: build TS + Python tests + SHACL conformance + TypeScript tests.
test-full: build test validate-shacl test-ts
    @echo "OK: All tests complete"

# ===== Build (TypeScript) =====

# Build the TypeScript package.
build:
    cd {{TS_DIR}} && {{yarn}} install && {{yarn}} build

# ===== Credential lifecycle story pipeline =====

# Python storyline: generate → sign → verify → digestSRI → SHACL validate.
story: generate story-sign story-verify story-digests validate-shacl
    @echo "OK: Harbour storyline complete"

# TypeScript storyline: generate → build → sign → verify → digestSRI → SHACL validate.
story-ts: generate build story-sign-ts story-verify-ts story-digests-ts validate-shacl
    @echo "OK: Harbour TypeScript storyline complete"

# Cross-runtime: TS signs → Python verifies, then Python signs → TS verifies, + digestSRI.
story-cross: generate build story-sign-ts story-verify story-sign story-verify-ts story-digests story-digests-ts
    @echo "OK: Cross-runtime story verification complete"

# Write ignored signed example artifacts under examples/**/signed/ (Python).
story-sign:
    rm -rf examples/signed examples/gaiax/signed
    {{run}} python -m credentials.example_signer examples/

# Verify the signed example artifacts with the real verifier (Python).
story-verify:
    {{run}} python -m credentials.verify_signed_examples

# Verify example digestSRI integrity hashes (Python).
story-digests:
    {{run}} python -m credentials.digest_sri_examples --check

# Write ignored signed example artifacts under examples/**/signed/ (TypeScript).
story-sign-ts:
    rm -rf examples/signed examples/gaiax/signed
    cd {{TS_DIR}} && {{yarn}} install && {{yarn}} story:sign

# Verify the signed example artifacts with the real verifier (TypeScript).
story-verify-ts:
    cd {{TS_DIR}} && {{yarn}} story:verify

# Verify example digestSRI integrity hashes (TypeScript).
story-digests-ts:
    cd {{TS_DIR}} && {{yarn}} story:digests

# ===== Compound pipelines =====

# Generate artifacts, then run structural validation.
check: generate validate
    @echo "OK: Check pipeline complete"

# Full local CI pipeline: lint + check + tests.
all: lint check test
    @echo "OK: Full quality pipeline complete"

# ===== Release artifacts =====

# Copy artifacts into the w3id directory structure for GitHub Pages publishing.
release-artifacts:
    #!/usr/bin/env bash
    set -euo pipefail
    echo "Preparing w3id artifact structure..."
    mkdir -p "{{RELEASE_DIR}}/core/v1" "{{RELEASE_DIR}}/gx/v1" "{{RELEASE_DIR}}/delegate/v1"
    cp artifacts/harbour-core-credential/harbour-core-credential.owl.ttl "{{RELEASE_DIR}}/core/v1/ontology.ttl"
    cp artifacts/harbour-core-credential/harbour-core-credential.shacl.ttl "{{RELEASE_DIR}}/core/v1/shapes.ttl"
    cp artifacts/harbour-core-credential/harbour-core-credential.context.jsonld "{{RELEASE_DIR}}/core/v1/context.jsonld"
    cp artifacts/harbour-gx-credential/harbour-gx-credential.owl.ttl "{{RELEASE_DIR}}/gx/v1/ontology.ttl"
    cp artifacts/harbour-gx-credential/harbour-gx-credential.shacl.ttl "{{RELEASE_DIR}}/gx/v1/shapes.ttl"
    cp artifacts/harbour-gx-credential/harbour-gx-credential.context.jsonld "{{RELEASE_DIR}}/gx/v1/context.jsonld"
    cp artifacts/harbour-core-delegation/harbour-core-delegation.owl.ttl "{{RELEASE_DIR}}/delegate/v1/ontology.ttl"
    cp artifacts/harbour-core-delegation/harbour-core-delegation.context.jsonld "{{RELEASE_DIR}}/delegate/v1/context.jsonld"
    echo "OK: Artifacts prepared in {{RELEASE_DIR}}/"

# ===== Cleaning =====

# Remove build artifacts, caches, and the local uv-managed virtual environment.
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    rm -rf .venv build/ dist/ *.egg-info/ .pytest_cache/ .coverage htmlcov/
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    echo "OK: Cleaned"
