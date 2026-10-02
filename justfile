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
#
# The interpreter comes from `.python-version` (3.12, the primary version CI tests).
# Without it uv would build `.venv` on the newest CPython it can find, which is not
# necessarily a version this project is tested on. CI overrides it per matrix leg
# with `UV_PYTHON`, which takes precedence over the file.

# Run a Python command inside the project's dev environment. `--frozen` uses the
# committed uv.lock as-is — never re-resolving or rewriting it, which matters because
# the dev extra carries a git dependency (the ASCS-eV LinkML fork) — and syncs `.venv`
# from that lock; `--extra dev` selects the dev dependencies (ruff, pytest, linkml,
# omb, …) from the locked graph.
run := "uv run --frozen --extra dev"

# TypeScript toolchain (Yarn via Corepack — never a bare `yarn`).
yarn := "corepack yarn"

TS_DIR := "src/typescript/harbour"
SVC_SUBMODULE_DIR := "submodules/service-characteristics"
RELEASE_DIR := "site/w3id/reachhaven/harbour"

export PYTHONUTF8 := "1"
export PYTHONIOENCODING := "utf-8"

# Default: list all recipes.
default:
    @just --list

# ===== Setup / install =====

# Init flat submodules + create the dev env (.venv, dev deps) + hooks + TS deps.
setup: setup-submodules install-dev check-gx-pin
    {{run}} pre-commit install
    cd {{TS_DIR}} && {{yarn}} install
    @echo "[OK] Dev environment ready. Run recipes with: just <recipe>"

# Initialise the direct submodules FLAT (never recursively).
setup-submodules:
    #!/usr/bin/env bash
    set -euo pipefail
    # Direct submodules of this repo (no nesting):
    #   - service-characteristics  : Gaia-X LinkML schema source imported by
    #     `just generate` via linkml/importmap.json; pinned to the commit OMB's gx
    #     artifacts were generated from — deliberately NOT shallow. `just
    #     check-gx-pin` asserts that pin against the installed omb wheel.
    #   - w3id.org                 : W3ID context redirects.
    # ontology-management-base (the `omb` package) is installed from PyPI, and the
    # LinkML compiler fork is a git dependency in the [dev] extra of pyproject.toml,
    # so neither requires a submodule or recursive clone.
    echo "Setting up submodules (flat, non-recursive)..."
    if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
        git submodule update --init {{SVC_SUBMODULE_DIR}} submodules/w3id.org
    fi
    if [ -f "{{SVC_SUBMODULE_DIR}}/linkml/gaia-x.yaml" ]; then
        echo "OK: service-characteristics schemas present (gaia-x import source)"
    else
        echo "WARNING: service-characteristics not initialized at {{SVC_SUBMODULE_DIR}}" >&2
        echo "         Run: git submodule update --init {{SVC_SUBMODULE_DIR}}" >&2
        exit 1
    fi

# Assert the service-characteristics pin matches the gx artifacts in the omb wheel.
check-gx-pin:
    #!/usr/bin/env bash
    set -euo pipefail
    # `just generate` compiles harbour's gx layer against the gaia-x LinkML source in
    # submodules/service-characteristics, while `just validate-shacl` validates the
    # result against the gx SHACL shapes vendored inside the installed omb wheel. The
    # two only agree if the submodule sits on the very commit those shapes were
    # generated from — which the wheel records in omb/data/artifacts/gx/UPSTREAM_COMMIT.
    # Comparing against the wheel means an omb bump cannot silently leave the pin behind.
    #
    # Two halves of the pin can drift apart, so both are checked: the gitlink recorded
    # in the index (what a commit records and what a fresh clone / CI checks out) and
    # the commit the local submodule working tree is actually on. A repin that was
    # checked out but never `git add`ed leaves the repository still pinned to the old
    # Gaia-X — exactly the drift this guard exists to catch.
    expected=$({{run}} python -c "import omb, pathlib; print((pathlib.Path(omb.__file__).parent / 'data/artifacts/gx/UPSTREAM_COMMIT').read_text().strip())")
    gitlink=$(git ls-files -s -- {{SVC_SUBMODULE_DIR}} | awk '$1 == "160000" { print $2 }')
    if [ -z "$gitlink" ]; then
        echo "ERROR: {{SVC_SUBMODULE_DIR}} is not registered as a submodule in this index." >&2
        exit 1
    fi
    if [ ! -e "{{SVC_SUBMODULE_DIR}}/.git" ]; then
        echo "ERROR: {{SVC_SUBMODULE_DIR}} is not initialized — run: just setup-submodules" >&2
        exit 1
    fi
    worktree=$(git -C {{SVC_SUBMODULE_DIR}} rev-parse HEAD)
    if [ "$expected" != "$gitlink" ] || [ "$expected" != "$worktree" ]; then
        omb_version=$({{run}} python -c "import importlib.metadata as m; print(m.version('ontology-management-base'))")
        gx_ref=$({{run}} python -c "import omb, pathlib; print((pathlib.Path(omb.__file__).parent / 'data/artifacts/gx/UPSTREAM_REF').read_text().strip())")
        echo "ERROR: submodules/service-characteristics is out of step with omb ${omb_version}." >&2
        echo "       omb vendors gx ${gx_ref} generated from ${expected}" >&2
        echo "       recorded gitlink is                      ${gitlink}" >&2
        echo "       submodule working tree HEAD is           ${worktree}" >&2
        echo "       Fix: git -C {{SVC_SUBMODULE_DIR}} fetch origin ${expected} && \\" >&2
        echo "            git -C {{SVC_SUBMODULE_DIR}} checkout ${expected} && git add {{SVC_SUBMODULE_DIR}}" >&2
        exit 1
    fi
    echo "OK: service-characteristics matches the gx artifacts vendored by omb ($expected)"

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
    # A folder is expanded to its own .json/.jsonld files and NOT handed to omb as a
    # directory: omb walks a directory recursively, which would drag the gitignored
    # examples/**/signed/ output of `just story-sign` into the graph (the decoded
    # evidence VPs are fragments, not standalone credentials, so the run fails). The
    # default no-path run globs the example files for the same reason.
    # Env: HARBOUR_VALIDATE_ALLOW_ONLINE=0 -> --offline (no did:web/http(s) fallback);
    #      HARBOUR_VALIDATE_ENFORCE_REQUIRED_ONTOLOGIES overrides the required-ontology
    #      gate (default 1 for the full example set, 0 when a path is given).
    #
    # Every document is validated PER RESOURCE (`--per-resource`): each file in its
    # own data graph against the shared, closed shapes, never merged with the others.
    # That is the grain VC and DID data is issued and verified at, and the examples
    # reuse the same IRIs across files on purpose: did:ethr:0x14a34:0xa682... is the
    # credentialSubject of a closed harbour.gx:HarbourLegalPerson shape in
    # legal-person-credential.json and the root of a DID document carrying
    # sec:verificationMethod / didcore:service in examples/did-ethr/. Merged into one
    # graph, each document's properties land on the others' closed nodes as
    # ClosedConstraintComponent violations; worse, a merged graph lets an incomplete
    # document borrow a required property from a different file and pass.
    echo "Running SHACL data conformance check on examples (per-resource)..."
    allow_online="${HARBOUR_VALIDATE_ALLOW_ONLINE:-1}"
    enforce="${HARBOUR_VALIDATE_ENFORCE_REQUIRED_ONTOLOGIES:-}"
    target_path="{{path}}"
    allow_online_flag=""
    if [ "$allow_online" = "0" ]; then allow_online_flag="--offline"; fi

    targets=()
    if [ -n "$target_path" ]; then
        if [ -d "$target_path" ]; then
            while IFS= read -r data_file; do
                targets+=("$data_file")
            done < <(find "$target_path" -maxdepth 1 -type f \( -name '*.json' -o -name '*.jsonld' \) | sort)
            if [ "${#targets[@]}" -eq 0 ]; then
                echo "ERROR: No .json or .jsonld files found under $target_path" >&2
                exit 1
            fi
        elif [ -f "$target_path" ]; then
            case "$target_path" in
                *.json|*.jsonld) ;;
                *) echo "ERROR: Harbour SHACL validation only supports .json/.jsonld files or directories: $target_path" >&2; exit 1 ;;
            esac
            targets=("$target_path")
        else
            echo "ERROR: Validation path not found: $target_path" >&2
            exit 1
        fi
        : "${enforce:=0}"
    else
        targets=(examples/*.json examples/gaiax/*.json examples/did-ethr/*.json)
        : "${enforce:=1}"
    fi

    run_output=$(mktemp)
    trap 'rm -f "$run_output"' EXIT
    status=0
    {{run}} python -m omb.validators.validation_suite \
        --run check-data-conformance \
        --per-resource \
        $allow_online_flag \
        --data-paths "${targets[@]}" \
        --artifacts artifacts > "$run_output" 2>&1 || status=$?
    cat "$run_output"
    if [ "$status" -ne 0 ]; then exit "$status"; fi

    # A stale or half-resolved catalog otherwise "passes" by validating against
    # nothing: the full example set has to pull in the gx layer and the cs/cred imports.
    if [ "$enforce" = "1" ]; then
        for required in \
            "imports/cs/cs.owl.ttl" \
            "imports/cred/cred.owl.ttl" \
            "artifacts/harbour-gx-credential/harbour-gx-credential.owl.ttl" \
            "artifacts/gx/gx.owl.ttl" ; do
            if ! grep -q "$required" "$run_output" ; then
                echo "ERROR: Required ontology not loaded by validation suite: $required" >&2
                exit 1
            fi
        done
    fi
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

# `generate` and `story-sign` lead the dependency list because they produce inputs the
# suite reads and `just clean` removes (as does a fresh clone — both are gitignored):
#   * artifacts/          — the SHACL conformance run and the artifact tests read it;
#                           without it this recipe fails instead of testing anything.
#   * examples/**/signed/ — test_verify_signed_jwt is parametrized over the signed
#                           JWTs, so an empty directory collapses 7 assertions into a
#                           single degenerate [NOTSET] skip rather than failing.

# Full suite: artifacts + signed examples + TS build + Python tests + SHACL + TS tests.
test-full: generate story-sign build test validate-shacl test-ts
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

# Remove generated artifacts, caches, and the local uv-managed virtual environment.
clean:
    #!/usr/bin/env bash
    set -euo pipefail
    # artifacts/, site/ and examples/**/signed/ are generated output, not inputs.
    # Leaving artifacts/ behind keeps stale domains from renamed schemas registered
    # with omb on every `just validate-shacl` run, validating against shapes no
    # schema produces any more. `just generate` and `just story` rebuild them.
    rm -rf .venv build/ dist/ *.egg-info/ .pytest_cache/ .ruff_cache/ .coverage htmlcov/
    rm -rf artifacts/ site/ examples/signed examples/gaiax/signed
    find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name "*.pyc" -delete 2>/dev/null || true
    echo "OK: Cleaned"
