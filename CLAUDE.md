# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Harbour Credentials** — Cryptographic library for signing, verifying, and managing W3C Verifiable Credentials. Dual-runtime implementation in Python and TypeScript with feature parity.

Supports SD-JWT-VC (EUDI/OIDC4VP) + VC-JOSE-COSE (Gaia-X) formats with ES256 (P-256) as the primary algorithm.

## Essential Commands

```bash
# First-time setup (creates venv, installs deps, bootstraps TS, sets up submodules)
make setup
source .venv/bin/activate

# Run all tests (Python + TypeScript)
make test-all

# Run Python tests only
make test

# Run TypeScript tests only
make test-ts

# Run a single Python test file
PYTHONPATH=src/python:$PYTHONPATH pytest tests/python/harbour/test_sign.py -v

# Run a single Python test by name
PYTHONPATH=src/python:$PYTHONPATH pytest tests/python/harbour/test_sign.py -v -k "test_name"

# Run TypeScript tests (from TS_DIR)
cd src/typescript/harbour && yarn test

# Run a single TypeScript test file
cd src/typescript/harbour && yarn vitest run --config vitest.config.ts ../../../tests/typescript/harbour/sign.test.ts

# Run interop tests (requires both Python and TS deps)
PYTHONPATH=src/python:$PYTHONPATH pytest tests/interop/test_cross_runtime.py -v

# Build TypeScript
make build-ts

# Lint and format
make lint
make format

# Generate OWL/SHACL/JSON-LD from LinkML schemas
make generate
```

**Important:** Python tests require `PYTHONPATH=src/python:$PYTHONPATH` when running pytest directly. The `make test` target handles this automatically.

## Architecture

### Dual Runtime with Feature Parity

Python (`src/python/harbour/`) and TypeScript (`src/typescript/harbour/`) implement the same crypto operations. API naming is consistent across runtimes (snake_case in Python, camelCase in TypeScript).

| Module | Python | TypeScript | Purpose |
|--------|--------|------------|---------|
| `keys` | `keys.py` | `keys.ts` | Key generation (P-256, Ed25519), DID:key encoding |
| `signer` / `sign` | `signer.py` | `sign.ts` | JWT signing (ES256, EdDSA) |
| `verifier` / `verify` | `verifier.py` | `verify.ts` | JWT verification |
| `sd_jwt` / `sd-jwt` | `sd_jwt.py` | `sd-jwt.ts` | SD-JWT-VC selective disclosure |
| `kb_jwt` / `kb-jwt` | `kb_jwt.py` | `kb-jwt.ts` | Key Binding JWT |
| `x509` | `x509.py` | `x509.ts` | X.509 certificates |
| `credentials/` | Python only | — | Credential processing pipeline |

### Test Layout

Tests live in `tests/` with shared fixtures:
- `tests/fixtures/` — shared keys (`keys/`), tokens (`tokens/`), credentials (`credentials/`), `sample-vc.json`
- `tests/python/harbour/` — Python harbour module tests
- `tests/python/credentials/` — Python credentials pipeline tests
- `tests/typescript/harbour/` — TypeScript tests (vitest, config at `src/typescript/harbour/vitest.config.ts`)
- `tests/interop/` — Cross-runtime interoperability tests
- `tests/conftest.py` — Root-level pytest fixtures (Ed25519 + P-256 keypairs, sample VC/VP)

### TypeScript Toolchain

- Package manager: **Yarn 4** via corepack (`corepack enable`)
- Test runner: **vitest** (config in `src/typescript/harbour/vitest.config.ts`)
- Build: `tsc` (strict mode, ES2022 target)
- Package: `@reachhaven/harbour-credentials`
- TS source lives in `src/typescript/harbour/`, tests reference back via relative paths

### Submodules

Clone with `--recurse-submodules`. If already cloned: `git submodule update --init --recursive --depth 1`

- `submodules/ontology-management-base/` — SHACL validation suite
- `submodules/w3id.org/` — W3ID context resolution

### LinkML → Artifacts Pipeline

`linkml/*.yaml` schemas generate `artifacts/` (OWL ontology, SHACL shapes, JSON-LD context) via `make generate`. The credentials pipeline (`src/python/credentials/`) handles claim mapping and example signing.

## Key Imports

### Python

```python
from harbour.keys import generate_p256_keypair, p256_public_key_to_did_key
from harbour.signer import sign_vc_jose
from harbour.verifier import verify_vc_jose, VerificationError
from harbour.sd_jwt import issue_sd_jwt_vc, verify_sd_jwt_vc
from harbour.kb_jwt import create_kb_jwt, verify_kb_jwt
from harbour.x509 import generate_self_signed_cert, validate_x5c_chain
```

### TypeScript

```typescript
import {
  generateP256Keypair, p256PublicKeyToDid,
  signJwt, verifyJwt,
  issueSdJwt, verifySdJwt,
  createKbJwt, verifyKbJwt,
} from '@reachhaven/harbour-credentials';
```

## CLI Entry Points

All Python modules have CLI interfaces: `python -m harbour.keys --help`, `python -m harbour.signer --help`, etc. Also: `python -m credentials.claim_mapping --help`, `python -m credentials.example_signer --help`.

## Coding Conventions

### Python
- **Python 3.12+** with type hints on public APIs
- **pathlib.Path** (never `os.path`)
- All modules must have `main()` with `argparse` and `--help`
- Formatter: black (line-length 88), isort (profile: black)

### TypeScript
- **TypeScript 5.x** with strict mode, ES2022 target
- **async/await** for crypto operations
- Export types alongside functions

## Git Commit Policy

**STRICT REQUIREMENTS:**

- Always sign commits with `-s -S` flags (Signed-off-by + GPG signature)
- **Never include AI attribution** — no `Co-Authored-By`, `Generated-By`, or similar headers mentioning AI assistants
- **Never mention AI tools in commit messages**
- Use conventional commit format: `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`

```bash
git commit -s -S -m "feat(harbour): add KB-JWT support"
```

## Change Documentation

When instructed to prepare a commit or PR, **do not commit directly**. Create these files in `.playground/` (gitignored) for human review:

| File | Purpose |
|------|---------|
| `.playground/commit-message.md` | Conventional commit message, ready for `git commit -s -S` |
| `.playground/pr-description.md` | PR description following any existing PR template |

## Instruction Files

| Topic | File |
|-------|------|
| Agent instructions | [AGENTS.md](AGENTS.md) |
| Copilot instructions | [.github/copilot-instructions.md](.github/copilot-instructions.md) |
| Documentation | [docs/README.md](docs/README.md) |
| ADRs | [docs/decisions/](docs/decisions/) |

## Common Mistakes to Avoid

- Using `os.path` instead of `pathlib.Path`
- Forgetting CLI `main()` with `--help` on new Python modules
- Breaking feature parity between Python and TypeScript
- Committing without `-s -S` signing
- Running pytest without `PYTHONPATH=src/python:$PYTHONPATH`
- Using different API conventions between Python and TypeScript
