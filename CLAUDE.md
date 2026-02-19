# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Harbour Credentials** — Cryptographic library for signing, verifying, and managing verifiable credentials. Dual-runtime implementation in Python and TypeScript with feature parity.

**Key capabilities:**
- P-256 and Ed25519 key generation with DID:key encoding
- VC-JOSE-COSE JWT signing and verification (ES256)
- SD-JWT-VC with selective disclosure
- KB-JWT (Key Binding JWT) for holder binding
- X.509 certificate generation and chain validation

## Essential Commands

```bash
# Install dev dependencies
make setup
make install-dev

# Run all tests (Python + TypeScript)
make test-all

# Run Python tests only
make test

# Run TypeScript tests only
make test-ts

# Build TypeScript
make build-ts

# Lint and format
make lint
make format

# Run with coverage
make test-cov
```

## Architecture

### Directory Structure

```
harbour-credentials/
├── src/
│   ├── python/
│   │   ├── harbour/        # Crypto library
│   │   │   ├── keys.py     # Key generation, DID:key encoding
│   │   │   ├── signer.py   # JWT signing
│   │   │   ├── verifier.py # JWT verification
│   │   │   ├── sd_jwt.py   # SD-JWT-VC issue/verify
│   │   │   ├── kb_jwt.py   # Key Binding JWT
│   │   │   └── x509.py     # X.509 certificates
│   │   └── credentials/    # LinkML pipeline (Python only)
│   │       ├── linkml_generator.py
│   │       ├── claim_mapping.py
│   │       └── example_signer.py
│   └── typescript/
│       └── harbour/        # TypeScript port of crypto library
│           ├── keys.ts
│           ├── sign.ts
│           ├── verify.ts
│           ├── sd-jwt.ts
│           ├── kb-jwt.ts
│           └── x509.ts
├── tests/
│   ├── fixtures/           # Shared test fixtures (keys, certs)
│   ├── python/credentials/ # Python credentials tests
│   └── typescript/harbour/ # TypeScript tests
└── linkml/                 # LinkML schemas for artifact generation
```

### Module Responsibilities

| Module | Python | TypeScript | Purpose |
|--------|--------|------------|---------|
| `keys` | ✅ | ✅ | Key generation, DID:key encoding |
| `signer` / `sign` | ✅ | ✅ | JWT signing (ES256, EdDSA) |
| `verifier` / `verify` | ✅ | ✅ | JWT verification |
| `sd_jwt` / `sd-jwt` | ✅ | ✅ | SD-JWT-VC selective disclosure |
| `kb_jwt` / `kb-jwt` | ✅ | ✅ | Key Binding JWT |
| `x509` | ✅ | ✅ | X.509 certificates |
| `credentials/` | ✅ | ❌ | LinkML generation (Python only) |

## Key Imports

### Python

```python
from harbour.keys import generate_p256_keypair, p256_public_key_to_did_key
from harbour.signer import sign_vc_jose
from harbour.verifier import verify_vc_jose, VerificationError
from harbour.sd_jwt import issue_sd_jwt_vc, verify_sd_jwt_vc
from harbour.kb_jwt import create_kb_jwt, verify_kb_jwt
from harbour.x509 import generate_self_signed_cert, validate_x5c_chain

from credentials.linkml_generator import generate_artifacts
from credentials.claim_mapping import vc_to_sd_jwt_claims
```

### TypeScript

```typescript
import {
  generateP256Keypair,
  p256PublicKeyToDid,
  signJwt,
  verifyJwt,
  issueSdJwt,
  verifySdJwt,
  createKbJwt,
  verifyKbJwt,
} from '@reachhaven/harbour-credentials';
```

## CLI Entry Points

All Python modules have CLI interfaces with `--help`:

```bash
python -m harbour.keys --help
python -m harbour.signer --help
python -m harbour.verifier --help
python -m harbour.sd_jwt --help
python -m harbour.kb_jwt --help
python -m harbour.x509 --help

python -m credentials.linkml_generator --help
python -m credentials.claim_mapping --help
python -m credentials.example_signer --help
```

## Coding Conventions

### Python
- **Python 3.10+** with type hints on public APIs
- **pathlib.Path** (never `os.path`)
- **4-space indentation**
- All modules must have `main()` with `argparse` and `--help`

### TypeScript
- **TypeScript 5.x** with strict mode
- **async/await** for crypto operations
- Export types alongside functions

## Git Commit Policy

**STRICT REQUIREMENTS:**

- ✅ **Always sign commits** with `-s -S` flags (Signed-off-by + GPG signature)
- ❌ **Never include AI attribution** — no `Co-Authored-By`, `Generated-By`, or similar headers mentioning AI assistants (Claude, Copilot, ChatGPT, etc.)
- ❌ **Never mention AI tools in commit messages** — do not reference that code was AI-generated or AI-assisted
- ✅ **Author must be the human developer** with official email address

```bash
# Correct commit command
git commit -s -S -m "feat(harbour): add KB-JWT support"
```

## Change Documentation

When making changes to the codebase, create/update these files in `.playground/` (gitignored):

| File | Purpose |
|------|---------|
| `.playground/commit-message.md` | Conventional commit message, ready for `git commit -s -S` |
| `.playground/pr-description.md` | PR description following any existing PR template |

**When instructed to prepare a commit or PR, do not commit directly.** Create these files for human review. The operator will either:
- Use them to manually commit/push and create a PR, or
- Use automated tooling with signed commits (`git commit -s -S`)

## Instruction Files

Read these before making changes:

| Topic | File |
|-------|------|
| Agent instructions | [AGENTS.md](AGENTS.md) |
| Documentation | [README.md](README.md) |
| Docs | [docs/README.md](docs/README.md) |

## Common Mistakes to Avoid

- ❌ Using `os.path` instead of `pathlib.Path`
- ❌ Forgetting to add CLI `main()` with `--help` to new Python modules
- ❌ Not maintaining feature parity between Python and TypeScript
- ❌ Committing without signing (`-s -S`)
- ❌ Using different API conventions between Python and TypeScript (keep consistent)
