# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Harbour Credentials** — Cryptographic library for signing, verifying, and managing W3C Verifiable Credentials. Dual-runtime implementation in Python and TypeScript with feature parity.

Supports SD-JWT-VC (EUDI/OIDC4VP) + VC-JOSE-COSE (Gaia-X) formats with ES256 (P-256) as the primary algorithm.

The library is validated end-to-end by the **Harbour Credential Lifecycle** (see `examples/README.md`): a 4-actor narrative — Trust Anchor → Signing Service → Legal Person (organization) → Natural Person (employee) — that is signed and verified in *both* runtimes via the **story pipeline** (`make story`), proving interoperability. Understanding this trust model (below) is the fastest way to grasp the codebase.

## Essential Commands

```bash
# First-time setup (creates venv, installs deps + ASCS-eV LinkML fork, bootstraps TS, inits submodules)
make setup
source .venv/bin/activate

# --- Tests ---
make test            # Python tests only (excludes interop)
make test full       # Python + SHACL validation + TypeScript
make test ts         # TypeScript (vitest) only
make test interop    # Cross-runtime interop tests only
make test cov        # Python tests with coverage -> htmlcov/index.html + terminal report

# Run a single Python test file / a single test by name
PYTHONPATH=src/python:$PYTHONPATH pytest tests/python/harbour/test_sign.py -v
PYTHONPATH=src/python:$PYTHONPATH pytest tests/python/harbour/test_sign.py -v -k "test_name"

# Run TypeScript tests (from the TS package dir)
cd src/typescript/harbour && yarn test
cd src/typescript/harbour && yarn vitest run --config vitest.config.ts ../../../tests/typescript/harbour/sign.test.ts

# Run interop tests directly (requires both Python and TS deps)
PYTHONPATH=src/python:$PYTHONPATH pytest tests/interop/test_cross_runtime.py -v

# --- Credential lifecycle story pipeline (end-to-end sign/verify/validate of examples/) ---
make story           # Python: generate -> sign -> verify -> SHACL-validate
make story ts        # Same pipeline in TypeScript
make story cross     # Cross-runtime: TS signs -> Python verifies, then Python signs -> TS verifies

# --- Schema / artifacts ---
make generate        # Generate OWL/SHACL/JSON-LD artifacts from LinkML schemas (needs ASCS-eV LinkML fork)
make validate        # Structural validation tests (pytest tests/python/credentials/test_validation.py)
make validate shacl  # SHACL conformance on example credentials (via ontology-management-base submodule)

# --- Quality / build / compound pipelines ---
make build           # Build TypeScript (tsc)
make lint            # All pre-commit hooks (ruff, JSON-LD/Turtle, markdownlint); `make lint ts` for tsc --noEmit
make format          # ruff format + ruff check --fix
make check           # generate + validate
make all             # lint + check + test full (the full local CI pipeline)
```

**Subcommand pattern:** Grouped targets (`setup`, `install`, `test`, `validate`, `lint`, `format`, `story`, `build`) take the first trailing word as a subcommand — e.g. `make test full` dispatches to the internal `_test_all` target. Run `make <target> help` to list a target's subcommands.

**Important:** Python tests require `PYTHONPATH=src/python:$PYTHONPATH` when running pytest directly (use `make test` to get this automatically). On Windows PowerShell the separator is `;`: `$env:PYTHONPATH="src/python;$env:PYTHONPATH"`. The Makefile also honors a `VENV` override (`make setup VENV=/path`) and auto-detects a parent `../../.venv` for shared/monorepo workspaces.

## Architecture

### Dual Runtime with Feature Parity

Python (`src/python/harbour/`) and TypeScript (`src/typescript/harbour/`) implement the same crypto operations. API naming is consistent across runtimes (snake_case in Python, camelCase in TypeScript). **Breaking parity is a primary mistake to avoid** — a change to one runtime almost always needs the mirror change in the other, plus an interop test.

| Module | Python | TypeScript | Purpose |
|--------|--------|------------|---------|
| `keys` | `keys.py` | `keys.ts` | Key generation (P-256, Ed25519), DID encoding (did:key, did:ethr) |
| `signer` / `sign` | `signer.py` | `sign.ts` | JWT/VC/VP signing (ES256, EdDSA) |
| `verifier` / `verify` | `verifier.py` | `verify.ts` | JWT/VC/VP verification |
| `sd_jwt` / `sd-jwt` | `sd_jwt.py` | `sd-jwt.ts` | SD-JWT-VC selective disclosure |
| `kb_jwt` / `kb-jwt` | `kb_jwt.py` | `kb-jwt.ts` | Key Binding JWT |
| `delegation` | `delegation.py` | `delegation.ts` | Delegated signing evidence (OID4VP transaction_data) |
| `sd_jwt_vp` / `sd-jwt-vp` | `sd_jwt_vp.py` | `sd-jwt-vp.ts` | SD-JWT VP issue/verify with evidence |
| `x509` | `x509.py` | `x509.ts` | X.509 certificates / x5c chains |
| `generate_artifacts` | `generate_artifacts.py` | — | LinkML → OWL/SHACL/JSON-LD artifact generation |
| credential pipeline | `credentials/` (CLI) | `story-sign.ts` / `story-verify.ts` (CLI) | End-to-end example signing/verification (see below) |

**Credential pipeline is CLI-only, not a library export** in either runtime. Python keeps it as a separate package `src/python/credentials/` (`example_signer.py` signs example credentials with role-based keys + evidence VPs; `verify_signed_examples.py` verifies them). TypeScript has functionally-equivalent `story-sign.ts` / `story-verify.ts` (run via `yarn story:sign` / `yarn story:verify`, excluded from the `tsc` build). Do not try to export these as library functions.

### The Credential Lifecycle & Trust Model

The `examples/` directory is the authoritative end-to-end narrative, not just test data (full walkthrough in `examples/README.md`):

- **`examples/*.json`** — Harbour credential skeletons showing the VC envelope and nested evidence-VP structure.
- **`examples/gaiax/`** — Complete journey with 4 actors and role-based authorization via evidence VPs.
- **`examples/gaiax_external/`** — Third-party Gaia-X credentials *not* produced by our pipeline.
- **`examples/signed/`, `examples/gaiax/signed/`** — Story-pipeline output (`.jwt`, `.decoded.json`, `.evidence-vp.jwt`); **gitignored**.

The trust chain each credential's evidence VP proves:

| Actor | Identity | Role |
|-------|----------|------|
| Trust Anchor | did:ethr | Root of trust; self-signed authority |
| Signing Service | did:ethr | Issues all credentials; `#controller` key for issuance, `#delegate-1` for delegated transactions |
| Legal Person | did:ethr | Organization authorized by the Trust Anchor; authorizes employees |
| Natural Person | did:ethr | Employee, linked to the org via `memberOf` |

The role keys used for signing live in `tests/fixtures/keys/` (trust-anchor, haven, company, employee, ascs).

### Test Layout

- `tests/fixtures/` — shared `keys/`, `tokens/`, `credentials/`, `sample-vc.json`
- `tests/conftest.py` — root fixtures: session-scoped Ed25519 + P-256 keypairs, sample VC/VP
- `tests/python/credentials/conftest.py` — parametrized fixtures over `examples/` credentials + pre-signed JWTs
- `tests/python/harbour/` — per-module tests (sign, verify, keys, sd_jwt, kb_jwt, sd_jwt_vp, x509, delegation, tamper)
- `tests/python/credentials/` — pipeline + LinkML/SHACL validation tests
- `tests/typescript/harbour/` — vitest tests (config: `src/typescript/harbour/vitest.config.ts`)
- `tests/interop/` — cross-runtime tests; **auto-skip** if TS deps are unavailable
- `tests/validation-probe/` — ontology-loading probe JSON used by Makefile validation targets (not in the pytest suite)

### TypeScript Toolchain

- Package manager: **Yarn 4.13.0** via corepack — always `corepack yarn ...`, never bare `yarn`
- Test runner: **vitest** (^3.0.0); build: `tsc` (strict, ES2022); lint: `tsc --noEmit`
- Story scripts run via `tsx`; runtime dep: `jose` ^6.0.11
- Package: `@reachhaven/harbour-credentials`; barrel export is `src/typescript/harbour/index.ts`

### Submodules

Clone with `--recurse-submodules`. If already cloned: `git submodule update --init --recursive --depth 1` (both use shallow clones).

- `submodules/ontology-management-base/` — SHACL validation suite (ASCS-eV fork). **Nested inside it** is the ASCS-eV LinkML fork (`.../submodules/linkml/packages/linkml`) that `make setup` installs — `make generate` depends on it (it passes fork-only params like `normalize_prefixes`). Against stock LinkML, `make generate` fails with a `TypeError`.
- `submodules/w3id.org/` — W3ID context resolution (`.htaccess` redirects for `w3id.org/reachhaven/harbour/...` IRIs to GitHub Pages)

### LinkML → Artifacts Pipeline

`linkml/*.yaml` schemas generate `artifacts/` (OWL ontology, SHACL shapes, JSON-LD context) via `make generate` → `generate_artifacts.py`. Schemas: `harbour-core-credential` (base VC envelope, revocation, evidence, DID docs), `harbour-gx-credential` (Gaia-X layer), `harbour-core-delegation` (OID4VP transaction types; no SHACL — canonical JSON must stay un-expanded for SHA-256 hashing), `w3c-vc` (VC v2 shim).

**Revocation = CRSet model** (commit #7, breaking): a `credentialStatus` entry carries `statusServiceOperator` (bare DID), `statusIndex` (lookup key), and optional `statusId` (convenience URL for SHACL closed-shape compatibility — *not* the trust root). A verifier resolves the operator DID, discovers the `harbour:CRSetRevocationRegistryService` by type, and checks `registryEndpoint` + `statusIndex`.

### Architecture Decisions & Key Specs

ADRs in `docs/decisions/`: `001` VC securing mechanism · `002` dual-runtime architecture · `003` no canonicalization · `004` key management (ES256/P-256 + X.509 + DID) · `005` did:web → did:ethr migration.

Deep-dive docs: `docs/did-identity-system.md` (did:ethr + IdentityController), `docs/schema/credential-model.md` (LinkML hierarchy / Gaia-X composition), `docs/specs/delegation-challenge-encoding.md`, and **`docs/specs/references/`** (local copies of W3C VCDM 2.0, DID Core, OID4VP, SD-JWT, VC-JOSE-COSE — see Standards Compliance).

## Key Imports

### Python

```python
from harbour.keys import (
    generate_p256_keypair, generate_ed25519_keypair,
    p256_public_key_to_did_key, p256_public_key_to_did_ethr, p256_public_key_to_eth_address,
)
from harbour.signer import sign_vc_jose, sign_vp_jose
from harbour.verifier import verify_vc_jose, verify_vp_jose, VerificationError
from harbour.sd_jwt import issue_sd_jwt_vc, verify_sd_jwt_vc
from harbour.kb_jwt import create_kb_jwt, verify_kb_jwt
from harbour.delegation import (
    TransactionData, ChallengeError,
    create_delegation_challenge, parse_delegation_challenge, verify_challenge,
)
from harbour.sd_jwt_vp import issue_sd_jwt_vp, verify_sd_jwt_vp
from harbour.x509 import generate_self_signed_cert, validate_x5c_chain
```

### TypeScript

```typescript
import {
  generateP256Keypair, p256PublicKeyToDidKey,
  signVcJose, verifyVcJose, signVpJose,
  issueSdJwtVc, verifySdJwtVc,
  createKbJwt, verifyKbJwt,
  createDelegationChallenge, verifyChallenge, createTransactionData,
  issueSdJwtVp, verifySdJwtVp,
} from '@reachhaven/harbour-credentials';
```

> Names mirror the Python API in camelCase. Note the `*VcJose` / `*SdJwtVc` suffixes — these are the real exports (not `signJwt`/`issueSdJwt`).

## CLI Entry Points

Every harbour module has an argparse `main()` with `--help`: `python -m harbour.{keys,signer,verifier,sd_jwt,kb_jwt,delegation,sd_jwt_vp,x509,generate_artifacts} --help`. Pipeline CLIs: `python -m credentials.example_signer --help`, `python -m credentials.verify_signed_examples --help`.

## Coding Conventions

### Python

- **Python 3.12+** with type hints on public APIs; **pathlib.Path** (never `os.path`)
- Every module must have `main()` with `argparse` and `--help`
- Formatter/linter: **ruff** — line-length 88, `select = E/F/W/I`, but **`ignore = E203, E501`** (line-length is a target, not hard-enforced)
- Crypto deps: `joserfc>=1.0.0` (JOSE), `cryptography>=44` (P-256/Ed25519), `base58` (did:key), `pycryptodome`
- Coverage tracks `src/python/harbour` + `src/python/credentials`

### TypeScript

- **TypeScript 5.7+**, strict mode, ES2022 target; **async/await** for crypto; export types alongside functions

## Standards Compliance

**STRICT REQUIREMENT — schemas, examples, and models must align with the relevant W3C / IETF / Gaia-X specs.** When editing LinkML schemas, JSON-LD examples, or DID documents:

1. **Cross-reference the spec copies in `docs/specs/references/`.** LinkML files use bracketed citation tags (`[VCDM2]`, `[DID Core]`, `[OID4VP]`, `[SD-JWT]`, `[VC-CTX]`, …) pointing at specific spec sections — verify against the normative text before changing a slot range, class hierarchy, or constraint, and leave a YAML comment citing the rationale.
2. **Never use `range: Any` in LinkML** — `linkml:Any` triggers closed-shape SHACL violations. Use `uri` for identifiers or a named class for structured objects.
3. **Validate before committing** — run `make validate shacl` (and `make story`) to catch inference/closed-shape issues that CI will otherwise flag.

## Git Commit Policy

**STRICT REQUIREMENTS:**

- Always sign commits with `-s -S` (Signed-off-by + GPG signature)
- **Never include AI attribution** — no `Co-Authored-By`, `Generated-By`, or any mention of AI tools in commit messages
- Use conventional commit format (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `ci:`); a `!` marks breaking changes (e.g. `feat(linkml)!: ...`). These feed the git-cliff changelog.
- Run `make all` (or at least `make test full` + `make lint`) before committing

```bash
git commit -s -S -m "feat(harbour): add KB-JWT support"
```

### CI / Release (context)

Pushing/PR-ing to `main` runs `ci.yml` (lint + generate + validate + tests + stories, on Python 3.12/3.13 and Node 22 across Linux/macOS/Windows). Pre-commit hooks (installed by `make setup`) run ruff, JSON-LD/Turtle, and markdownlint on commit. Releases are **tag-driven**: pushing a `v*.*.*` tag (or running the Release workflow with a tag input) generates a changelog with git-cliff, publishes TypeDoc + MkDocs, and deploys w3id artifacts to GitHub Pages via `make release-artifacts`. Versions in `pyproject.toml` / `package.json` are bumped manually.

## Change Documentation

When asked to prepare a commit or PR, default to writing these gitignored files in `.playground/` first for human review. Only after **explicit human confirmation in the current session** may the agent create the signed commit, push the branch, and open the PR.

| File | Purpose |
|------|---------|
| `.playground/commit-message.md` | Conventional commit message, ready for `git commit -s -S` |
| `.playground/pr-description.md` | PR description following any existing PR template |

## Instruction Files

| Topic | File |
|-------|------|
| Agent instructions (authoritative for LinkML/standards rules) | [AGENTS.md](AGENTS.md) |
| Copilot instructions | [.github/copilot-instructions.md](.github/copilot-instructions.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| ADRs | [docs/decisions/](docs/decisions/) |

## Common Mistakes to Avoid

- Using `os.path` instead of `pathlib.Path`
- Forgetting CLI `main()` with `--help` on new Python modules
- Breaking feature parity between Python and TypeScript (add the mirror change + an interop test)
- Trying to export the credential/story pipeline (`credentials/*`, `story-*.ts`) as library functions — they are CLI-only
- Confusing `make validate` (structural pytest) with `make validate shacl` (SHACL conformance)
- Committing generated/gitignored outputs (`examples/**/signed/`, `artifacts/*`, `htmlcov/`, `.coverage`)
- Using `range: Any` in LinkML schemas, or changing a schema without checking `docs/specs/references/`
- Committing without `-s -S` signing, or adding AI attribution to a commit message
- Running pytest without `PYTHONPATH=src/python:$PYTHONPATH`
- Using different API conventions between Python and TypeScript
