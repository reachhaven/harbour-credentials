# ADR-002: Dual Python/JavaScript Runtime Architecture

**Status:** Accepted
**Date:** 2026-02-17
**Depends on:** [ADR-001](001-vc-securing-mechanism.md) (VC-JOSE-COSE)

## Context

Harbour-credentials serves two audiences:

1. **Backend/ontology developers** working in Python (LinkML schemas, SHACL validation, ontology management)
2. **Web developers** working in TypeScript/JavaScript (wallet integrations, credential issuance APIs, browser-based verification)

Both groups need to sign and verify the same credentials. If the Python implementation produces something the JavaScript side can't verify (or vice versa), the system is broken.

## Decision

**Maintain both a Python and a JavaScript implementation of the signing/verification flow in the same repository, with shared test vectors that prove cross-runtime interoperability.**

### Repository Structure

```
harbour-credentials/
├── src/
│   ├── python/
│   │   ├── harbour/           # Python crypto library
│   │   │   ├── keys.py        # Key generation (P-256, Ed25519), DID:key, JWK
│   │   │   ├── signer.py      # VC-JOSE-COSE signing
│   │   │   ├── verifier.py    # VC-JOSE-COSE verification
│   │   │   ├── sd_jwt.py      # SD-JWT-VC selective disclosure
│   │   │   ├── kb_jwt.py      # Key Binding JWT
│   │   │   └── x509.py        # X.509 certificates
│   │   └── credentials/       # Credential processing pipeline
│   └── typescript/
│       └── harbour/           # TypeScript crypto library (feature parity)
│           ├── keys.ts
│           ├── sign.ts
│           ├── verify.ts
│           ├── sd-jwt.ts
│           └── x509.ts
├── tests/
│   ├── fixtures/
│   │   ├── keys/              # Shared test keypairs (P-256, Ed25519)
│   │   ├── tokens/            # Signed token fixtures
│   │   └── sample-vc.json     # Unsigned VC payload
│   ├── python/harbour/        # Python harbour module tests
│   ├── python/credentials/    # Python credentials module tests
│   ├── typescript/harbour/    # TypeScript tests (vitest)
│   └── interop/               # Cross-runtime interop tests
├── linkml/                    # LinkML schemas (harbour.yaml, core.yaml, gaiax-domain.yaml)
├── artifacts/                 # Generated OWL/SHACL/JSON-LD context
└── docs/
```

### Interoperability Contract

The interop guarantee is enforced by **shared test fixtures**:

1. `tests/fixtures/keys/test-keypair-p256.json` — Same P-256 JWK loaded by both runtimes
2. `tests/fixtures/keys/test-keypair.json` — Same Ed25519 JWK loaded by both runtimes
3. `tests/fixtures/sample-vc.json` — Same unsigned VC payload
4. `tests/fixtures/tokens/signed-vc-p256.jwt` — Reference signed JWT (committed, deterministic)

**Interop test pattern:**
```
Python signs sample-vc.json → JWT string → JavaScript verifies ✓
JavaScript signs sample-vc.json → JWT string → Python verifies ✓
Both produce identical JWT for same input + key ✓
```

Because VC-JOSE-COSE uses standard JWT (ADR-001), this interoperability is guaranteed by the JOSE specifications. The shared test fixtures serve as a regression safety net.

### CI Pipeline

```yaml
jobs:
  lint:         # black, isort, flake8, eslint, prettier
  test-python:  # pytest tests/
  test-js:      # npm test (vitest or jest)
  test-interop: # Cross-runtime verification
```

The interop job:
1. Installs both Python and Node.js
2. Python signs → writes JWT to stdout → Node.js reads and verifies
3. Node.js signs → writes JWT to stdout → Python reads and verifies
4. Compares outputs for determinism

### Why Both in One Repository

- **Single source of truth** for the signing contract
- **Shared test fixtures** ensure both implementations stay in sync
- **Atomic changes** — a schema change updates both implementations in one PR
- **harbour-credentials is a library**, not an application. Consumers pick their runtime.

## Consequences

### Positive
- Web developers can `npm install` the JS package and sign/verify immediately
- Python developers can `pip install` the Python package
- Cross-runtime bugs are caught by CI, not in production
- Proves the format is truly standard (if two independent implementations agree, it works)

### Negative
- Repository needs both Python and Node.js tooling
- CI pipeline is more complex (two runtimes)
- Contributors need familiarity with both ecosystems (or can focus on one)

### Decided Since Initial Proposal
- **npm package name** — `@reachhaven/harbour-credentials`
- **JS test framework** — vitest (fast, ESM-native)
- **Package manager** — Yarn 4 via corepack
- **TS source location** — `src/typescript/harbour/` (flat, no monorepo tooling)
