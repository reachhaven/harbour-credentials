# ADR-002: Dual Python/JavaScript Runtime Architecture

**Status:** Proposed
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
│   └── harbour/              # Python implementation
│       ├── __init__.py
│       └── jose/
│           ├── keys.py       # Ed25519 key management, did:key, JWK
│           ├── signer.py     # VC-JOSE-COSE signing
│           └── verifier.py   # VC-JOSE-COSE verification
├── js/
│   ├── package.json          # npm jose dependency
│   ├── tsconfig.json
│   └── src/
│       ├── keys.ts           # Ed25519 key management, did:key, JWK
│       ├── signer.ts         # VC-JOSE-COSE signing
│       └── verifier.ts       # VC-JOSE-COSE verification
├── tests/
│   ├── test_keys.py          # Python key tests
│   ├── test_sign.py          # Python sign tests
│   ├── test_verify.py        # Python verify tests
│   └── interop/test_cross_runtime.py  # Cross-runtime interop (Python signs, calls JS to verify)
├── js/tests/
│   ├── keys.test.ts          # JS key tests
│   ├── sign.test.ts          # JS sign tests
│   ├── verify.test.ts        # JS verify tests
│   └── interop.test.ts       # Cross-runtime interop (JS signs, calls Python to verify)
├── tests/fixtures/
│   ├── keys/test-keypair.json          # Shared Ed25519 JWK (used by both runtimes)
│   ├── tokens/signed-vc-p256.jwt       # Reference JWT signed by Python
│   └── sample-vc.json        # Unsigned VC payload
└── docs/
```

### Interoperability Contract

The interop guarantee is enforced by **shared test fixtures**:

1. `tests/fixtures/keys/test-keypair.json` — Same Ed25519 JWK loaded by both runtimes
2. `tests/fixtures/sample-vc.json` — Same unsigned VC payload
3. `tests/fixtures/tokens/signed-vc-p256.jwt` — Reference signed JWT (committed, deterministic)

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

### Not Decided Yet
- **npm package name** — `@reachhaven/harbour-credentials` or `harbour-credentials`
- **JS test framework** — vitest (recommended, fast, ESM-native) or jest
- **Monorepo tooling** — whether to use npm workspaces or keep it flat
