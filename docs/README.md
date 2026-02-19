# Harbour Credentials — Design Documentation

## Package Structure (Current)

```
harbour-credentials/
├── src/
│   ├── python/
│   │   ├── harbour/           # Crypto library (6 modules)
│   │   └── credentials/       # LinkML pipeline (3 modules)
│   └── typescript/
│       └── harbour/           # Crypto library (6 modules)
├── tests/
│   ├── *.py                   # Python tests (76 tests)
│   └── typescript/harbour/    # TypeScript tests (36 tests)
├── linkml/                    # LinkML schemas
└── artifacts/                 # Generated OWL/SHACL/context
```

## Architecture Decision Records

| # | Decision | Status |
|---|----------|--------|
| [001](decisions/001-vc-securing-mechanism.md) | SD-JWT-VC (EUDI) + VC-JOSE-COSE (Gaia-X) — dual format | Accepted |
| [002](decisions/002-dual-runtime-architecture.md) | Dual Python/JavaScript runtime | Accepted |
| [003](decisions/003-canonicalization.md) | No canonicalization required | Accepted |
| [004](decisions/004-key-management.md) | ES256 (P-256) primary + X.509 + DID | Accepted |

## Key Findings (February 2026)

The research uncovered three critical misalignments in the current implementation:

### 1. Wrong proof format
**Current:** Ed25519Signature2018 (deprecated, non-standard canonicalization)
**Required:** SD-JWT-VC (EUDI/OIDC4VP mandatory) + VC-JOSE-COSE (Gaia-X current)

### 2. Wrong algorithm
**Current:** Ed25519 / EdDSA (deprecated by RFC 9864)
**Required:** ES256 / P-256 (EUDI HAIP: "MUST, at a minimum, support ES256")

### 3. Wrong key resolution
**Current:** DID only (did:key)
**Required:** X.509 via `x5c` (EUDI HAIP mandatory) + DID (Gaia-X)

## Current State vs. Target

| Aspect | Current | Target |
|--------|---------|--------|
| Proof format | Ed25519Signature2018 (broken) | SD-JWT-VC + VC-JOSE-COSE |
| Algorithm | Ed25519 (EdDSA, deprecated) | **ES256 (P-256)** |
| Key resolution | did:key only | **X.509 (x5c)** + did:web + did:key |
| Selective disclosure | None | Native (SD-JWT-VC) |
| Canonicalization | json.dumps(sort_keys=True) | None needed (JWT/SD-JWT) |
| Runtimes | Python only | Python + JavaScript |
| EUDI compatible | No | Yes |
| Gaia-X compatible | Partially | Yes |
| OIDC4VP ready | No | Yes |

## Format Relationship

```
LinkML Schema → JSON-LD Context + SHACL (schema validation)
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    JSON-LD VCs    VC-JOSE-COSE   SD-JWT-VC
    (examples)     (Gaia-X JWT)  (EUDI wallet)
```

The schema validation layer (SHACL/JSON-LD) validates the attribute design.
The signing layer (JWT/SD-JWT) secures the credential for transport.
Both layers use the same attribute definitions, different serializations.
