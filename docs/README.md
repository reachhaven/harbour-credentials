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
│   ├── fixtures/              # Shared fixtures (credentials, keys, tokens)
│   ├── interop/               # Cross-runtime interoperability tests
│   ├── python/                # Python tests (harbour + credentials)
│   └── typescript/harbour/    # TypeScript tests
├── linkml/                    # LinkML schemas (harbour.yaml, core.yaml, gaiax-domain.yaml)
└── artifacts/                 # Generated OWL/SHACL/context (per domain)
```

## Architecture Decision Records

| # | Decision | Status |
|---|----------|--------|
| [001](decisions/001-vc-securing-mechanism.md) | SD-JWT-VC (EUDI) + VC-JOSE-COSE (Gaia-X) — dual format | Accepted |
| [002](decisions/002-dual-runtime-architecture.md) | Dual Python/JavaScript runtime | Accepted |
| [003](decisions/003-canonicalization.md) | No canonicalization required | Accepted |
| [004](decisions/004-key-management.md) | ES256 (P-256) primary + X.509 + DID | Accepted |

## Implementation Status

| Aspect | Status |
|--------|--------|
| Proof format | SD-JWT-VC + VC-JOSE-COSE |
| Algorithm | ES256 (P-256) primary, EdDSA (Ed25519) supported |
| Key resolution | X.509 (x5c) + did:web + did:key |
| Selective disclosure | Native (SD-JWT-VC) |
| Canonicalization | None needed (JWT/SD-JWT) |
| Runtimes | Python + TypeScript |
| EUDI compatible | Yes |
| Gaia-X compatible | Yes |
| OIDC4VP ready | Yes |

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
