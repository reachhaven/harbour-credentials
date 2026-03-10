# Architecture Overview

Harbour Credentials is a dual-runtime cryptographic library for signing
and verifying W3C Verifiable Credentials. It spans three layers:

1. **Schema layer** — LinkML definitions that produce OWL, SHACL, and JSON-LD
   context artifacts
2. **Crypto layer** — Python and TypeScript modules for key management,
   signing (VC-JOSE-COSE, SD-JWT-VC), and verification
3. **Infrastructure layer** — DID documents, revocation (CRSet), and
   Gaia-X compliance composition

## Component Diagram

```mermaid
flowchart TB
    subgraph schema["Schema Layer"]
        LM["LinkML Schemas<br/>(w3c-vc, core, gx)"]
        OWL["OWL Ontology"]
        SHACL["SHACL Shapes"]
        CTX["JSON-LD Context"]
    end

    subgraph crypto["Crypto Layer"]
        PY["Python<br/>harbour.*"]
        TS["TypeScript<br/>harbour"]
    end

    subgraph infra["Infrastructure"]
        DID["DID Documents<br/>(did:ethr, did:key)"]
        CRSET["CRSet Revocation"]
        GX["Gaia-X Compliance<br/>(gxParticipant)"]
    end

    subgraph output["Outputs"]
        JOSE["VC-JOSE-COSE<br/>(Gaia-X JWT)"]
        SDJWT["SD-JWT-VC<br/>(EUDI wallet)"]
    end

    LM --> OWL & SHACL & CTX
    CTX --> PY & TS
    PY --> JOSE & SDJWT
    TS --> JOSE & SDJWT
    DID --> PY & TS
    CRSET --> PY
    GX --> SHACL

    style schema fill:#fff3e0,stroke:#e65100
    style crypto fill:#e3f2fd,stroke:#1565c0
    style infra fill:#f3e5f5,stroke:#6a1b9a
    style output fill:#e8f5e9,stroke:#2e7d32
```

## Data Model

For the full credential type hierarchy, evidence model, Gaia-X composition
pattern, and class map, see [Credential Data Model](schema/credential-model.md).

## Package Structure

```text
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
├── linkml/                    # LinkML schemas
└── artifacts/                 # Generated OWL/SHACL/context (per domain)
```

## Signing Flow

```mermaid
sequenceDiagram
    participant I as Issuer
    participant H as Harbour Library
    participant W as Wallet

    I->>H: Credential JSON + Private Key
    H->>H: Resolve JSON-LD Context
    H->>H: Sign (ES256 / P-256)

    alt VC-JOSE-COSE
        H-->>I: JWT (compact serialisation)
    else SD-JWT-VC
        H->>H: Select disclosable claims
        H-->>I: SD-JWT (issuer + disclosures + KB-JWT)
    end

    I->>W: Deliver signed credential
    W->>H: Verify signature + resolve DID
    H->>H: Check revocation (CRSet)
    H-->>W: Verification result
```

## Architecture Decision Records

| # | Decision | Status |
|---|----------|--------|
| [001](decisions/001-vc-securing-mechanism.md) | SD-JWT-VC (EUDI) + VC-JOSE-COSE (Gaia-X) — dual format | Accepted |
| [002](decisions/002-dual-runtime-architecture.md) | Dual Python/JavaScript runtime | Accepted |
| [003](decisions/003-canonicalization.md) | No canonicalization required | Accepted |
| [004](decisions/004-key-management.md) | ES256 (P-256) primary + X.509 + DID | Accepted |
| [005](decisions/005-did-ethr-migration.md) | did:ethr migration to Base L2 | Accepted |

## Format Relationship

```text
LinkML Schema → JSON-LD Context + SHACL (schema validation)
                       │
          ┌────────────┼────────────┐
          ▼            ▼            ▼
    JSON-LD VCs    VC-JOSE-COSE   SD-JWT-VC
    (examples)     (Gaia-X JWT)  (EUDI wallet)
```

The schema validation layer (SHACL/JSON-LD) validates the attribute design.
The signing layer (JWT/SD-JWT) secures the credential for transport.
Both layers use the same attribute definitions, different serialisations.
