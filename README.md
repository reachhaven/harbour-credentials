# Harbour Credentials

JOSE signing and verification library for W3C Verifiable Credentials, supporting both EUDI (SD-JWT-VC) and Gaia-X (VC-JOSE-COSE) formats.

## Features

- **Dual Format Support**: SD-JWT-VC (EUDI/OIDC4VP) + VC-JOSE-COSE (Gaia-X)
- **Dual Runtime**: Python and TypeScript with feature parity
- **ES256 (P-256)**: EUDI HAIP compliant algorithm
- **EdDSA (Ed25519)**: Supported (deprecated per RFC 9864, use ES256 for production)
- **X.509 Support**: Certificate chains via `x5c` header
- **DID Support**: `did:key` key identifiers plus `did:web` / `did:webs` subject identifiers (resolution handled by integrators)
- **Selective Disclosure**: Native SD-JWT-VC with disclosable claims
- **Key Binding**: KB-JWT for holder binding in presentations
- **Harbour Credential Types**: Base credential framework with composition slots for Gaia-X compliance

## Installation

### Python

```bash
pip install harbour-credentials
```

Or for development:

```bash
git clone --recurse-submodules https://github.com/reachhaven/harbour-credentials.git
cd harbour-credentials
make setup
source .venv/bin/activate
```

> **Note:** The `--recurse-submodules` flag is required to clone the ontology-management-base and w3id.org submodules.
>
> `make setup` installs Python dev dependencies (`.[dev]`), LinkML, pre-commit hooks, and bootstraps TypeScript dependencies (`corepack enable` + `yarn install` in `src/typescript/harbour`).
> Use `make install-dev` only if you need to refresh an existing Python environment.

If you already cloned without submodules:

```bash
git submodule update --init --recursive --depth 1
```

### TypeScript/JavaScript

```bash
# If you already ran `make setup`, TypeScript dependencies are already bootstrapped.
# Otherwise:
make ts-bootstrap
```

## Quick Start

### Python

```python
from harbour import generate_p256_keypair, sign_vc_jose, verify_vc_jose

# Generate a P-256 keypair
private_key, public_key = generate_p256_keypair()

# Sign a Verifiable Credential
vc = {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiableCredential"],
    "issuer": "did:web:example.com",
    "credentialSubject": {"id": "did:example:holder", "name": "Alice"}
}
jwt = sign_vc_jose(vc, private_key)

# Verify the credential
payload = verify_vc_jose(jwt, public_key)
```

### TypeScript

```typescript
import {
  generateP256Keypair,
  signVcJose,
  verifyVcJose,
} from "@reachhaven/harbour-credentials";

// Generate a P-256 keypair
const { privateKey, publicKey } = await generateP256Keypair();

// Sign a Verifiable Credential
const vc = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  type: ["VerifiableCredential"],
  issuer: "did:web:example.com",
  credentialSubject: { id: "did:example:holder", name: "Alice" },
};
const jwt = await signVcJose(vc, privateKey);

// Verify the credential
const payload = await verifyVcJose(jwt, publicKey);
```

## Harbour Credential Types

Harbour provides a base credential framework (`harbour.yaml`) with **skeleton credentials** that define the minimum required structure. A Gaia-X domain layer (`gaiax-domain.yaml`) extends the skeletons with participant types using a **composition pattern**:

| Credential Type                     | Subject Type              | Composition Slot      | Gaia-X Inner Type     |
| ----------------------------------- | ------------------------- | --------------------- | --------------------- |
| `harbour:LegalPersonCredential`     | `harbour:LegalPerson`     | `gxParticipant`       | `gx:LegalPerson`     |
| `harbour:NaturalPersonCredential`   | `harbour:NaturalPerson`   | `gxParticipant`       | `gx:Participant`     |


All harbour credentials require:

- `issuer` - DID of the credential issuer
- `validFrom` - Mandatory datetime
- `credentialStatus` - At least one `harbour:CRSetEntry` for revocation support

Base skeleton examples live in `examples/` (no Gaia-X data). Gaia-X domain extensions with `gxParticipant` live in `examples/gaiax/`. The composition pattern keeps harbour properties on the harbour-typed outer node and Gaia-X properties on a gx-typed inner blank node, so both harbour and Gaia-X SHACL shapes validate independently:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/gaia-x/development#",
    "https://w3id.org/reachhaven/harbour/credentials/v1/"
  ],
  "type": ["VerifiableCredential", "harbour:LegalPersonCredential"],
  "issuer": "did:webs:reachhaven.com:ENVSnGVU_q39C0Lsim8CtXP_c0TbQW7BBndLVnBeDPXo",
  "validFrom": "2024-01-15T00:00:00Z",
  "credentialSubject": {
    "id": "did:webs:participants.harbour.reachhaven.com:legal-persons:0aa6d7ea-27ef-416f-abf8-9cb634884e66:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "type": "harbour:LegalPerson",
    "name": "Example Corporation GmbH",
    "gxParticipant": {
      "type": "gx:LegalPerson",
      "gx:legalName": "Example Corporation GmbH",
      "gx:registrationNumber": "DE123456789",
      "gx:headquartersAddress": {
        "type": "gx:Address",
        "gx:countryCode": "DE"
      },
      "gx:legalAddress": {
        "type": "gx:Address",
        "gx:countryCode": "DE"
      }
    }
  },
  "credentialStatus": [
    {
      "id": "did:webs:reachhaven.com:ENVSnGVU_q39C0Lsim8CtXP_c0TbQW7BBndLVnBeDPXo:services:revocation-registry#abc123",
      "type": "harbour:CRSetEntry",
      "statusPurpose": "revocation"
    }
  ]
}
```

## Validating Credentials

### Using the Validation Suite

Validate harbour credentials against SHACL shapes using the ontology-management-base validation suite:

```bash
# Generate artifacts from LinkML schemas
make generate

# Validate examples against SHACL shapes (harbour + gx)
make validate-shacl

# Run structural validation tests
make validate
```

### Run Tests

```bash
# Run Python tests only
make test

# Run full pipeline (Python + SHACL conformance via validation_suite.py + TypeScript)
make test-all
```

## CLI Usage

All Python modules have CLI entry points:

```bash
# Key management
python -m harbour.keys generate --algorithm ES256 --output key.jwk
python -m harbour.keys convert --input key.jwk --format did-key

# Signing
python -m harbour.signer sign-vc --credential vc.json --key key.jwk

# Verification
python -m harbour.verifier verify-vc --jwt vc.jwt --public-key key.jwk

# SD-JWT-VC
python -m harbour.sd_jwt issue --claims claims.json --key key.jwk --vct https://example.com/vc
python -m harbour.sd_jwt verify --sd-jwt token.txt --public-key key.jwk

# X.509 Certificates
python -m harbour.x509 generate --key key.jwk --subject "Test Issuer" --output cert.pem

```

## Package Structure

```
src/
├── python/
│   ├── harbour/           # Crypto library
│   │   ├── keys.py        # Key generation, JWK, DID:key
│   │   ├── signer.py      # VC/VP signing
│   │   ├── verifier.py    # VC/VP verification
│   │   ├── sd_jwt.py      # SD-JWT-VC issue/verify
│   │   ├── kb_jwt.py      # Key Binding JWT
│   │   └── x509.py        # X.509 certificates
│   └── credentials/       # Credential processing pipeline
│       ├── claim_mapping.py
│       └── example_signer.py
└── typescript/
    └── harbour/           # Crypto library (feature parity)
        ├── keys.ts
        ├── signer.ts
        ├── verifier.ts
        ├── sd-jwt.ts
        └── x509.ts

submodules/
├── ontology-management-base/  # Validation pipeline, SHACL tools
└── w3id.org/                  # W3ID context resolution

examples/
├── legal-person-credential.json       # Harbour skeleton credentials
├── natural-person-credential.json     # (canonical unsigned JSON-LD)
├── gaiax/                             # Gaia-X domain extensions
└── did-webs/                          # Example did:webs DID documents used by examples

tests/
├── fixtures/                      # Shared test fixtures
│   ├── keys/                      # Test keypairs
│   ├── tokens/                    # Signed token fixtures
│   └── sample-vc.json             # Shared unsigned VC payload
├── interop/                       # Cross-runtime interop tests
├── python/                        # Python tests
│   ├── harbour/                   # harbour module tests
│   └── credentials/               # credentials module tests
└── typescript/harbour/            # TypeScript tests

linkml/
├── core.yaml              # Core types (id, type)
├── harbour.yaml           # Harbour base credential framework
└── gaiax-domain.yaml      # Gaia-X domain layer (participant/service types)

artifacts/                 # Generated per domain (make generate)
├── harbour/               # Base OWL/SHACL/context
├── gaiax-domain/          # Domain OWL/SHACL/context
└── core/
```

## Testing

```bash
# Python tests
make test

# TypeScript tests
cd src/typescript/harbour && yarn test

# Cross-runtime interop tests
PYTHONPATH=src/python:$PYTHONPATH pytest tests/interop/test_cross_runtime.py -v

# All tests with coverage
make test-cov

# Lint
make lint
```

## Documentation

- [Architecture Decision Records](docs/decisions/)
- [API Documentation](docs/README.md)

## License

EPL-2.0
