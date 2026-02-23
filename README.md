# Harbour Credentials

JOSE signing and verification library for W3C Verifiable Credentials, supporting both EUDI (SD-JWT-VC) and Gaia-X (VC-JOSE-COSE) formats.

## Features

- **Dual Format Support**: SD-JWT-VC (EUDI/OIDC4VP) + VC-JOSE-COSE (Gaia-X)
- **Dual Runtime**: Python and TypeScript with feature parity
- **ES256 (P-256)**: EUDI HAIP compliant algorithm
- **EdDSA (Ed25519)**: Legacy support (deprecated per RFC 9864)
- **X.509 Support**: Certificate chains via `x5c` header
- **DID Support**: `did:key` and `did:web` resolution
- **Selective Disclosure**: Native SD-JWT-VC with disclosable claims
- **Key Binding**: KB-JWT for holder binding in presentations
- **Harbour Credential Types**: Abstraction layer over Gaia-X types with mandatory revocation support

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

> **Note:** The `--recurse-submodules` flag is required to clone the Gaia-X service-characteristics, ontology-management-base, and w3id.org submodules.
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

Harbour provides an abstraction layer over Gaia-X types with mandatory revocation support:

| Credential Type                     | Subject Type              | Wraps                |
| ----------------------------------- | ------------------------- | -------------------- |
| `harbour:LegalPersonCredential`     | `harbour:LegalPerson`     | `gx:LegalPerson`     |
| `harbour:NaturalPersonCredential`   | `harbour:NaturalPerson`   | `gx:Participant`     |
| `harbour:ServiceOfferingCredential` | `harbour:ServiceOffering` | `gx:ServiceOffering` |

All harbour credentials require:

- `validFrom` - Mandatory datetime
- `credentialStatus` - At least one `harbour:CRSetEntry` for revocation support

Example harbour credential:

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://w3id.org/reachhaven/harbour/credentials/v1/",
    "https://w3id.org/gaia-x/development#"
  ],
  "type": ["VerifiableCredential", "harbour:LegalPersonCredential"],
  "issuer": "did:web:trust-anchor.example.com",
  "validFrom": "2024-01-15T00:00:00Z",
  "credentialSubject": {
    "id": "did:web:participant.example.com",
    "type": ["harbour:LegalPerson", "gx:LegalPerson"],
    "gx:legalName": "Example Corporation GmbH"
  },
  "credentialStatus": [
    {
      "id": "did:web:issuer.example.com:revocation#abc123",
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
# 1. Generate artifacts from LinkML schemas
make generate

# 2. Navigate to the validation suite
cd submodules/ontology-management-base

# 3. Validate credential fixtures against harbour SHACL shapes
python3 -m src.tools.validators.validation_suite \
  --run check-data-conformance \
  --data-paths ../../tests/fixtures/credentials/ \
  --artifacts ../../artifacts

# 4. Validate specific credentials with harbour + gx artifacts
python3 -m src.tools.validators.validation_suite \
  --run check-data-conformance \
  --data-paths ../../tests/fixtures/credentials/harbour-legal-person-credential.json \
  --artifacts ../../artifacts ../../submodules/service-characteristics/artifacts
```

> **Note**: The validation suite uses `--data-paths` for input files and `--artifacts` for schema directories.

> **Known Issue**: SHACL and JSON-LD context generation currently fails due to relative import issues in the Gaia-X service-characteristics schema (`address.yaml` not found). The OWL ontology generates successfully (3.5MB with full Gaia-X imports).

### Quick Validation Check

For a quick structural validation without SHACL:

```bash
# Validate harbour credential requirements
python3 << 'EOF'
import json
from pathlib import Path

def validate_harbour_credential(filepath: str) -> bool:
    """Validate a harbour credential has required fields."""
    with open(filepath) as f:
        vc = json.load(f)

    # Check required fields
    has_valid_from = "validFrom" in vc
    has_status = "credentialStatus" in vc

    if has_status:
        status = vc["credentialStatus"][0]
        has_crset = status.get("type") == "harbour:CRSetEntry"
    else:
        has_crset = False

    # Check harbour abstraction types
    subject = vc.get("credentialSubject", {})
    types = subject.get("type", [])
    has_harbour_type = any("harbour:" in t for t in types)
    has_gx_type = any("gx:" in t for t in types)

    print(f"validFrom: {'✅' if has_valid_from else '❌'}")
    print(f"credentialStatus (CRSetEntry): {'✅' if has_crset else '❌'}")
    print(f"harbour abstraction type: {'✅' if has_harbour_type else '❌'}")
    print(f"gx compatibility type: {'✅' if has_gx_type else '❌'}")

    return has_valid_from and has_crset and has_harbour_type and has_gx_type

# Example usage
validate_harbour_credential("tests/fixtures/credentials/harbour-legal-person-credential.json")
EOF
```

### Run Tests

```bash
# Run all fixture validations via pytest
make test
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

# LinkML Generation (credentials module)
python -m credentials.linkml_generator linkml/*.yaml --out-root artifacts/
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
│   └── credentials/       # LinkML pipeline
│       ├── linkml_generator.py
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
├── service-characteristics/   # Gaia-X LinkML schemas (gx: prefix)
└── w3id.org/                  # W3ID context resolution

tests/
├── fixtures/                      # Shared test fixtures
│   ├── credentials/               # Harbour credential examples
│   │   ├── harbour-legal-person-credential.json
│   │   ├── harbour-natural-person-credential.json
│   │   └── harbour-service-offering-credential.json
│   ├── keys/                      # Test keypairs
│   ├── tokens/                    # Signed token fixtures
│   └── sample-vc.json             # Shared unsigned VC payload
├── interop/                       # Cross-runtime interop tests
├── python/                        # Python tests
│   ├── harbour/                   # harbour module tests
│   └── credentials/               # credentials module tests
└── typescript/harbour/            # TypeScript tests

linkml/
├── harbour.yaml           # Harbour credential schema
└── core.yaml              # Core types (id, type)

artifacts/
├── harbour/
│   ├── harbour.owl.ttl        # Generated OWL ontology
│   ├── harbour.shacl.ttl      # Generated SHACL shapes
│   └── harbour.context.jsonld # Generated JSON-LD context
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
