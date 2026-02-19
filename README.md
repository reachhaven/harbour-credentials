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

## Installation

### Python

```bash
pip install harbour-credentials
```

Or for development:

```bash
git clone https://github.com/reachhaven/harbour-credentials.git
cd harbour-credentials
make setup
source .venv/bin/activate
```

### TypeScript/JavaScript

```bash
npm install @reachhaven/harbour-credentials
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
import { generateP256Keypair, signVcJose, verifyVcJose } from '@reachhaven/harbour-credentials';

// Generate a P-256 keypair
const { privateKey, publicKey } = await generateP256Keypair();

// Sign a Verifiable Credential
const vc = {
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential"],
  "issuer": "did:web:example.com",
  "credentialSubject": { "id": "did:example:holder", "name": "Alice" }
};
const jwt = await signVcJose(vc, privateKey);

// Verify the credential
const payload = await verifyVcJose(jwt, publicKey);
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
```

## Testing

```bash
# Python tests
make test

# TypeScript tests
make test-ts

# All tests
make test-all

# Python with coverage
make test-cov
```

## Documentation

- [Architecture Decision Records](docs/decisions/)
- [API Documentation](docs/README.md)

## License

MPL-2.0