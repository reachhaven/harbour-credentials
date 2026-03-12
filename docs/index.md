# Harbour Credentials

**Harbour Credentials** is a cryptographic library for signing and verifying verifiable credentials. It provides dual-runtime support for both Python and TypeScript with feature parity.

## Features

- 🔑 **Key Management** — P-256 and Ed25519 key generation with DID:key encoding
- ✍️ **JWT Signing** — VC-JOSE-COSE compliant JWT signing (ES256, EdDSA)
- ✅ **Verification** — Signature verification with tamper detection
- 🎭 **SD-JWT** — Selective Disclosure JWT for privacy-preserving credentials
- 🔐 **KB-JWT** — Key Binding JWT for holder binding
- 📜 **X.509** — Certificate generation and chain validation

## Quick Start

**Python:**

```python
from harbour.keys import generate_p256_keypair, p256_public_key_to_did_key
from harbour.signer import sign_vc_jose
from harbour.verifier import verify_vc_jose

# Generate keypair
private_key, public_key = generate_p256_keypair()
did = p256_public_key_to_did_key(public_key)

# Sign a credential
credential = {"type": ["VerifiableCredential"], "issuer": did, ...}
jwt = sign_vc_jose(credential, private_key)

# Verify
result = verify_vc_jose(jwt, public_key)
```

**TypeScript:**

```typescript
import { generateP256Keypair, p256PublicKeyToDid, signJwt, verifyJwt } from '@reachhaven/harbour-credentials';

// Generate keypair
const { privateKey, publicKey } = await generateP256Keypair();
const did = await p256PublicKeyToDid(publicKey);

// Sign a credential
const credential = { type: ['VerifiableCredential'], issuer: did, ... };
const jwt = await signJwt(credential, privateKey);

// Verify
const result = await verifyJwt(jwt, publicKey);
```

## Installation

**Python:**

```bash
pip install harbour-credentials
```

**TypeScript:**

```bash
npm install @reachhaven/harbour-credentials
```

## Documentation

- [Installation](getting-started/installation.md) — Detailed setup instructions
- [Quick Start](getting-started/quickstart.md) — Get up and running
- [CLI Reference](cli/index.md) — Command-line tools
- [API Reference](api/python/index.md) — Python and TypeScript APIs
- [DID Method Evaluation](specs/did-method-evaluation.md) — `did:ethr` modeling notes and local reference specs
