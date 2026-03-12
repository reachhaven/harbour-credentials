# Delegated Signing

Harbour's delegated signing feature enables users to authorize blockchain transactions through **any** VC wallet, with a signing service executing on their behalf. This decouples wallet choice from blockchain capability.

## Problem

Traditional blockchain transactions require a wallet that can both:

1. Hold Verifiable Credentials (for identity)
2. Sign blockchain transactions (for execution)

Currently, only specialized wallets (like Altme) offer both capabilities. This creates vendor lock-in and limits user choice.

## Solution

Harbour separates these concerns:

- **User's wallet**: Holds credentials, creates consent proofs (VPs)
- **Harbour signing service**: Executes blockchain transactions on behalf of users

The key innovation is **cryptographic proof of consent** — the user's VP serves as auditable evidence that they authorized the transaction.

## How It Works

```text
User                    Signing Service              Blockchain
  |                           |                          |
  |  1. Request transaction   |                          |
  |  ─────────────────────►   |                          |
  |                           |                          |
  |  2. Consent request       |                          |
  |  ◄─────────────────────   |                          |
  |  (OID4VP transaction_data,|                          |
  |   nonce, audience)        |                          |
  |                           |                          |
  |  3. Create SD-JWT VP      |                          |
  |  (consent proof with      |                          |
  |   KB-JWT binding to       |                          |
  |   transaction_data_hash)  |                          |
  |  ─────────────────────►   |                          |
  |                           |                          |
  |                           |  4. Verify VP            |
  |                           |  ✓ Signature valid       |
  |                           |  ✓ Credential valid      |
  |                           |  ✓ Transaction matches   |
  |                           |                          |
  |                           |  5. Execute transaction  |
  |                           |  ─────────────────────►  |
  |                           |                          |
  |                           |  6. Issue receipt VC     |
  |                           |  (DelegatedSignature-    |
  |                           |   Evidence + CRSet)      |
  |                           |                          |
```

## User Setup

### 1. Harbour Credential

The user needs a Harbour credential (e.g., `NaturalPersonCredential`) issued as an **SD-JWT-VC** with disclosable claims:

```json
{
  "type": ["VerifiableCredential", "harbour:NaturalPersonCredential"],
  "issuer": "did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697",
  "credentialSubject": {
    "id": "did:ethr:0x14a34:0x26e4...16c9",
    "type": "harbour:NaturalPerson",
    "name": "Alice Smith",                // ← Disclosable (PII)
    "email": "alice.smith@example.com",   // ← Disclosable (PII)
    "memberOf": "did:ethr:0x14a34:0xf7ef...dab"
  }
}
```

### 2. DID Document

The user's `did:ethr` DID document must expose the same P-256 public key as a
local `#controller` verification method:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "JsonWebKey": "https://w3id.org/security#JsonWebKey",
      "publicKeyJwk": {
        "@id": "https://w3id.org/security#publicKeyJwk",
        "@type": "@json"
      }
    }
  ],
  "id": "did:ethr:0x14a34:0x26e4...16c9",
  "verificationMethod": [
    {
      "id": "did:ethr:0x14a34:0x26e4...16c9#controller",
      "type": "JsonWebKey",
      "controller": "did:ethr:0x14a34:0x26e4...16c9",
      "publicKeyJwk": {
        "kty": "EC",
        "crv": "P-256",
        "x": "...",
        "y": "..."
      }
    }
  ],
  "authentication": [
    "did:ethr:0x14a34:0x26e4...16c9#controller"
  ],
  "assertionMethod": [
    "did:ethr:0x14a34:0x26e4...16c9#controller"
  ]
}
```

See [`examples/did-ethr/`](../../examples/did-ethr/) for complete DID documents.

### Repository Boundary (did:ethr)

This repository verifies signatures and hash bindings, but it does **not** host or publish DID documents.

- Integrators must run the appropriate `did:ethr` resolver for their Base deployment.
- Integrators must pass the resolved holder key into `verify_sd_jwt_vp(...)`.
- Repository examples now use `did:ethr` identifiers for person subjects. See `examples/did-ethr/` for static example DID documents used by `examples/*.json`.
- Naming policy in examples:
  - All identifiers use UUID-based path segments (no real names or organization names in DID paths).

Current integration hooks and TODOs:

- `issue_sd_jwt_vp(..., holder_did=...)` allows the wallet DID to be embedded in the consent VP.
- `verify_sd_jwt_vp(..., holder_public_key=...)` accepts the DID-resolved public key from your resolver stack.
- TODO: Add optional resolver callback adapters for `did:ethr` so verification can resolve custom P-256 controller keys in-process.

## OID4VP Transaction Data

The signing service creates an OID4VP-aligned transaction data object (see [Delegation Challenge Encoding](../specs/delegation-challenge-encoding.md)):

```json
{
  "type": "harbour_delegate:data.purchase",
  "credential_ids": ["harbour_natural_person"],
  "transaction_data_hashes_alg": ["sha-256"],
  "nonce": "da9b1009",
  "iat": 1771934400,
  "txn": {
    "asset_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "price": "100",
    "currency": "ENVITED",
    "marketplace": "did:ethr:0x14a34:0x89fe5e7f506d992f76bcba309773c0ee3ee6039c"
  }
}
```

Naming note:

- `transaction_data` and `credential_ids` are OID4VP-defined snake_case fields.
- `txn` is profile-defined payload; Harbour v1 standardizes snake_case keys such as `asset_id`.

## Creating the Consent VP

When the signing service requests consent, the user creates an **SD-JWT VP** with:

1. **Selective disclosure**: Only non-PII claims disclosed
2. **Evidence**: Transaction data proving what was consented to
3. **KB-JWT**: Bound to the transaction data hash
4. **Signature**: Signed with the user's P-256 key

### Python Example

```python
from harbour.sd_jwt_vp import issue_sd_jwt_vp

# User's SD-JWT-VC (with all disclosures)
sd_jwt_vc = "eyJ...~disclosure1~disclosure2~..."

# Transaction evidence (OID4VP-aligned)
evidence = [{
    "type": "DelegatedSignatureEvidence",
    "transaction_data": {
        "type": "harbour_delegate:data.purchase",
        "credential_ids": ["harbour_natural_person"],
        "nonce": "da9b1009",
        "iat": 1771934400,
        "txn": {
            "asset_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
            "price": "100",
            "currency": "ENVITED"
        }
    },
    "delegatedTo": "did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697"
}]

# Create VP with selective disclosure (redact PII)
sd_jwt_vp = issue_sd_jwt_vp(
    sd_jwt_vc,
    holder_private_key,
    disclosures=["memberOf"],  # Only disclose non-PII claims
    evidence=evidence,
    nonce="da9b1009",
    audience="did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697"
)
```

### TypeScript Example

```typescript
import { issueSdJwtVp } from '@reachhaven/harbour-credentials';

const sdJwtVp = await issueSdJwtVp(sdJwtVc, holderPrivateKey, {
  disclosures: ['memberOf'],
  evidence: [{
    type: 'DelegatedSignatureEvidence',
    transaction_data: {
      type: 'harbour_delegate:data.purchase',
      credential_ids: ['harbour_natural_person'],
      nonce: 'da9b1009',
      iat: 1771934400,
      txn: {
        asset_id: 'urn:uuid:550e8400-e29b-41d4-a716-446655440000',
        price: '100',
        currency: 'ENVITED'
      }
    },
    delegatedTo: 'did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697'
  }],
  nonce: 'da9b1009',
  audience: 'did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697'
});
```

`issue_sd_jwt_vp` / `issueSdJwtVp` derives the delegation challenge (`<nonce> HARBOUR_DELEGATE <sha256(canonical(transaction_data))>`) and writes it to `evidence[].challenge`. It also computes the OID4VP `transaction_data_hashes` value (base64url(SHA-256(transaction_data request string))) and binds/verifies that in KB-JWT on `verify_sd_jwt_vp` / `verifySdJwtVp`.

## Verification

The signing service verifies the VP before executing the transaction:

```python
from harbour.sd_jwt_vp import verify_sd_jwt_vp

result = verify_sd_jwt_vp(
    sd_jwt_vp,
    issuer_public_key,      # From credential issuer's DID
    holder_public_key,      # From user's DID document
    expected_nonce="da9b1009",
    expected_audience="did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697"
)

# Check transaction data matches original request
tx = result["evidence"][0]["transaction_data"]
assert tx["type"] == "harbour_delegate:data.purchase"
assert tx["txn"]["asset_id"] == "urn:uuid:550e8400-e29b-41d4-a716-446655440000"

# Check credential is still valid (CRSet)
# ... revocation check ...

# All checks pass -> execute transaction
```

## Receipt Credential

After executing the transaction, the signing service issues a **receipt credential** (SD-JWT-VC) with `DelegatedSignatureEvidence`:

```json
{
  "type": ["VerifiableCredential", "harbour:DelegatedSigningReceipt"],
  "issuer": "did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697",
  "evidence": [{
    "type": "harbour:DelegatedSignatureEvidence",
    "verifiablePresentation": "<consent VP with PII redacted>",
    "delegatedTo": "did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697",
    "transaction_data": { "..." }
  }],
  "credentialStatus": [{
    "type": "harbour:CRSetEntry",
    "statusPurpose": "revocation"
  }]
}
```

The receipt credential enables three-layer privacy via selective disclosure (see [Evidence](evidence.md#three-layer-privacy-model)).

## Privacy Model

The SD-JWT VP enables **three-layer privacy-preserving audit**:

| Data | Layer 1 (Public) | Layer 2 (Authorized) | Layer 3 (Full Audit) |
|------|:-:|:-:|:-:|
| CRSet entry (credential exists) | Yes | Yes | Yes |
| Transaction data hash on-chain | Yes | Yes | Yes |
| KB-JWT signature valid | Yes | Yes | Yes |
| Transaction details (asset, price) | No | Yes | Yes |
| Consent VP hash verification | No | Yes | Yes |
| User name | No | No | Yes |
| User email | No | No | Yes |

## Security Considerations

### Replay Protection

The `nonce` in transaction data prevents replay attacks:

- Signing service generates unique nonce per request
- VP must contain matching nonce in KB-JWT
- Nonce is single-use

### Audience Binding

The `audience` field ensures the VP was created for a specific verifier:

```python
verify_sd_jwt_vp(
    vp,
    ...,
    expected_audience="did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697"
)
```

### Revocation Checking

Before executing, verify the credential hasn't been revoked:

```python
# Check CRSet entry
crset_entry = result["credential"]["credentialStatus"][0]
is_revoked = check_crset(crset_entry["id"])
if is_revoked:
    raise Error("Credential has been revoked")
```

### DID Document Verification

Verify the VP signature matches the public key in the user's DID document:

```python
# Resolve DID document (integrator-provided resolver)
did_doc = resolve_did("did:ethr:0x14a34:0x26e4...16c9")

# Extract public key
public_key = did_doc["verificationMethod"][0]["publicKeyJwk"]

# Verify VP was signed with this key
verify_sd_jwt_vp(vp, issuer_key, public_key_from_did_doc, ...)
```

## Use Cases

### Data Marketplace

User purchases dataset through blockchain:

1. User browses marketplace, selects dataset
2. App creates OID4VP transaction data: "Purchase 'Weather Data 2024' for 100 ENVITED"
3. User creates consent VP with wallet
4. Harbour executes blockchain transaction
5. Receipt credential issued with `DelegatedSignatureEvidence`

### Contract Signing

User signs legal contract:

1. Contract platform prepares document
2. Creates transaction data: `harbour_delegate:contract.sign`
3. User creates consent VP
4. Harbour records signature on blockchain
5. Receipt VP serves as proof of signing intent

### Access Delegation

User grants access to resource:

1. Service creates transaction data: `harbour_delegate:data.access`
2. User creates consent VP
3. Harbour updates access control on blockchain
4. Receipt VP serves as access grant evidence

## Related Documentation

- [Evidence Types](evidence.md) — All Harbour evidence types
- [Delegation Challenge Encoding](../specs/delegation-challenge-encoding.md) — OID4VP transaction data spec
- [SD-JWT-VC](../api/python/index.md) — SD-JWT credential issuance
- [ADR-001: VC Securing Mechanism](../decisions/001-vc-securing-mechanism.md) — Why SD-JWT
- [ADR-004: Key Management](../decisions/004-key-management.md) — P-256 keys
