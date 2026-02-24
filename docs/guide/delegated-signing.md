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

```
User                    Signing Service              Blockchain
  │                           │                          │
  │  1. Request transaction   │                          │
  │  ─────────────────────►   │                          │
  │                           │                          │
  │  2. Consent request       │                          │
  │  ◄─────────────────────   │                          │
  │  (transaction details,    │                          │
  │   nonce)                  │                          │
  │                           │                          │
  │  3. Create SD-JWT VP      │                          │
  │  (consent proof with      │                          │
  │   redacted PII)           │                          │
  │  ─────────────────────►   │                          │
  │                           │                          │
  │                           │  4. Verify VP            │
  │                           │  ✓ Signature valid       │
  │                           │  ✓ Credential valid      │
  │                           │  ✓ Intent matches        │
  │                           │                          │
  │                           │  5. Execute transaction  │
  │                           │  ─────────────────────►  │
  │                           │                          │
  │                           │  6. Store VP as evidence │
  │                           │  (for audit)             │
  │                           │                          │
```

## User Setup

### 1. Harbour Credential

The user needs a Harbour credential (e.g., `NaturalPersonCredential`) issued as an **SD-JWT-VC** with disclosable claims:

```json
{
  "type": ["VerifiableCredential", "harbour:NaturalPersonCredential"],
  "issuer": "did:web:issuer.example.com",
  "credentialSubject": {
    "id": "did:web:carlo.simpulse.io",
    "type": "harbour:NaturalPerson",
    "name": "Carlo Rossi",          // ← Disclosable (PII)
    "email": "carlo@bmw.de",        // ← Disclosable (PII)
    "memberOf": "did:web:bmw.gaiax.de"
  }
}
```

### 2. DID Document

The user's DID document (`did:web:carlo.simpulse.io`) must contain a verification method with their P-256 public key:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:carlo.simpulse.io",
  "verificationMethod": [{
    "id": "did:web:carlo.simpulse.io#key-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:carlo.simpulse.io",
    "publicKeyJwk": {
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "..."
    }
  }],
  "authentication": ["did:web:carlo.simpulse.io#key-1"]
}
```

## Creating the Consent VP

When the signing service requests consent, the user creates an **SD-JWT VP** with:

1. **Selective disclosure**: Only non-PII claims disclosed
2. **Evidence**: Transaction intent proving what was consented to
3. **Signature**: Signed with the user's P-256 key

### Python Example

```python
from harbour.sd_jwt_vp import issue_sd_jwt_vp

# User's SD-JWT-VC (with all disclosures)
sd_jwt_vc = "eyJ...~disclosure1~disclosure2~..."

# Transaction intent (what the user is consenting to)
evidence = [{
    "type": "harbour:DelegatedSignatureEvidence",
    "transactionIntent": {
        "type": "harbour:TransactionIntent",
        "actionType": "purchase",
        "actionReference": "urn:uuid:tx-12345",
        "description": "Purchase 'Weather Data 2024' for €500",
        "consentTimestamp": "2024-01-15T10:30:00Z",
        "nonce": "abc123xyz"
    },
    "delegatedTo": "did:web:signing-service.harbour.io"
}]

# Create VP with selective disclosure (redact PII)
sd_jwt_vp = issue_sd_jwt_vp(
    sd_jwt_vc,
    holder_private_key,
    disclosures=["memberOf"],  # Only disclose non-PII claims
    evidence=evidence,
    nonce="abc123xyz",
    audience="did:web:signing-service.harbour.io"
)
```

### TypeScript Example

```typescript
import { issueSdJwtVp } from '@reachhaven/harbour-credentials';

const sdJwtVp = await issueSdJwtVp(sdJwtVc, holderPrivateKey, {
  disclosures: ['memberOf'],
  evidence: [{
    type: 'harbour:DelegatedSignatureEvidence',
    transactionIntent: {
      type: 'harbour:TransactionIntent',
      actionType: 'purchase',
      actionReference: 'urn:uuid:tx-12345',
      description: "Purchase 'Weather Data 2024' for €500",
      consentTimestamp: '2024-01-15T10:30:00Z',
      nonce: 'abc123xyz'
    },
    delegatedTo: 'did:web:signing-service.harbour.io'
  }],
  nonce: 'abc123xyz',
  audience: 'did:web:signing-service.harbour.io'
});
```

## Verification

The signing service verifies the VP before executing the transaction:

```python
from harbour.sd_jwt_vp import verify_sd_jwt_vp

result = verify_sd_jwt_vp(
    sd_jwt_vp,
    issuer_public_key,      # From credential issuer's DID
    holder_public_key,      # From user's DID document
    expected_nonce="abc123xyz",
    expected_audience="did:web:signing-service.harbour.io"
)

# Check transaction intent matches original request
assert result["evidence"][0]["transactionIntent"]["actionReference"] == "urn:uuid:tx-12345"

# Check credential is still valid (CRSet)
# ... revocation check ...

# All checks pass → execute transaction
```

## Privacy Model

The SD-JWT VP enables **privacy-preserving audit**:

| Data | Public Audit | Private Audit |
|------|--------------|---------------|
| Transaction intent | ✅ Visible | ✅ Visible |
| User DID | ✅ Visible | ✅ Visible |
| VP signature | ✅ Verifiable | ✅ Verifiable |
| Credential validity | ✅ Via CRSet | ✅ Via CRSet |
| User name | ❌ Redacted | ✅ Available |
| User email | ❌ Redacted | ✅ Available |

**Public audit** proves:
> "The holder of `did:web:carlo.simpulse.io` consented to transaction `tx-12345` at `2024-01-15T10:30:00Z`"

**Private audit** (with additional disclosures) proves:
> "Carlo Rossi (carlo@bmw.de), member of BMW, consented to..."

## Security Considerations

### Replay Protection

The `nonce` in `TransactionIntent` prevents replay attacks:

- Signing service generates unique nonce per request
- VP must contain matching nonce
- Nonce is single-use

### Audience Binding

The `audience` field ensures the VP was created for a specific verifier:

```python
verify_sd_jwt_vp(
    vp,
    ...,
    expected_audience="did:web:signing-service.harbour.io"
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
# Resolve DID document
did_doc = resolve_did("did:web:carlo.simpulse.io")

# Extract public key
public_key = did_doc["verificationMethod"][0]["publicKeyJwk"]

# Verify VP was signed with this key
verify_sd_jwt_vp(vp, issuer_key, public_key_from_did_doc, ...)
```

## Use Cases

### Data Marketplace

User purchases dataset through blockchain:

1. User browses marketplace, selects dataset
2. App requests consent: "Purchase 'Weather Data 2024' for €500?"
3. User creates consent VP with wallet
4. Harbour executes blockchain transaction
5. VP stored as purchase receipt/evidence

### Contract Signing

User signs legal contract:

1. Contract platform prepares document
2. Requests signature: "Sign employment contract with BMW?"
3. User creates consent VP
4. Harbour records signature on blockchain
5. VP serves as proof of signing intent

### Access Delegation

User grants access to resource:

1. Service requests access: "Grant read access to Project X?"
2. User creates consent VP
3. Harbour updates access control on blockchain
4. VP serves as access grant evidence

## Related Documentation

- [Evidence Types](evidence.md) — All Harbour evidence types
- [SD-JWT-VC](../api/python/index.md) — SD-JWT credential issuance
- [ADR-001: VC Securing Mechanism](../decisions/001-vc-securing-mechanism.md) — Why SD-JWT
- [ADR-004: Key Management](../decisions/004-key-management.md) — P-256 keys
