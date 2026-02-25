# Harbour Delegated Signing Evidence Specification

**Version**: 2.0.0  
**Status**: Draft  
**Namespace**: `https://harbour.reachhaven.io/delegation/v2`

---

## 1. Overview

This specification defines how to bind a Verifiable Presentation (VP) to a specific transaction for delegated signing consent. The design:

- **Aligns with OpenID4VP** `transaction_data` mechanism ([OID4VP §8.4](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4))
- **Uses only W3C standard fields** — no proprietary extensions
- **Supports QR code presentation** — challenge contains hash, full data stored separately
- **Enables auditability** — transaction details can be verified against hash

### 1.1 Design Philosophy

Following the OID4VP pattern:

| Component | Purpose | Location |
|-----------|---------|----------|
| **Full transaction data** | Human review, business logic | Request body OR external reference |
| **Transaction data binding** | Cryptographic integrity | `proof.challenge` (Harbour challenge hash) + KB-JWT `transaction_data_hashes` (OID4VP hash) |
| **Verifier identity** | Trust anchor | `proof.domain` |
| **Replay protection** | Freshness | `proof.nonce` / timestamp in challenge |

This separation is critical for QR code flows where the signed proof must be compact.

---

## 2. Challenge Format

### 2.1 Structure

The `proof.challenge` field uses a compact, single-line format:

```
<nonce> HARBOUR_DELEGATE <sha256-hash>
```

Where:
- `<nonce>` is a unique identifier (hex string, min 8 chars)
- `HARBOUR_DELEGATE` is the action type identifier
- `<sha256-hash>` is the lowercase hex-encoded SHA-256 hash of the transaction data

### 2.2 Example

```
da9b1009 HARBOUR_DELEGATE c0a4f646410379520b80256ca8a9f738d7ce59c9511d24649a452d6e23ea590f
```

This format is inspired by [simpulse-id-credentials](https://github.com/ASCS-eV/simpulse-id-credentials) which uses:
```
<nonce> ISSUE_PAYLOAD <hash>
```

### 2.3 ABNF Grammar (RFC 5234)

```abnf
; ============================================================
; Harbour Delegation Challenge - ABNF Grammar
; RFC 5234 compliant
; ============================================================

; --- Top-level production ---
delegation-challenge = nonce SP action-type SP hash

; --- Components ---
nonce                = 8*16HEXDIG                     ; e.g., "da9b1009"
action-type          = "HARBOUR_DELEGATE"             ; fixed identifier
hash                 = 64HEXDIG                       ; SHA-256 (32 bytes = 64 hex chars)

; --- Core rules (RFC 5234 Appendix B.1) ---
SP                   = %x20                           ; space
HEXDIG               = DIGIT / "A" / "B" / "C" / "D" / "E" / "F"
                     / "a" / "b" / "c" / "d" / "e" / "f"
DIGIT                = %x30-39                        ; 0-9
```

---

## 3. Transaction Data Object

The full transaction details are stored separately (in the VP body, request, or external reference). The hash in the challenge is computed over this JSON object.

This structure aligns with [OID4VP §5.1 `transaction_data`](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.1) parameter.

### 3.1 Structure

```json
{
  "type": "harbour_delegate:<action>",
  "credential_ids": ["<credential-query-id>"],
  "transaction_data_hashes_alg": ["sha-256"],
  "nonce": "<nonce>",
  "iat": <unix-timestamp>,
  "exp": <unix-timestamp>,
  "txn": {
    // Action-specific transaction details
  }
}
```

### 3.2 Required Fields (OID4VP Compliant)

| Field | Type | OID4VP | Description |
|-------|------|--------|-------------|
| `type` | string | REQUIRED | Transaction data type identifier. Format: `harbour_delegate:<action>` |
| `credential_ids` | string[] | REQUIRED | References to DCQL Credential Query `id` fields that can authorize this transaction |
| `nonce` | string | Extension | Unique identifier for replay protection (same as in challenge) |
| `iat` | number | Extension | Issued-at Unix timestamp (seconds since epoch) |

### 3.3 Optional Fields

| Field | Type | Description |
|-------|------|-------------|
| `transaction_data_hashes_alg` | string[] | Hash algorithms supported. Default: `["sha-256"]` |
| `exp` | number | Expiration Unix timestamp |
| `txn` | object | Action-specific transaction details (see §3.4) |
| `description` | string | Human-readable description for consent display |

### 3.4 Transaction Details (`txn`) by Action Type

| Action Type | `txn` Fields |
|-------------|--------------|
| `harbour_delegate:blockchain.transfer` | `chain`, `contract`, `recipient`, `amount`, `token` |
| `harbour_delegate:blockchain.execute` | `chain`, `contract`, `method`, `params`, `value` |
| `harbour_delegate:data.purchase` | `asset_id`, `price`, `currency`, `marketplace` |
| `harbour_delegate:contract.sign` | `document_hash`, `document_uri`, `parties` |
| `harbour_delegate:credential.issue` | `credential_type`, `subject`, `claims` |

#### Naming Conventions and Compatibility Boundary

Different standards in this flow use different naming conventions by design:

| Layer | Source | Naming Rule |
|-------|--------|-------------|
| VC envelope/evidence terms | W3C VC Data Model | Use VC-defined terms as-is (`credentialStatus`, `validFrom`, `evidence`, etc.) |
| OID4VP protocol fields | OpenID4VP / OAuth parameters and KB-JWT profile claims | Use snake_case exactly (`transaction_data`, `credential_ids`, `transaction_data_hashes`, `transaction_data_hashes_alg`) |
| Harbour action payload (`txn`) | Harbour transaction type profile | Profile-defined keys; Harbour v1 uses snake_case action keys (for example `asset_id`) |

Important: `txn` keys are part of canonicalization and hashing. Renaming a key (for example `asset_id` to `assetId`) changes the canonical JSON and therefore changes the challenge/hash binding.

### 3.5 Example Transaction Data

```json
{
  "type": "harbour_delegate:data.purchase",
  "credential_ids": ["simpulse_id"],
  "transaction_data_hashes_alg": ["sha-256"],
  "nonce": "da9b1009",
  "iat": 1771934400,
  "exp": 1771935300,
  "description": "Purchase sensor data package from BMW",
  "txn": {
    "asset_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "price": "100",
    "currency": "ENVITED",
    "marketplace": "did:web:dataspace.envited.io"
  }
}
```

### 3.6 Computing the Hash

```python
import hashlib
import json

def compute_transaction_hash(transaction_data: dict) -> str:
    """Compute SHA-256 hash of transaction data.
    
    Uses JSON canonical form: sorted keys, no whitespace.
    """
    canonical = json.dumps(transaction_data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical.encode('utf-8')).hexdigest()
```

The resulting challenge:
```
da9b1009 HARBOUR_DELEGATE c0a4f646410379520b80256ca8a9f738d7ce59c9511d24649a452d6e23ea590f
```

---

## 4. VP Evidence Structure (W3C VC 2.0 Compliant)

The delegated consent is captured as `evidence` in a Verifiable Credential or directly as the VP. This follows the pattern from [simpulse-id-credentials](https://github.com/ASCS-eV/simpulse-id-credentials/pull/24).

### 4.1 Evidence with Embedded VP

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2"],
  "type": ["VerifiableCredential"],
  "issuer": "did:web:harbour.signing-service.example.com",
  "validFrom": "2026-02-24T12:00:00Z",
  "credentialSubject": {
    "id": "did:web:user.example.com"
  },
  "evidence": [{
    "type": ["CredentialEvidence"],
    "verifiablePresentation": {
      "@context": ["https://www.w3.org/ns/credentials/v2"],
      "type": ["VerifiablePresentation"],
      "holder": "did:web:user.example.com",
      "verifiableCredential": [
        "<SD-JWT-VC with PII redacted>"
      ],
      "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-rdfc-2019",
        "proofPurpose": "authentication",
        "challenge": "da9b1009 HARBOUR_DELEGATE c0a4f646410379520b80256ca8a9f738d7ce59c9511d24649a452d6e23ea590f",
        "domain": "did:web:harbour.signing-service.example.com",
        "verificationMethod": "did:web:user.example.com#key-1",
        "created": "2026-02-24T12:00:05Z",
        "proofValue": "z5vgFc..."
      }
    }
  }]
}
```

### 4.2 Key Fields Used (All Standard W3C)

| Field | Vocabulary | Purpose |
|-------|------------|---------|
| `evidence` | [cred:evidence](https://www.w3.org/ns/credentials#evidence) | Links VP to credential |
| `proof.challenge` | [sec:challenge](https://w3id.org/security#challenge) | Transaction hash binding |
| `proof.domain` | [sec:domain](https://w3id.org/security#domain) | Signing service identity |
| `proof.nonce` | [sec:nonce](https://w3id.org/security#nonce) | Replay protection |
| `verifiablePresentation` | [cred:VerifiablePresentation](https://www.w3.org/ns/credentials#VerifiablePresentation) | Container for consent |

### 4.3 Transaction Data Location

The full transaction data object (§3) can be stored in one of:

1. **VP `evidence[].transaction_data`** — Inline (increases VP size)
2. **External reference** — VP contains hash, full data at `ref` URL
3. **Request context** — OID4VP `transaction_data` parameter (recommended)

For auditability, the signing service MUST store the full transaction data and provide it on request.

---

## 5. OID4VP Compatibility

This specification is designed for seamless integration with [OpenID for Verifiable Presentations (OID4VP)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html).

### 5.1 Request Flow

```
┌─────────┐                    ┌─────────┐                    ┌─────────┐
│ Verifier│                    │ Wallet  │                    │ Signing │
│(Service)│                    │ (User)  │                    │ Service │
└────┬────┘                    └────┬────┘                    └────┬────┘
     │                              │                              │
     │  Authorization Request       │                              │
     │  (transaction_data param)    │                              │
     │─────────────────────────────>│                              │
     │                              │                              │
     │                              │ Display transaction          │
     │                              │ for user consent             │
     │                              │                              │
     │                              │ User approves                │
     │                              │                              │
     │  VP with KB-JWT              │                              │
     │  (transaction_data_hashes)   │                              │
     │<─────────────────────────────│                              │
     │                              │                              │
     │                              │  Execute transaction         │
     │                              │  with VP as evidence         │
     │                              │─────────────────────────────>│
     │                              │                              │
```

### 5.2 OID4VP `transaction_data` Request Parameter

```json
{
  "type": "harbour_delegate:data.purchase",
  "credential_ids": ["simpulse_id"],
  "transaction_data_hashes_alg": ["sha-256"],
  "nonce": "da9b1009",
  "iat": 1771934400,
  "txn": {
    "asset_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "price": "100",
    "currency": "ENVITED",
    "marketplace": "did:web:dataspace.envited.io"
  }
}
```

### 5.3 SD-JWT VC Key Binding JWT Response

Per OID4VP Appendix B.3.3, the KB-JWT includes:

```json
{
  "nonce": "n-0S6_WzA2Mj",
  "aud": "did:web:harbour.signing-service.example.com",
  "iat": 1709838604,
  "sd_hash": "Dy-RYwZfaaoC3inJbLslgPvMp09bH-clYP_3qbRqtW4",
  "transaction_data_hashes": ["7W0LFUTpMvb6nJK7ngamNNY0zNvxqJ-2jNXTmLzhWQE"],
  "transaction_data_hashes_alg": "sha-256"
}
```

### 5.4 Dual Support

Our challenge profile and OID4VP binding support both:

1. **OID4VP flow** — Hash in `transaction_data_hashes` (KB-JWT claim; hash over `transaction_data` request string)
2. **Direct VP flow** — Hash in `proof.challenge` (W3C proof; hash over canonical decoded object)

These are two related but distinct representations and MUST be verified according to their respective rules.

---

## 6. Verification Requirements

A verifier (signing service) MUST:

1. **Parse the challenge** — Extract nonce, action type, and hash
2. **Retrieve transaction data** — From request context, cache, or external reference
3. **Verify hash** — Recompute SHA-256 of transaction data, compare to challenge hash
4. **Check nonce uniqueness** — Reject if nonce was previously used
5. **Validate timestamp** — Transaction timestamp within acceptable window (default: 5 minutes)
6. **Verify holder identity** — VP signature matches credential subject
7. **Check credential status** — Verify credential not revoked (CRL, status list)
8. **Validate domain** — `proof.domain` matches signing service DID

---

## 7. Security Considerations

### 7.1 Replay Protection

- The `nonce` MUST be cryptographically random (min 64 bits / 8 hex chars)
- Verifiers MUST maintain a nonce registry and reject duplicates
- The transaction timestamp provides additional freshness guarantee

### 7.2 Timestamp Validation

- Accept timestamps within a configurable window (default: 5 minutes)
- Reject future timestamps beyond 1 minute clock skew allowance

### 7.3 Hash Integrity

- SHA-256 provides collision resistance
- The hash is signed as part of the VP proof
- Any modification to transaction data invalidates the hash match

### 7.4 Selective Disclosure

- SD-JWT VC allows redacting PII while maintaining signature validity
- The evidence VP can contain an SD-JWT with only non-PII claims disclosed
- This enables public audit without revealing holder identity

---

## 8. Implementation

### 8.1 Python

The implementation is in `src/python/harbour/delegation.py`:

```python
from harbour.delegation import TransactionData, create_delegation_challenge, verify_challenge

# Create OID4VP-aligned transaction data
tx = TransactionData.create(
    action="data.purchase",
    txn={
        "asset_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
        "price": "100",
        "currency": "ENVITED",
        "marketplace": "did:web:dataspace.envited.io",
    },
    credential_ids=["simpulse_id"],
)

# Create challenge: "<nonce> HARBOUR_DELEGATE <sha256-hash>"
challenge = create_delegation_challenge(tx)
print(f"Challenge: {challenge}")
print(f"Valid: {verify_challenge(challenge, tx)}")
```

### 8.2 TypeScript

The implementation is in `src/typescript/harbour/delegation.ts`:

```typescript
import {
  createTransactionData,
  createDelegationChallenge,
  verifyChallenge,
} from '@reachhaven/harbour-credentials';

// Create OID4VP-aligned transaction data
const tx = createTransactionData({
  action: 'data.purchase',
  txn: {
    asset_id: 'urn:uuid:550e8400-e29b-41d4-a716-446655440000',
    price: '100',
    currency: 'ENVITED',
    marketplace: 'did:web:dataspace.envited.io',
  },
  credentialIds: ['simpulse_id'],
});

// Create challenge: "<nonce> HARBOUR_DELEGATE <sha256-hash>"
const challenge = await createDelegationChallenge(tx);
console.log('Challenge:', challenge);
console.log('Valid:', await verifyChallenge(challenge, tx));
```

---

## 9. Human-Readable Display

Following the design philosophy of [SIWE (EIP-4361)](https://eips.ethereum.org/EIPS/eip-4361), transaction data SHOULD be rendered in a human-readable format when presented to users for consent.

### 9.1 Display Format

```
╔══════════════════════════════════════════════════════════════╗
║  Harbour Signing Service requests your authorization         ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  Action:      Purchase data asset                            ║
║  Asset:       urn:uuid:550e8400-e29b-41d4-a716-44665544...  ║
║  Amount:      100 ENVITED                                    ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║  Service:     did:web:harbour.signing-service.example.com    ║
║  Nonce:       da9b1009                                       ║
║  Time:        2026-02-24 12:00:00 UTC                        ║
╚══════════════════════════════════════════════════════════════╝
```

### 9.2 Display Requirements

Wallet/application implementations SHOULD:

1. **Show all transaction fields**: action, transaction details, service, nonce, timestamp
2. **Use human-friendly labels** (e.g., "Purchase data asset" not "data.purchase")
3. **Format timestamps** in user's local timezone with clear UTC indication
4. **Truncate long values** (e.g., UUIDs) with ellipsis, showing full value on hover/tap
5. **Show the hash** for advanced users (collapsed by default)
6. **Require explicit consent** (button click, not auto-sign)

### 9.3 Action Labels

| Action Code | Human Label |
|-------------|-------------|
| `blockchain.transfer` | Transfer tokens |
| `blockchain.approve` | Approve token spending |
| `blockchain.execute` | Execute smart contract |
| `contract.sign` | Sign contract |
| `contract.accept` | Accept agreement |
| `data.purchase` | Purchase data asset |
| `data.share` | Share data |
| `credential.issue` | Issue credential |
| `credential.present` | Present credential |

### 9.4 Python Display Renderer

```python
from harbour.delegation import TransactionData, render_transaction_display

tx = TransactionData.create(
    action="data.purchase",
    txn={"asset_id": "urn:uuid:550e8400...", "price": "100", "currency": "ENVITED"},
)
print(render_transaction_display(tx))
```

### 9.5 TypeScript Display Renderer

```typescript
import { createTransactionData, renderTransactionDisplay } from '@reachhaven/harbour-credentials';

const tx = createTransactionData({
  action: 'data.purchase',
  txn: { asset_id: 'urn:uuid:550e8400...', price: '100', currency: 'ENVITED' },
});
console.log(renderTransactionDisplay(tx));
```

---

## 10. Examples

### 10.1 Data Purchase Transaction

These examples use the shared test vectors from `tests/fixtures/canonicalization-vectors.json`.

**Transaction Data:**
```json
{
  "type": "harbour_delegate:data.purchase",
  "credential_ids": ["simpulse_id"],
  "transaction_data_hashes_alg": ["sha-256"],
  "nonce": "da9b1009",
  "iat": 1771934400,
  "txn": {
    "asset_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "price": "100",
    "currency": "ENVITED",
    "marketplace": "did:web:dataspace.envited.io"
  }
}
```

**Challenge:**
```
da9b1009 HARBOUR_DELEGATE c0a4f646410379520b80256ca8a9f738d7ce59c9511d24649a452d6e23ea590f
```

### 10.2 Blockchain Transfer Transaction

**Transaction Data:**
```json
{
  "type": "harbour_delegate:blockchain.transfer",
  "credential_ids": ["default"],
  "transaction_data_hashes_alg": ["sha-256"],
  "nonce": "ef567890",
  "iat": 1771934400,
  "txn": {
    "chain": "eip155:42793",
    "amount": "1000000000000000000",
    "recipient": "0xabcdef1234567890",
    "contract": "0x1234567890abcdef"
  }
}
```

**Challenge:**
```
ef567890 HARBOUR_DELEGATE 0736db89c15be412294f96717a3e435f89d095e7e953b1808c422252b845d4c1
```

### 10.3 Contract Signature Transaction

**Transaction Data:**
```json
{
  "type": "harbour_delegate:contract.sign",
  "credential_ids": ["org_credential"],
  "transaction_data_hashes_alg": ["sha-256"],
  "nonce": "ab12cd34",
  "iat": 1771934400,
  "exp": 1771935300,
  "description": "Sign partnership agreement",
  "txn": {
    "document_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "parties": ["did:web:alice.example", "did:web:bob.example"]
  }
}
```

**Challenge:**
```
ab12cd34 HARBOUR_DELEGATE 0863ac13bc5f15c7dfcdee71b8beea1aead4b822d0a7c03154405da4f192af08
```

---

## 11. Relationship to W3C Standards

This encoding is used within **standard W3C fields**:

| W3C Field | Purpose in This Spec |
|-----------|---------------------|
| `proof.challenge` | Contains `<nonce> HARBOUR_DELEGATE <hash>` |
| `proof.domain` | Signing service DID |
| `proof.nonce` | Additional replay protection (optional) |
| `evidence` | Contains the embedded VP with consent |

The challenge field is:

- Part of the VP proof (signed by holder)
- Universally supported by VC wallets
- Immutable once signed

---

## 12. Relationship to OpenID4VP

This specification aligns with [OID4VP Transaction Data (§8.4)](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-8.4):

| OID4VP Concept | Harbour Delegation Equivalent |
|----------------|-------------------------------|
| `transaction_data` request param | Transaction Data Object (§3) |
| `transaction_data.type` | `"harbour_delegate:<action>"` |
| `transaction_data.txn` | Action-specific transaction details |
| `transaction_data_hashes` in KB-JWT | OID4VP hash over transaction_data request string |
| `transaction_data_hashes_alg` | `"sha-256"` |

### Integration Example

OID4VP authorization request:
```json
{
  "response_type": "vp_token",
  "client_id": "did:web:signing-service.envited.io",
  "nonce": "da9b1009",
  "transaction_data": [{
    "type": "harbour_delegate:data.purchase",
    "credential_ids": ["simpulse_id"],
    "transaction_data_hashes_alg": ["sha-256"],
    "nonce": "da9b1009",
    "iat": 1771934400,
    "txn": {
      "asset_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
      "price": "100",
      "currency": "ENVITED",
      "marketplace": "did:web:dataspace.envited.io"
    }
  }]
}
```

The wallet computes the hash and includes it in the KB-JWT `transaction_data_hashes` claim.

---

## 13. Relationship to SIWE (EIP-4361)

This specification draws design inspiration from [Sign-In with Ethereum (SIWE)](https://eips.ethereum.org/EIPS/eip-4361):

| SIWE Concept | Harbour Delegation Equivalent |
|--------------|-------------------------------|
| `domain` | `proof.domain` (signing service DID) |
| `address` | Holder DID (in VP) |
| `statement` | `description` field (human-readable) |
| `uri` | Transaction reference (in `txn` object) |
| `nonce` | `nonce` field |
| `issued-at` | `iat` field (Unix timestamp) |
| `expiration-time` | `exp` field (Unix timestamp) |
| `chain-id` | Implicit in `txn` fields (e.g., `chain: "eip155:42793"`) |

**Key differences**:

1. **Wire format**: SIWE uses multiline plaintext; we use compact hash-based challenge
2. **Signature scheme**: SIWE uses EIP-191; we use VP proofs (Data Integrity / SD-JWT KB-JWT)
3. **Identity**: SIWE uses Ethereum address; we use DIDs
4. **Purpose**: SIWE is for authentication; ours is for transaction consent
5. **Data location**: SIWE puts all data in signed message; we put hash in signature, full data elsewhere

The human-readable display format (§9) provides SIWE-like UX while the wire format remains compact for QR codes.

---

## 14. Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2026-02-24 | Major revision: hash-based challenge format, OID4VP alignment |
| 1.0.0 | 2026-02-24 | Initial specification (URL query string format) |
