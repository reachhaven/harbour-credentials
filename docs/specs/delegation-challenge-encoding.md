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
| **Transaction data hash** | Cryptographic binding | `proof.challenge` (signed by holder) |
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
da9b1009 HARBOUR_DELEGATE d0450062b3c4c9168ac8266f0806d62f5d95ed96894d5a9a0aaddf4298317eaa
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
| `harbour_delegate:data.purchase` | `assetId`, `price`, `currency`, `marketplace` |
| `harbour_delegate:contract.sign` | `documentHash`, `documentUri`, `parties` |
| `harbour_delegate:credential.issue` | `credentialType`, `subject`, `claims` |

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
    "assetId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "price": "100",
    "currency": "ENVITED",
    "marketplace": "did:web:dataspace.envited.io"
  }
}
```

### 3.5 Computing the Hash

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
da9b1009 HARBOUR_DELEGATE d0450062b3c4c9168ac8266f0806d62f5d95ed96894d5a9a0aaddf4298317eaa
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
      "holder": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
      "verifiableCredential": [
        "<SD-JWT-VC with PII redacted>"
      ],
      "proof": {
        "type": "DataIntegrityProof",
        "cryptosuite": "ecdsa-rdfc-2019",
        "proofPurpose": "authentication",
        "challenge": "da9b1009 HARBOUR_DELEGATE d0450062b3c4c9168ac8266f0806d62f5d95ed96894d5a9a0aaddf4298317eaa",
        "domain": "did:web:harbour.signing-service.example.com",
        "verificationMethod": "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
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

1. **VP `evidence[].transactionData`** — Inline (increases VP size)
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
  "type": "harbour_delegated_signing",
  "credential_ids": ["user_identity_credential"],
  "transaction_data_hashes_alg": ["sha-256"],
  "action": "data.purchase",
  "transaction": {
    "assetId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "price": "100",
    "currency": "ENVITED"
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
  "transaction_data_hashes": ["d0450062b3c4c9168ac8266f0806d62f5d95ed96894d5a9a0aaddf4298317eaa"],
  "transaction_data_hashes_alg": "sha-256"
}
```

### 5.4 Dual Support

Our challenge format supports both:

1. **OID4VP flow** — Hash in `transaction_data_hashes` (KB-JWT claim)
2. **Direct VP flow** — Hash in `proof.challenge` (W3C proof)

The same hash can appear in both locations for maximum compatibility.

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

```python
import hashlib
import json
import secrets
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class TransactionData:
    """Full transaction data object."""
    action: str
    timestamp: str
    nonce: str
    transaction: dict[str, Any]
    type: str = "HarbourDelegatedTransaction"
    version: str = "1.0"
    metadata: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def compute_hash(self) -> str:
        """Compute SHA-256 hash of canonical JSON representation."""
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))
        return hashlib.sha256(canonical.encode('utf-8')).hexdigest()


def create_delegation_challenge(
    transaction_data: TransactionData,
) -> str:
    """Create a Harbour delegation challenge string.
    
    Format: <nonce> HARBOUR_DELEGATE <sha256-hash>
    """
    tx_hash = transaction_data.compute_hash()
    return f"{transaction_data.nonce} HARBOUR_DELEGATE {tx_hash}"


def parse_delegation_challenge(challenge: str) -> tuple[str, str, str]:
    """Parse a Harbour delegation challenge string.
    
    Returns:
        Tuple of (nonce, action_type, hash)
    """
    parts = challenge.split(' ')
    if len(parts) != 3:
        raise ValueError(f"Invalid challenge format: expected 3 parts, got {len(parts)}")
    
    nonce, action_type, tx_hash = parts
    
    if action_type != "HARBOUR_DELEGATE":
        raise ValueError(f"Invalid action type: {action_type}")
    
    if len(tx_hash) != 64:
        raise ValueError(f"Invalid hash length: expected 64, got {len(tx_hash)}")
    
    return nonce, action_type, tx_hash


def verify_challenge(
    challenge: str,
    transaction_data: TransactionData,
) -> bool:
    """Verify that a challenge matches transaction data.
    
    Returns:
        True if the hash in the challenge matches the transaction data
    """
    nonce, _, challenge_hash = parse_delegation_challenge(challenge)
    
    if nonce != transaction_data.nonce:
        return False
    
    computed_hash = transaction_data.compute_hash()
    return challenge_hash == computed_hash


# Example usage
if __name__ == "__main__":
    tx = TransactionData(
        action="data.purchase",
        timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        nonce=secrets.token_hex(4),  # 8 hex chars
        transaction={
            "assetId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
            "price": "100",
            "currency": "ENVITED",
        },
        metadata={"description": "Purchase sensor data package"},
    )
    
    challenge = create_delegation_challenge(tx)
    print(f"Challenge: {challenge}")
    print(f"Valid: {verify_challenge(challenge, tx)}")
```

### 8.2 TypeScript

```typescript
import { createHash, randomBytes } from 'crypto';

interface TransactionData {
  type: 'HarbourDelegatedTransaction';
  version: '1.0';
  action: string;
  timestamp: string;
  nonce: string;
  transaction: Record<string, unknown>;
  metadata?: Record<string, unknown>;
}

function computeTransactionHash(data: TransactionData): string {
  const canonical = JSON.stringify(data, Object.keys(data).sort());
  return createHash('sha256').update(canonical).digest('hex');
}

function createDelegationChallenge(data: TransactionData): string {
  const hash = computeTransactionHash(data);
  return `${data.nonce} HARBOUR_DELEGATE ${hash}`;
}

function parseDelegationChallenge(challenge: string): {
  nonce: string;
  actionType: string;
  hash: string;
} {
  const parts = challenge.split(' ');
  if (parts.length !== 3) {
    throw new Error(`Invalid challenge format: expected 3 parts, got ${parts.length}`);
  }
  
  const [nonce, actionType, hash] = parts;
  
  if (actionType !== 'HARBOUR_DELEGATE') {
    throw new Error(`Invalid action type: ${actionType}`);
  }
  
  if (hash.length !== 64) {
    throw new Error(`Invalid hash length: expected 64, got ${hash.length}`);
  }
  
  return { nonce, actionType, hash };
}

function verifyChallenge(challenge: string, data: TransactionData): boolean {
  const { nonce, hash: challengeHash } = parseDelegationChallenge(challenge);
  
  if (nonce !== data.nonce) {
    return false;
  }
  
  const computedHash = computeTransactionHash(data);
  return challengeHash === computedHash;
}

// Example usage
const tx: TransactionData = {
  type: 'HarbourDelegatedTransaction',
  version: '1.0',
  action: 'data.purchase',
  timestamp: new Date().toISOString(),
  nonce: randomBytes(4).toString('hex'),
  transaction: {
    assetId: 'urn:uuid:550e8400-e29b-41d4-a716-446655440000',
    price: '100',
    currency: 'ENVITED',
  },
  metadata: { description: 'Purchase sensor data package' },
};

console.log('Challenge:', createDelegationChallenge(tx));
console.log('Valid:', verifyChallenge(createDelegationChallenge(tx), tx));
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
ACTION_LABELS = {
    "blockchain.transfer": "Transfer tokens",
    "blockchain.approve": "Approve token spending",
    "blockchain.execute": "Execute smart contract",
    "contract.sign": "Sign contract",
    "contract.accept": "Accept agreement",
    "data.purchase": "Purchase data asset",
    "data.share": "Share data",
    "credential.issue": "Issue credential",
    "credential.present": "Present credential",
}

def render_transaction_display(
    transaction_data: TransactionData, 
    service_name: str = "Harbour Signing Service"
) -> str:
    """Render transaction data for human-readable display.
    
    Args:
        transaction_data: The full transaction data object
        service_name: Human-friendly name for the signing service
    
    Returns:
        Multi-line string suitable for display to user
    """
    action = transaction_data.action
    action_label = ACTION_LABELS.get(action, action.replace(".", " ").title())
    
    lines = [
        f"{service_name} requests your authorization",
        "─" * 50,
        "",
        f"  Action:      {action_label}",
    ]
    
    # Add transaction-specific fields
    for key, value in transaction_data.transaction.items():
        display_key = key.replace("_", " ").title()
        display_value = str(value)
        if len(display_value) > 40:
            display_value = display_value[:37] + "..."
        lines.append(f"  {display_key}:  {display_value}")
    
    lines.extend([
        "",
        "─" * 50,
        f"  Nonce:       {transaction_data.nonce}",
        f"  Time:        {transaction_data.timestamp}",
    ])
    
    if transaction_data.metadata.get("expiresAt"):
        lines.append(f"  Expires:     {transaction_data.metadata['expiresAt']}")
    
    return "\n".join(lines)
```

### 9.5 TypeScript Display Renderer

```typescript
const ACTION_LABELS: Record<string, string> = {
  'blockchain.transfer': 'Transfer tokens',
  'blockchain.approve': 'Approve token spending',
  'blockchain.execute': 'Execute smart contract',
  'contract.sign': 'Sign contract',
  'contract.accept': 'Accept agreement',
  'data.purchase': 'Purchase data asset',
  'data.share': 'Share data',
  'credential.issue': 'Issue credential',
  'credential.present': 'Present credential',
};

function renderTransactionDisplay(
  data: TransactionData,
  serviceName = 'Harbour Signing Service'
): string {
  const actionLabel = ACTION_LABELS[data.action] ?? 
    data.action.replace('.', ' ').replace(/\b\w/g, c => c.toUpperCase());
  
  const lines: string[] = [
    `${serviceName} requests your authorization`,
    '─'.repeat(50),
    '',
    `  Action:      ${actionLabel}`,
  ];
  
  for (const [key, value] of Object.entries(data.transaction)) {
    const displayKey = key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    let displayValue = String(value);
    if (displayValue.length > 40) {
      displayValue = displayValue.slice(0, 37) + '...';
    }
    lines.push(`  ${displayKey}:  ${displayValue}`);
  }
  
  lines.push(
    '',
    '─'.repeat(50),
    `  Nonce:       ${data.nonce}`,
    `  Time:        ${data.timestamp}`,
  );
  
  if (data.metadata?.expiresAt) {
    lines.push(`  Expires:     ${data.metadata.expiresAt}`);
  }
  
  return lines.join('\n');
}
```

---

## 10. Examples

### 10.1 Data Purchase Transaction

**Transaction Data:**
```json
{
  "type": "HarbourDelegatedTransaction",
  "version": "1.0",
  "action": "data.purchase",
  "timestamp": "2026-02-24T12:00:00Z",
  "nonce": "da9b1009",
  "transaction": {
    "assetId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
    "price": "100",
    "currency": "ENVITED",
    "marketplace": "did:web:dataspace.envited.io"
  }
}
```

**Challenge:**
```
da9b1009 HARBOUR_DELEGATE d0450062b3c4c9168ac8266f0806d62f5d95ed96894d5a9a0aaddf4298317eaa
```

### 10.2 Blockchain Transfer Transaction

**Transaction Data:**
```json
{
  "type": "HarbourDelegatedTransaction",
  "version": "1.0",
  "action": "blockchain.transfer",
  "timestamp": "2026-02-24T12:30:00Z",
  "nonce": "ab12cd34",
  "transaction": {
    "chain": "eip155:42793",
    "contract": "0x1234567890abcdef1234567890abcdef12345678",
    "recipient": "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
    "amount": "1000000000000000000",
    "token": "ENVITED"
  }
}
```

**Challenge:**
```
ab12cd34 HARBOUR_DELEGATE 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b
```

### 10.3 Contract Signature Transaction

**Transaction Data:**
```json
{
  "type": "HarbourDelegatedTransaction",
  "version": "1.0",
  "action": "contract.sign",
  "timestamp": "2026-02-24T13:00:00Z",
  "nonce": "ef567890",
  "transaction": {
    "documentHash": "sha256:abc123def456...",
    "documentUri": "https://contracts.example.com/abc123",
    "parties": ["did:web:alice.example", "did:web:bob.example"]
  },
  "metadata": {
    "expiresAt": "2026-02-24T13:15:00Z"
  }
}
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
| `transaction_data.type` | `"harbour_delegated_signing"` |
| `transaction_data_hashes` in KB-JWT | Same hash as in `proof.challenge` |
| `transaction_data_hashes_alg` | `"sha-256"` |

### Integration Example

OID4VP authorization request:
```json
{
  "response_type": "vp_token",
  "client_id": "did:web:harbour.signing-service.example.com",
  "nonce": "n-0S6_WzA2Mj",
  "transaction_data": [{
    "type": "harbour_delegated_signing",
    "credential_ids": ["simpulse_id"],
    "transaction_data_hashes_alg": ["sha-256"],
    "transaction": {
      "action": "data.purchase",
      "assetId": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
      "price": "100",
      "currency": "ENVITED"
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
| `statement` | `metadata.description` (human-readable) |
| `uri` | Transaction reference (in transaction object) |
| `nonce` | `nonce` field |
| `issued-at` | `timestamp` field |
| `expiration-time` | `metadata.expiresAt` |
| `chain-id` | Implicit in transaction fields (e.g., `chain: "eip155:42793"`) |

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
