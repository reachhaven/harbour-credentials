# Evidence in Harbour Credentials

Evidence is a W3C VC Data Model concept that provides cryptographic proof of **how** an issuer verified claims or **why** a holder is authorized to perform an action.

## What is Evidence?

When a credential is issued or a presentation is made, the `evidence` field can contain supporting proof that:

1. **For issuance**: Shows what the issuer relied upon to verify claims
2. **For presentations**: Shows why the holder is authorized to perform an action

Evidence creates an **audit trail** — allowing third parties to verify not just *that* something happened, but *how* it was validated.

## Harbour Evidence Types

### CredentialEvidence

Proves that an authorizing party approved the credential issuance via OID4VP. The embedded VP carries the authorization proof — a Verifiable Presentation containing the authorizer's credential.

The Harbour Signing Service is the **sole issuer** of all credentials. Evidence VPs establish the chain of authorization:

**Use case 1 — Trust Anchor authorizes org (LegalPersonCredential)**: The Trust Anchor presents a VP containing its **self-signed LegalPersonCredential** (root of trust, analogous to a root CA certificate). The Signing Service verifies this VP and issues the org's credential with it as evidence.

**Use case 2 — Org authorizes employee (NaturalPersonCredential)**: The organization presents a VP containing its **LegalPersonCredential** (SD-JWT with sensitive fields redacted — registration number and addresses hidden, name/legalName disclosed). The Signing Service verifies this VP and issues the employee's credential with it as evidence.

```json
{
  "type": "harbour:CredentialEvidence",
  "verifiablePresentation": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiablePresentation"],
    "holder": "did:webs:reachhaven.com:ENVSnGVU_q39C0Lsim8CtXP_c0TbQW7BBndLVnBeDPXo",
    "verifiableCredential": [
      {
        "@context": ["https://www.w3.org/ns/credentials/v2", "..."],
        "type": ["VerifiableCredential", "harbour:LegalPersonCredential"],
        "issuer": "did:webs:reachhaven.com:ENVSnGVU_q39C0Lsim8CtXP_c0TbQW7BBndLVnBeDPXo",
        "credentialSubject": {
          "id": "did:webs:reachhaven.com:ENVSnGVU_q39C0Lsim8CtXP_c0TbQW7BBndLVnBeDPXo",
          "type": "harbour:LegalPerson",
          "name": "ReachHaven GmbH"
        }
      }
    ]
  }
}
```

**What it proves**: The authorizing party (Trust Anchor or org) approved the Signing Service to issue a credential for the target subject. The chain of trust flows: Trust Anchor → org → employee.

### DelegatedSignatureEvidence

Evidence on a **receipt credential** (SD-JWT-VC) that a signing service executed a transaction with the user's explicit consent. The consent VP uses SD-JWT with PII redacted. Transaction data is a disclosable claim enabling three-layer privacy (public / authorized / full audit).

**Use case**: A signing service issues a receipt credential after executing a blockchain purchase on behalf of a user.

```json
{
  "type": "harbour:DelegatedSignatureEvidence",
  "verifiablePresentation": "<SD-JWT VP with redacted PII>",
  "delegatedTo": "did:webs:harbour.reachhaven.com:Er9_mnFstIFyj7JXhHtf7BTHAaUXkaFoJQq96z8WycDQ",
  "transaction_data": {
    "type": "harbour_delegate:data.purchase",
    "credential_ids": ["harbour_natural_person"],
    "transaction_data_hashes_alg": ["sha-256"],
    "nonce": "da9b1009",
    "iat": 1771934400,
    "txn": {
      "asset_id": "urn:uuid:550e8400-e29b-41d4-a716-446655440000",
      "price": "100",
      "currency": "ENVITED",
      "marketplace": "did:web:dataspace.envited.io"
    }
  },
  "challenge": "da9b1009 HARBOUR_DELEGATE cb9916944deeb764c7f78b4ade8f8466178824d58bbd0083734eba67818b1a52"
}
```

**What it proves**: The user explicitly consented to the specific transaction, and the signing service executed it on their behalf.

See [Delegated Signing](delegated-signing.md) for the complete flow.

## Three-Layer Privacy Model

The receipt credential is an **SD-JWT-VC**. Transaction data and identity details are **selectively disclosable**:

| Layer | Audience | What's Visible |
|-------|----------|----------------|
| **Layer 1 — Public** | Everyone | CRSet entry (credential exists), transaction_data_hash on-chain, DID identifier, KB-JWT signature valid |
| **Layer 2 — Authorized** | Auditor | Transaction details (asset, price, marketplace), consent VP hash verification |
| **Layer 3 — Full Audit** | Compliance | User identity (name, email, organization), full credential chain |

## When to Use Each Type

| Evidence Type | Use When | Example Scenario |
|--------------|----------|------------------|
| `CredentialEvidence` | Issuing credential after authorization from a trusted party | Trust Anchor authorizes org issuance; org authorizes employee issuance |
| `DelegatedSignatureEvidence` | Issuing receipt after delegated action | Blockchain purchase, contract signing, access delegation |

## Evidence Structure

All evidence types inherit from the abstract `Evidence` class and share:

```yaml
Evidence:
  abstract: true
  class_uri: cred:Evidence
  slots:
    - type  # Required: identifies the evidence type
```

Most evidence types include a `verifiablePresentation` slot containing a signed VP as proof.

## Privacy Considerations

Evidence often contains sensitive information. For privacy-preserving audit:

1. **Use SD-JWT VPs**: Selectively disclose only necessary claims
2. **Redact PII**: Names, emails, etc. can be hidden while keeping DID visible
3. **Three-layer disclosure**:
   - Public: CRSet + transaction hash + signature validity
   - Authorized: Transaction details (asset, price)
   - Full audit: Identity details (name, email, organization)

## Verification

When verifying credentials or presentations with evidence:

1. **Verify the outer signature** (credential or VP)
2. **Verify each evidence VP signature**
3. **Check evidence issuer trust** (is the evidence issuer trusted?)
4. **Validate evidence freshness** (timestamps, nonces)
5. **Check revocation status** of evidence credentials

```python
from harbour.verifier import verify_vc_jose

# Verify outer credential
result = verify_vc_jose(credential_jwt, issuer_public_key)

# Verify evidence VP
for evidence in result.get("evidence", []):
    if "verifiablePresentation" in evidence:
        vp = evidence["verifiablePresentation"]
        # Verify VP signature...
```

## Adding Evidence to Credentials

When issuing a credential with evidence:

```python
credential = {
    "@context": [...],
    "type": ["VerifiableCredential", "harbour:NaturalPersonCredential"],
    "issuer": "did:webs:harbour.reachhaven.com:Er9_mnFstIFyj7JXhHtf7BTHAaUXkaFoJQq96z8WycDQ",
    "credentialSubject": {...},
    "evidence": [
        {
            "type": "harbour:CredentialEvidence",
            "verifiablePresentation": authorization_vp_jwt
        }
    ]
}

signed_vc = sign_vc_jose(credential, issuer_private_key)
```

## Schema Definition

Evidence types are defined in `linkml/harbour.yaml`:

```yaml
Evidence:
  abstract: true
  class_uri: cred:Evidence
  slots:
    - type

CredentialEvidence:
  is_a: Evidence
  class_uri: harbour:CredentialEvidence
  slots:
    - verifiablePresentation
  slot_usage:
    verifiablePresentation:
      required: true

DelegatedSignatureEvidence:
  is_a: Evidence
  class_uri: harbour:DelegatedSignatureEvidence
  slots:
    - verifiablePresentation
    - delegatedTo
    - transaction_data
  slot_usage:
    verifiablePresentation:
      required: true
    delegatedTo:
      required: true
    transaction_data:
      required: true
```

## Related Documentation

- [Delegated Signing](delegated-signing.md) — Full delegated signing flow
- [SD-JWT-VC](../api/python/index.md) — Selective disclosure credentials
- [W3C VC Data Model — Evidence](https://www.w3.org/TR/vc-data-model-2.0/#evidence)
