# Evidence in Harbour Credentials

Evidence is a W3C VC Data Model concept that provides cryptographic proof of **how** an issuer verified claims or **why** a holder is authorized to perform an action.

## What is Evidence?

When a credential is issued or a presentation is made, the `evidence` field can contain supporting proof that:

1. **For issuance**: Shows what the issuer relied upon to verify claims
2. **For presentations**: Shows why the holder is authorized to perform an action

Evidence creates an **audit trail** — allowing third parties to verify not just *that* something happened, but *how* it was validated.

## Harbour Evidence Types

### CredentialEvidence

Proves that the issuer verified claims using a prior credential or verifiable presentation. The embedded VP contains the credentials the issuer relied upon (e.g., email verification, notary attestation).

**Use case (email verification)**: A `NaturalPersonCredential` includes evidence that the user's email was verified via an email verification service (e.g., Altme EmailPass).
The EmailPass proof is modeled as a VC issued by a `did:webs` issuer DID.

```json
{
  "type": "harbour:CredentialEvidence",
  "verifiablePresentation": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiablePresentation"],
    "holder": "did:webs:users.altme.example:natural-persons:550e8400-e29b-41d4-a716-446655440000:EKYGGh-FtAphGmSZbsuBs_t4qpsjYJ2ZqvMKluq9OxmP",
    "verifiableCredential": [
      {
        "type": ["VerifiableCredential"],
        "issuer": "did:webs:issuers.altme.example:legal-persons:altme_sas:EMtR9m3wZ5xV2k8sP4jQ7nH1cD6bL0fYgAaUu2hCqK9M",
        "credentialSubject": {
          "type": "EmailPass",
          "email": "alice@example.com"
        }
      }
    ]
  }
}
```

**Use case (notary attestation)**: A `LegalPersonCredential` includes evidence of a prior credential from a notary attesting to the organization's registration.

```json
{
  "type": "harbour:CredentialEvidence",
  "verifiablePresentation": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiablePresentation"],
    "holder": "did:webs:participants.example.com:legal-persons:bmw_ag:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe",
    "verifiableCredential": [
      {
        "type": ["VerifiableCredential"],
        "issuer": "did:web:notary.example.com",
        "credentialSubject": {
          "type": "gx:LegalPerson",
          "gx:legalName": "Example Corporation GmbH",
          "gx:registrationNumber": "DE123456789"
        }
      }
    ]
  }
}
```

**What it proves**: The issuer based the credential on a prior attestation from another trusted party.

### DelegatedSignatureEvidence

Evidence on a **receipt credential** (SD-JWT-VC) that a signing service executed a transaction with the user's explicit consent. The consent VP uses SD-JWT with PII redacted. Transaction data is a disclosable claim enabling three-layer privacy (public / authorized / full audit).

**Use case**: A signing service issues a receipt credential after executing a blockchain purchase on behalf of a user.

```json
{
  "type": "harbour:DelegatedSignatureEvidence",
  "verifiablePresentation": "<SD-JWT VP with redacted PII>",
  "delegatedTo": "did:web:signing-service.envited.io",
  "transaction_data": {
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
  },
  "challenge": "da9b1009 HARBOUR_DELEGATE c0a4f646410379520b80256ca8a9f738d7ce59c9511d24649a452d6e23ea590f"
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
| `CredentialEvidence` | Issuing credential based on prior attestation | Email verification, notary credential, identity proofing |
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
    "issuer": "did:web:issuer.example.com",
    "credentialSubject": {...},
    "evidence": [
        {
            "type": "harbour:CredentialEvidence",
            "verifiablePresentation": email_verification_vp_jwt
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
