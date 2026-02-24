# Evidence in Harbour Credentials

Evidence is a W3C VC Data Model concept that provides cryptographic proof of **how** an issuer verified claims or **why** a holder is authorized to perform an action.

## What is Evidence?

When a credential is issued or a presentation is made, the `evidence` field can contain supporting proof that:

1. **For issuance**: Shows what the issuer relied upon to verify claims
2. **For presentations**: Shows why the holder is authorized to perform an action

Evidence creates an **audit trail** — allowing third parties to verify not just *that* something happened, but *how* it was validated.

## Harbour Evidence Types

### EmailVerification

Proves that an email address was verified before credential issuance.

**Use case**: A `NaturalPersonCredential` includes evidence that the user's email was verified via an email verification service (e.g., Altme EmailPass).

```json
{
  "type": "harbour:EmailVerification",
  "verifiablePresentation": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiablePresentation"],
    "holder": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    "verifiableCredential": [
      {
        "type": ["VerifiableCredential"],
        "issuer": "did:web:altme.io",
        "credentialSubject": {
          "type": "EmailPass",
          "email": "alice@example.com"
        }
      }
    ]
  }
}
```

**What it proves**: The issuer verified the email address via a trusted email verification provider before issuing the credential.

### IssuanceEvidence

References a previously issued credential that served as the basis for the new credential.

**Use case**: A `LegalPersonCredential` includes evidence of a prior credential from a notary attesting to the organization's registration.

```json
{
  "type": "harbour:IssuanceEvidence",
  "verifiablePresentation": {
    "@context": ["https://www.w3.org/ns/credentials/v2"],
    "type": ["VerifiablePresentation"],
    "holder": "did:web:participant.example.com",
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

**What it proves**: The issuer based the credential on a prior attestation from another trusted party (the notary).

### DelegatedSignatureEvidence

Proves user consent for a delegated signature operation. Used when a signing service executes transactions on behalf of users.

**Use case**: A blockchain transaction record includes evidence that the user consented to the purchase.

```json
{
  "type": "harbour:DelegatedSignatureEvidence",
  "transactionIntent": {
    "type": "harbour:TransactionIntent",
    "actionType": "purchase",
    "actionReference": "urn:uuid:tx-12345",
    "description": "Purchase 'Weather Data 2024' for €500",
    "consentTimestamp": "2024-01-15T10:30:00Z",
    "nonce": "abc123xyz"
  },
  "delegatedTo": "did:web:signing-service.harbour.io",
  "verifiablePresentation": "<SD-JWT VP with redacted PII>"
}
```

**What it proves**: The user (identified by their DID) explicitly consented to the specific transaction at the specified time.

See [Delegated Signing](delegated-signing.md) for the complete flow.

## When to Use Each Type

| Evidence Type | Use When | Example Scenario |
|--------------|----------|------------------|
| `EmailVerification` | Issuing credential that includes email claim | Onboarding a new user, verifying contact info |
| `IssuanceEvidence` | Basing credential on prior attestation | Trust anchor issuing based on notary credential |
| `DelegatedSignatureEvidence` | User consenting to delegated action | Blockchain purchase, contract signing |

## Evidence Structure

All evidence types inherit from the abstract `Evidence` class and share:

```yaml
Evidence:
  abstract: true
  class_uri: cred:evidence
  slots:
    - type  # Required: identifies the evidence type
```

Most evidence types include a `verifiablePresentation` slot containing a signed VP as proof.

## Privacy Considerations

Evidence often contains sensitive information. For privacy-preserving audit:

1. **Use SD-JWT VPs**: Selectively disclose only necessary claims
2. **Redact PII**: Names, emails, etc. can be hidden while keeping DID visible
3. **Public vs. Private audit**:
   - Public: Transaction intent + DID + signature validity
   - Private: Full credential details with all claims

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
            "type": "harbour:EmailVerification",
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

EmailVerification:
  is_a: Evidence
  class_uri: harbour:EmailVerification
  slots:
    - verifiablePresentation

IssuanceEvidence:
  is_a: Evidence
  class_uri: harbour:IssuanceEvidence
  slots:
    - verifiablePresentation

DelegatedSignatureEvidence:
  is_a: Evidence
  class_uri: harbour:DelegatedSignatureEvidence
  slots:
    - verifiablePresentation
    - transactionIntent
    - delegatedTo
```

## Related Documentation

- [Delegated Signing](delegated-signing.md) — Full delegated signing flow
- [SD-JWT-VC](../api/python/index.md) — Selective disclosure credentials
- [W3C VC Data Model — Evidence](https://www.w3.org/TR/vc-data-model-2.0/#evidence)
