# Evidence in Harbour Credentials

Evidence is a W3C VC Data Model concept ([VCDM 2.0 §5.6](https://www.w3.org/TR/vc-data-model-2.0/#evidence)) that provides cryptographic proof of **how** an issuer verified claims or **why** an action was authorized.

## The Two-Signature Model

Under the sovereign-issuer model ([ADR-006](../decisions/006-sovereign-issuers.md)), every Harbour credential carries two distinct signatures with a deliberate separation of powers:

- **Evidence** — the *authorization*, signed by a **human admin** whose wallet key is authorized on the issuing organization's `did:ethr`. A person decided this credential should exist; the evidence is the durable, non-repudiable record of that decision.
- **Proof** — the SD-JWT signature that makes the credential verifiable, produced by the **Signing Service** under an assertion-only mandate key in the issuer's DID document. It executes; it decides nothing.

Because every verifier checks the evidence, a Signing Service that minted a credential nobody authorized is detectable: it cannot forge an admin's signature.

## Harbour Evidence Types

### BatchCredentialEvidence

Proves that an authorizing party approved this credential's issuance as part of a **Merkle-committed batch** with a **single signature** — one admin signature covers all credentials issued in the batch, and each credential independently proves its own inclusion. The full construction is specified in [batched-credential-evidence.md](../specs/batched-credential-evidence.md).

Wire form (from the signed `legal-person-credential.decoded.json` story output):

```json
{
  "type": ["harbour:BatchCredentialEvidence"],
  "authorizedBy": "did:ethr:0x14a34:0x4d6246a7d1e60caa44b75e3af9b37ac8d6442774",
  "authorization": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImhhcmJvdXIt...",
  "merkleProof": {
    "path": [
      { "hash": "ANLV12CRfKcCFPzo_lkAC1DDzHy9Le22opPgTp6x51s", "position": "left" },
      { "hash": "droQfyi3wLC3_tDEOHtk6B9_NP_UbCBe_GKTIZDsE0o", "position": "right" }
    ]
  }
}
```

| Slot | Meaning |
|------|---------|
| `authorizedBy` | The issuing organization's `did:ethr`; the authorization JWT is signed by an admin key listed in that DID document. Required — the only slot present on the human-readable source examples. |
| `authorization` | Compact ES256 JWS signed by the admin; its `nonce` is the base64url batch Merkle root, its `aud` the **Signing Service** (the executor being authorized). Generated at batch-signing time. |
| `merkleProof` | Ordered sibling digests (`hash` + `position`) folding this credential's leaf to the signed root. A batch of size 1 has an empty `path`. |

**What it proves**: a human admin of the authorizer organization approved exactly this credential's payload — its leaf folds to the root the admin signed. Authorizer and issuer usually coincide at the DID level (the Trust Anchor authorizes and issues LegalPersonCredentials; an organization authorizes and issues its members' NaturalPersonCredentials).

**Who authorizes what** (ADR-006):

- **LegalPersonCredential** — issued by the Trust Anchor; a Trust Anchor admin signs the batch evidence.
- **NaturalPersonCredential** — issued by the organization (`memberOf` MUST equal `issuer`); an org admin signs the batch evidence.

### DelegatedSignatureEvidence (`harbour:SignatureEvidence` on the wire)

Evidence on a **receipt credential** (SD-JWT-VC) that a signing service executed a transaction with the user's explicit consent. The consent VP uses SD-JWT with PII redacted. Transaction data is a disclosable claim enabling three-layer privacy (public / authorized / full audit).

> **Naming note**: the LinkML class is named `DelegatedSignatureEvidence` for clarity, but its canonical IRI — the `type` value on the wire — is **`harbour:SignatureEvidence`**. All code, tests, and examples use `harbour:SignatureEvidence`; the IRI is stable and must not be renamed.

**Use case**: A signing service issues a receipt credential after executing a blockchain purchase on behalf of a user.

```json
{
  "type": "harbour:SignatureEvidence",
  "verifiablePresentation": "<SD-JWT VP with redacted PII>",
  "delegatedTo": "did:ethr:0x14a34:0x31f1ca3dc5da9f83f360d805662d11a418950202",
  "transaction_data": {
    "type": "harbour.delegate:data.purchase",
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
  },
  "challenge": "da9b1009 HARBOUR_DELEGATE c3d4ba771c1103935ab4121874c4b3a78c8471719c80f60d59ca5811e232089b"
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

| Evidence Type | Wire `type` | Use When |
|--------------|-------------|----------|
| `BatchCredentialEvidence` | `harbour:BatchCredentialEvidence` | Issuing credentials after a human admin's authorization — one signature per batch (Trust Anchor batches LegalPersonCredentials; an org batches its employees' NaturalPersonCredentials) |
| `DelegatedSignatureEvidence` | `harbour:SignatureEvidence` | Issuing a receipt after a delegated action — blockchain purchase, contract signing, access delegation |

## Verifying Batch Evidence

A verifier holding **one** credential checks it in isolation (spec [§6](../specs/batched-credential-evidence.md#6-verification)):

1. **Verify the proof** against the verification method the `kid` names in the **issuer's** DID document (the Signing Service's assertion-only `#delegate-1` mandate key).
2. **Recompute the leaf** from the raw issuer payload with `evidence` removed (RFC 8785 canonicalization, `0x00` domain prefix, SHA-256). The leaf is over the salted `_sd` digests, so it is invariant under selective disclosure.
3. **Fold the `merkleProof`** to a root and compare it with the `nonce` inside the `authorization` JWT.
4. **Verify the `authorization` JWS** against the admin key the JWT `kid` names in the authorizer's DID document; check `iss` = `authorizedBy` (the executor additionally checks `aud` = its own DID before acting).

```python
from harbour.sd_jwt import verify_sd_jwt_vc
from harbour.batch_evidence import verify_batch_evidence

claims = verify_sd_jwt_vc(sd_jwt, proof_public_key)      # step 1
verify_batch_evidence(                                    # steps 2-4
    raw_payload,                # issuer payload with _sd digests
    raw_payload["evidence"][0],
    authorizer_public_key,
    expected_audience=signing_service_did,
)
```

```typescript
import { verifySdJwtVc, verifyBatchEvidence } from "@reachhaven/harbour-credentials";

const claims = await verifySdJwtVc(sdJwt, proofPublicKey);
await verifyBatchEvidence(rawPayload, rawPayload.evidence[0], authorizerPublicKey, {
  expectedAudience: signingServiceDid,
});
```

## Adding Evidence to Credentials

Source credentials carry only the `authorizedBy` DID; `authorization` and `merkleProof` are generated at batch-signing time:

```python
from harbour.sd_jwt import build_sd_jwt_payload, sign_sd_jwt
from harbour.batch_evidence import build_batch_evidence

# 1. Fix salts for every credential in the batch first.
payload, disclosures = build_sd_jwt_payload(credential, vct=vct)

# 2. One admin signature over the batch Merkle root; per-credential proofs.
evidence = build_batch_evidence(
    [payload], admin_key, authorizer_did=org_did, audience=signing_service_did
)

# 3. Inject the evidence, then sign the proof with the issuer's mandate key.
payload["evidence"] = [evidence[0]]
sd_jwt = sign_sd_jwt(payload, disclosures, ss_key, kid=f"{issuer_did}#delegate-1")
```

## Schema Definition

Evidence types are defined in `linkml/harbour-core-credential.yaml`:

```yaml
Evidence:
  abstract: true
  class_uri: harbour:Evidence

BatchCredentialEvidence:
  is_a: Evidence
  class_uri: harbour:BatchCredentialEvidence
  slots:
    - authorizedBy    # required; org did:ethr
    - authorization   # compact JWS, nonce = batch Merkle root
    - merkleProof     # MerkleProof: path of {hash, position}

MerkleProof:
  class_uri: harbour:MerkleProof
  # path: ordered MerklePathElement list ({hash, position: left|right})

DelegatedSignatureEvidence:
  is_a: Evidence
  class_uri: harbour:SignatureEvidence   # canonical wire IRI — do not rename
  slots:
    - verifiablePresentation  # required
    - delegatedTo             # required
    - transaction_data        # required
    - challenge               # required
```

## Related Documentation

- [ADR-006 — Sovereign issuers with a Signing-Service mandate](../decisions/006-sovereign-issuers.md)
- [Batched Credential Evidence Specification](../specs/batched-credential-evidence.md)
- [Delegated Signing](delegated-signing.md) — Full delegated signing flow
- [W3C VC Data Model — Evidence](https://www.w3.org/TR/vc-data-model-2.0/#evidence)
