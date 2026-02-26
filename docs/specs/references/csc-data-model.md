# CSC Data Model for Remote Signature Applications

**Status:** CSC Standard, v1.0.0 (October 2025)
**URL:** https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/data-model-bindings.pdf
**API:** CSC API v2.2 (November 2025)

## Overview

The CSC Data Model defines how remote signing services (QTSPs) interact with
OID4VP for qualified electronic signature (QES) authorization. It bridges the
CSC API layer with the OID4VP credential presentation layer.

## Key Concepts

### Signature Request Flow
1. Relying party creates a `signatureRequest` via CSC API
2. QTSP triggers OID4VP Authorization Request with `transaction_data`
3. Wallet presents credentials + KB-JWT with `transaction_data_hashes`
4. QTSP uses authorized credentials to produce QES

### Data Model Mapping to Harbour
| CSC Concept | Harbour Equivalent | OID4VP |
|-------------|-------------------|--------|
| `signatureRequest` | `transaction_data` | `transaction_data` (request param) |
| `documentDigests` | `txn.document_hash` | — |
| `credentialID` | `credential_ids` | `credential_ids` |
| `hashAlgorithmOID` (OID) | `transaction_data_hashes_alg` (IANA) | `transaction_data_hashes_alg` |
| `SAD` (Signature Activation Data) | OID4VP consent flow | KB-JWT binding |

### SCAL2 Requirement
For SCAL2 (Sole Control Assurance Level 2), the authorization MUST be
cryptographically bound to the specific document hashes being signed.
This maps to OID4VP `transaction_data` with hash-bound consent.

### Integration with OID4VP
CSC-DM defines OID4VP `transaction_data` objects with:
- `type`: action type (e.g., `"sign"`)
- `documentDigests`: array of document hashes
- `hashAlgorithmOID`: hash algorithm (OID format in CSC, IANA name in OID4VP)
- `credentialID`: identifies the signing credential at the QTSP

## Relationship to Other Specs
- **OID4VP**: CSC uses OID4VP `transaction_data` for authorization
- **RFC 9901**: KB-JWT carries `transaction_data_hashes` proving wallet consent
- **eIDAS 2.0**: QES requirements drive SCAL2 hash-bound authorization
- **Harbour**: `DelegatedSignatureEvidence` captures the delegation receipt
  with `transaction_data` as an evidence-level claim on the receipt VC
