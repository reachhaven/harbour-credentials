# OpenID for Verifiable Presentations 1.0 (OID4VP)

**Status:** OpenID Final Specification (9 July 2025)
**URL:** https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
**Authors:** O. Terbu (MATTR), T. Lodderstedt (SPRIND), K. Yasuda
**Raw text:** `oid4vp-1.0.txt` (full spec, 3,834 lines)

## Overview

OID4VP extends OAuth 2.0 to enable Wallets to present Verifiable Credentials
and Verifiable Presentations to Verifiers. It introduces the `vp_token`
response type, `direct_post` response mode, and the `transaction_data`
mechanism for authorized transactions.

## Key Parameters

### Authorization Request (§5.1)

| Parameter | Requirement | Description |
|-----------|-------------|-------------|
| `client_id` | REQUIRED | Verifier identifier (with Client Identifier Prefix) |
| `nonce` | REQUIRED | Fresh cryptographically random value per request (§14.1) |
| `response_type` | REQUIRED | `vp_token` or `vp_token id_token` |
| `response_mode` | OPTIONAL | `direct_post` or `direct_post.jwt` |
| `dcql_query` | CONDITIONAL | Digital Credentials Query Language query |
| `transaction_data` | OPTIONAL | Array of base64url-encoded JSON objects (§8.4) |

### Authorization Response (§8)

| Parameter | Description |
|-----------|-------------|
| `vp_token` | Contains one or more Verifiable Presentations |
| `presentation_submission` | Maps credentials to query (deprecated in favor of DCQL) |

## Transaction Data (§8.4)

Each `transaction_data` object MUST contain:

| Parameter | Requirement | Description |
|-----------|-------------|-------------|
| `type` | REQUIRED | String identifying the transaction data type |
| `credential_ids` | REQUIRED | Array of credential query IDs for authorization |

- Wallet MUST return error on unrecognized transaction data types (§5.1).
- Wallet MUST reject `transaction_data` if it doesn't support the parameter.
- Wallet MUST include representation/reference to data in the credential
  presentation (§8.4).

## SD-JWT VC Credential Format (Appendix B.3)

### Format Identifier

- `dc+sd-jwt` (aligned with SD-JWT-VC draft-15 media type)

### Transaction Data in KB-JWT (§B.3.3)

| KB-JWT Claim | Requirement | Description |
|-------------|-------------|-------------|
| `nonce` | REQUIRED | Value from Authorization Request nonce |
| `aud` | REQUIRED | Value of client_id (or `origin:` prefix for DC API) |
| `iat` | REQUIRED | Issued-at timestamp |
| `sd_hash` | REQUIRED | Hash over the SD-JWT before KB-JWT |
| `transaction_data_hashes` | CONDITIONAL | Array of base64url hashes over transaction_data strings |
| `transaction_data_hashes_alg` | CONDITIONAL | Hash algorithm used (default: `sha-256`) |

### Presentation Response (§B.3.6)

- SD-JWT+KB compact serialization: `<JWT>~<D.1>~...~<D.N>~<KB-JWT>`
- KB-JWT provides Holder binding and audience/nonce binding.

## Security Requirements (§14)

### Replay Prevention (§14.1)

- Verifier MUST create fresh nonce with sufficient entropy per request.
- Verifier MUST validate nonce in every VP in the response.
- Verifier MUST validate `aud` matches its client_id.

### Session Fixation (§14.2)

- Response URI MUST be validated against registered URIs.

## Harbour Usage

- Harbour uses OID4VP `transaction_data` for delegated signing flows.
- KB-JWT carries `transaction_data_hashes` + `_alg` for integrity binding.
- `DelegatedSignatureEvidence` in LinkML maps:
  - `transaction_data` → OID4VP transaction_data object (decoded JSON)
  - `delegatedTo` → conceptually maps to `client_id` / KB-JWT `aud`
- Harbour hashes decoded canonical JSON (content integrity), while OID4VP
  hashes base64url transport strings (transport binding) — different layers.
- CSC Data Model `signatureRequest` triggers OID4VP flow.
