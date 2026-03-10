# RFC 9901: Selective Disclosure for JSON Web Tokens (SD-JWT)

**Status:** Internet Standards Track (Proposed Standard)
**Published:** November 2025
**URL:** https://www.rfc-editor.org/rfc/rfc9901
**Datatracker:** https://datatracker.ietf.org/doc/rfc9901/
**Authors:** D. Fett (Authlete), K. Yasuda (Keio University), B. Campbell (Ping Identity)

## Overview

SD-JWT defines a mechanism for selective disclosure of individual elements
of a JSON payload within a JWS. The primary use case is selective disclosure
of JWT claims: an Issuer creates a signed JWT containing digests of
selectively disclosable claims, and the Holder chooses which claims to
reveal to a Verifier.

## Key Concepts

### SD-JWT Structure (§4)

- **SD-JWT** = Issuer-signed JWT + zero or more Disclosures
- **SD-JWT+KB** = SD-JWT + Key Binding JWT (proves Holder possession)
- Compact serialization: `<JWT>~<D.1>~<D.2>~...~<D.N>~`
- SD-JWT+KB serialization: `<JWT>~<D.1>~...~<D.N>~<KB-JWT>`

### Disclosures (§4.2)

- Base64url-encoded JSON array: `[salt, claim_name, claim_value]`
  (claim_name omitted for array elements)
- Hash of Disclosure is embedded in the JWT payload via `_sd` array.
- Digest computation: `base64url(hash(base64url(Disclosure)))` (§4.2.3)

### Hash Function Claim — `_sd_alg` (§4.1.1)

- OPTIONAL. Defaults to `sha-256`.
- If present, specifies the hash algorithm for Disclosure digests.

### Key Binding JWT (§4.3)

- `typ` header: `kb+jwt`
- Required claims: `iat`, `aud`, `nonce`, `sd_hash`
- `sd_hash`: hash over the SD-JWT string up to and including the last `~`
  before the KB-JWT.
- Proves the presenter controls the private key referenced by `cnf`.

### Confirmation Claim — `cnf` (§4.1.2)

- When Key Binding is used, SD-JWT MUST contain `cnf` claim.
- `cnf` contains the Holder's public key (typically as `jwk`).

## Verification Algorithm (§7)

### Issuer-side (§7.1)

1. Verify JWS signature on the Issuer-signed JWT.
2. Check `_sd_alg` (if present) is an accepted algorithm.

### Holder processing (§7.2)

1. Select which Disclosures to include in the presentation.
2. Optionally create a Key Binding JWT if required.

### Verifier-side (§7.3)

1. Separate the SD-JWT into JWT, Disclosures, and optional KB-JWT.
2. Verify the JWT signature.
3. For each Disclosure:
   a. Compute its digest.
   b. Find the digest in `_sd` arrays within the JWT payload.
   c. Replace the digest with the Disclosure's claim.
4. If Key Binding required:
   a. Verify KB-JWT signature against `cnf` key.
   b. Verify `sd_hash` matches the presented SD-JWT.
   c. Check `aud`, `nonce`, `iat` per policy.

## Security Considerations (§9)

| Topic | Requirement |
|-------|-------------|
| Signing | Issuer-signed JWT MUST be signed; `none` algorithm MUST NOT be used (§9.1) |
| Salt entropy | Salt MUST have at least 128 bits of entropy (§9.3) |
| Hash algorithm | SHA-256 or stronger RECOMMENDED (§9.4) |
| Key Binding | When enforced, Holder MUST prove possession (§9.5) |
| Forwarding | Without Key Binding, SD-JWTs are bearer credentials (§9.9) |
| Explicit typing | `typ` header SHOULD be used to prevent cross-protocol attacks (§9.11) |

## Claims That MUST NOT Be Selectively Disclosable

The specification does not mandate which claims are or aren't disclosable —
that is left to the credential profile. However, SD-JWT-VC (draft-15) defines
that `credentialStatus` and `@context` SHOULD NOT be selectively disclosable.

## Harbour Usage

- Harbour uses SD-JWT+KB for credential presentations (VP).
- KB-JWT provides Holder binding via P-256 key pair.
- `cnf` claim carries the Holder's public key.
- `transaction_data_hashes` in KB-JWT for OID4VP delegation flows.
- Selective disclosure annotations in LinkML map to SD-JWT `_sd` arrays.
