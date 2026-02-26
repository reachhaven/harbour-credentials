# IETF SD-JWT-VC — SD-JWT-based Verifiable Digital Credentials

**Status:** Internet Draft (draft-ietf-oauth-sd-jwt-vc-14, Feb 2026)
**URL:** https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
**Base:** RFC 9901 (SD-JWT)

## Key Normative Requirements

### Relationship to W3C VCDM (§11)
SD-JWT-VC does NOT utilize W3C VCDM v1.0, v1.1, or v2.0. It uses flat JWT
claims rather than JSON-LD structure. There is no `@context` or `type` array.

### Required/Optional Claims
| Claim | Requirement | Notes |
|-------|-------------|-------|
| `vct` | REQUIRED | Credential type (URI string, replaces `type` array) |
| `iss` | OPTIONAL (draft-14) | Was REQUIRED in draft-08. Can use x5c instead |
| `iat` | OPTIONAL | Issuance time (selectively disclosable) |
| `nbf` | OPTIONAL | Not before (not selectively disclosable) |
| `exp` | OPTIONAL | Expiration (MUST NOT be selectively disclosable) |
| `sub` | OPTIONAL | Subject identifier |
| `cnf` | CONDITIONAL | REQUIRED when key binding is used |
| `status` | OPTIONAL | MUST NOT be selectively disclosable |

### `typ` Header Change
| Version | `typ` value | Media type |
|---------|-------------|------------|
| draft-08 | `vc+sd-jwt` | `application/vc+sd-jwt` |
| draft-14 | `dc+sd-jwt` | `application/dc+sd-jwt` |

Renamed to avoid conflict with W3C VC-JOSE-COSE's `application/vc+sd-jwt`
which carries full JSON-LD payload. Verifiers SHOULD accept both during transition.

### Status (§3.2)
The `status` claim MUST NOT be selectively disclosable. Uses `status_list`
sub-object with `idx` (integer) and `uri` (status list URL).

### Key Binding (§4, via RFC 9901)
- KB-JWT REQUIRED claims: `iat`, `aud`, `nonce`, `sd_hash`
- `sd_hash` computed over US-ASCII bytes of entire SD-JWT before KB-JWT:
  `<issuer-jwt>~<disc1>~...~<discN>~`
- KB-JWT `typ` header: `kb+jwt`

### Custom Claims (§11)
Custom claims are allowed. `evidence` is not defined by SD-JWT-VC but can be
added as a custom claim and MAY be selectively disclosable.

## Mapping to W3C VCDM
| W3C VCDM | SD-JWT-VC | Notes |
|----------|-----------|-------|
| `type` array | `vct` | URI string, not array |
| `issuer` | `iss` | URI string |
| `credentialSubject.id` | `sub` | URI string |
| `validFrom` | `iat` / `nbf` | NumericDate, not ISO 8601 |
| `validUntil` | `exp` | NumericDate, not ISO 8601 |
| `credentialStatus` | `status` | Different structure |
| `evidence` | custom claim | Not defined by spec |
| `@context` | not used | No JSON-LD |
