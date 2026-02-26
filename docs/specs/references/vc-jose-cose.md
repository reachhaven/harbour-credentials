# W3C VC-JOSE-COSE — Securing Verifiable Credentials using JOSE and COSE

**Status:** W3C Recommendation, 15 May 2025
**URL:** https://www.w3.org/TR/vc-jose-cose/

## Key Normative Requirements

### Payload Structure (§3.1)
- The entire VC JSON-LD document IS the JWT Claims Set (enveloping proof model).
- The JWT Claim Names `vc` and `vp` MUST NOT be present (§1.1.2.1, §3.1.3).
- Implementations MUST support JWS compact serialization; JSON serialization NOT RECOMMENDED.

### Media Types (§6.1)
| Media Type | Purpose |
|------------|---------|
| `application/vc+jwt` | JWT-secured credentials |
| `application/vp+jwt` | JWT-secured presentations |
| `application/vc+sd-jwt` | SD-JWT-secured credentials |
| `application/vp+sd-jwt` | SD-JWT-secured presentations |
| `application/vc+cose` | COSE-secured credentials |
| `application/vp+cose` | COSE-secured presentations |

**Note:** No `+ld+` media types exist (e.g., `vc+ld+jwt` is NOT valid).

### `typ` Header (§3.1.1, §3.1.2, §3.2.1, §3.2.2)
| Context | `typ` SHOULD be |
|---------|-----------------|
| JOSE VC | `vc+jwt` |
| JOSE VP | `vp+jwt` |
| SD-JWT VC | `vc+sd-jwt` |
| SD-JWT VP | `vp+sd-jwt` |

### Claim/Property Conflict Avoidance (§3.1.3)
| JWT Claim | VC Property | Guidance |
|-----------|-------------|----------|
| `iss` | `issuer` | SHOULD NOT conflict |
| `jti` | `id` | SHOULD NOT conflict |
| `sub` | `credentialSubject.id` | SHOULD NOT conflict |
| `iat` | `validFrom` | Different semantics (signature vs credential time) |
| `exp` | `validUntil` | Different semantics (signature vs credential expiry) |

Use of `nbf` is NOT RECOMMENDED (§3.1.3).

### SD-JWT Non-Disclosable Properties (§3.2.1)
Properties that SHOULD NOT be selectively disclosable:
- `@context`, `type`, `credentialStatus`, `credentialSchema`, `relatedResource`

### Key Discovery (§4.1, §4.2)
- `kid` MUST be present when key is expressed as DID URL (§4.1.1).
- Verification method type MUST be `JsonWebKey`; key MUST be in `publicKeyJwk` (§4.2).
- `cnf` MAY identify proof-of-possession key per RFC 7800 (§4.1.3).

### Verification (§5)
- Verified document MUST be well-formed compact JSON-LD per VCDM2.
- All claims for `typ` MUST be present and evaluated per validation policies.
- Claims not understood MUST be ignored.
