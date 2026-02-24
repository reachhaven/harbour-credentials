# ADR-001: VC Securing Mechanism

**Status:** Accepted
**Date:** 2026-02-17
**Updated:** 2026-02-17 (extended research on EUDI/OIDC4VP/SD-JWT-VC)

## Context

Harbour-credentials needs a proof mechanism for Verifiable Credentials that:

1. Works identically across Python and JavaScript runtimes
2. Uses standard libraries a web developer would already know
3. Is compliant with W3C VC Data Model v2
4. Is compatible with Gaia-X Trust Framework
5. Is compatible with the EUDI Wallet ecosystem and OIDC4VP

## The Landscape (February 2026)

There are **four** relevant securing/format mechanisms, not two:

### 1. Data Integrity Proofs (Embedded Proofs)

W3C spec for embedding cryptographic proofs inside credential JSON.

- **Requires:** JSON-LD processor + RDF canonicalization (RDFC-1.0)
- **Cryptosuites:** `eddsa-rdfc-2022` (current), `Ed25519Signature2018` (deprecated)
- **Selective disclosure:** Via `ecdsa-sd-2023` cryptosuite (complex)
- **EUDI status:** Not adopted
- **Gaia-X status:** Not the primary format (was `JsonWebSignature2020`, now moving to VC-JWT)

**Verdict:** Complex, limited library support, not on the EUDI or Gaia-X roadmap. **Not recommended.**

### 2. W3C VC-JOSE-COSE (Enveloping Proofs)

W3C spec for wrapping VC Data Model 2.0 credentials in JWT/JWS or COSE.

- **Format:** Standard JWT with `typ: vc+ld+jwt`, payload is the full VC JSON-LD
- **Data model:** W3C VC Data Model 2.0 (`@context`, `type` array, `credentialSubject`)
- **Selective disclosure:** Supported via SD-JWT extension within VC-JOSE-COSE
- **Libraries:** Any JOSE library (npm `jose`, Python `joserfc`)
- **EUDI status:** Not mandated (EUDI chose IETF SD-JWT-VC instead)
- **Gaia-X status:** Current format (VC-JWT as per 24.07 ICAM spec)

**Verdict:** Good for Gaia-X current compliance and JSON-LD schema validation. Standard JWT.

### 3. IETF SD-JWT-VC (Selective Disclosure JWT Verifiable Credentials)

IETF specification (draft-ietf-oauth-sd-jwt-vc-14, expected RFC Q1 2026) for credentials with built-in selective disclosure.

- **Format:** Compact SD-JWT: `issuer-jwt~disclosure1~disclosure2~...~kb-jwt`
- **Media type:** `application/dc+sd-jwt`
- **Data model:** Does NOT use W3C VC Data Model. Uses its own `vct` (credential type) claim, flat JWT claims
- **Selective disclosure:** Native — claims are hashed, disclosures travel separately
- **Key binding:** Via `cnf` claim + Key Binding JWT
- **Libraries:** `@sd-jwt/sd-jwt-vc` (npm/JS), `sd-jwt-python` (Python) — both by OpenWallet Foundation
- **EUDI status:** **MANDATORY** (one of two required formats alongside mdoc)
- **HAIP status:** **MANDATORY** (OpenID4VC High Assurance Interoperability Profile)

**Verdict:** Mandatory for EUDI compliance. Privacy-preserving. Strong library ecosystem. **The regulatory choice.**

### 4. ISO mdoc (ISO 18013-5)

CBOR-based credential format for mobile documents.

- **Format:** CBOR, not JSON
- **EUDI status:** **MANDATORY** (alongside SD-JWT-VC)
- **Relevance:** Primarily for mobile driving licenses and government IDs

**Verdict:** Not relevant for Gaia-X organizational credentials. Out of scope for harbour.

## Comparison Matrix

| Aspect | Data Integrity | VC-JOSE-COSE | SD-JWT-VC | mdoc |
|--------|---------------|--------------|-----------|------|
| **EUDI mandatory** | No | No | **Yes** | Yes |
| **Gaia-X current** | No | **Yes** | Roadmap | No |
| **HAIP profile** | No | No | **Yes** | Yes |
| **OIDC4VP support** | Partial | Yes | **Yes** | Yes |
| **Selective disclosure** | Complex | Via SD-JWT | **Native** | Yes |
| **W3C VCDM 2.0** | Yes | Yes | **No** | No |
| **JSON-LD / SHACL** | Yes | Yes | No | No |
| **Standard JWT libs** | No | Yes | Specialized | No |
| **JS library** | @digitalbazaar | npm `jose` | `@sd-jwt/sd-jwt-vc` | — |
| **Python library** | None mature | `joserfc` | `sd-jwt-python` | — |

## Critical Findings

### 1. EUDI Mandates ES256, Not Ed25519

The OpenID4VC HAIP specification states:

> "Issuers, Verifiers, and Wallets MUST, at a minimum, support ECDSA with P-256 and SHA-256 (JOSE algorithm identifier ES256)"

**Ed25519/EdDSA is not mentioned in HAIP.** Our current Ed25519 keys will not work with EUDI wallets. We must support **ES256 (P-256)** at minimum.

Additionally, `joserfc` now warns: "EdDSA is deprecated via RFC 9864" — the JOSE working group has deprecated the `EdDSA` algorithm identifier.

### 2. EUDI Mandates X.509 Certificates, Not DIDs

HAIP requires:

> "The public key used to validate the signature MUST be included in the x5c JOSE header parameter"

Gaia-X uses DIDs (primarily `did:web`) plus X.509 via GXDCH. We need to support **both** `x5c` (for EUDI) and DID resolution (for Gaia-X).

### 3. SD-JWT-VC ≠ W3C VC Data Model

This is the biggest architectural tension:

- Our LinkML schemas generate JSON-LD contexts and SHACL shapes for **W3C VCDM** credentials
- EUDI mandates **SD-JWT-VC**, which deliberately does NOT use W3C VCDM
- SD-JWT-VC uses `vct` (a type URI) instead of `@context` + `type` arrays
- SD-JWT-VC claims are flat JWT claims, not `credentialSubject` nested objects

This means our SHACL validation applies to the **schema design layer** (ensuring our credential attributes are well-modelled), while the **transport format** for EUDI is SD-JWT-VC.

### 4. Gaia-X Is Converging Toward EUDI

Gaia-X's current VC-JWT format will likely align with EUDI standards. The GXDCH already uses X.509 certificate chains (eIDAS or evSSL certificates as trust anchors). SD-JWT-VC adoption in Gaia-X is on the roadmap.

## Problems with the Current Implementation

1. **Ed25519Signature2018 is deprecated** — superseded 3 years ago
2. **Canonicalization is wrong** — uses `json.dumps(sort_keys=True)` instead of URDNA2015
3. **Ed25519 is not EUDI-compatible** — HAIP mandates ES256 (P-256)
4. **No selective disclosure** — privacy-sensitive fields cannot be hidden
5. **Non-standard hybrid** — detached JWS with `b64: false` is neither JWT nor Data Integrity
6. **DIDs only** — no X.509 certificate chain support for EUDI

## Decision

Support **two complementary formats**, serving different purposes:

### Primary: SD-JWT-VC (IETF) — for EUDI / OIDC4VP

| Aspect | Choice |
|--------|--------|
| Format | SD-JWT-VC (compact serialization) |
| Algorithm | **ES256** (ECDSA P-256) — HAIP mandatory minimum |
| Key resolution | X.509 via `x5c` header (EUDI) + `did:web` (Gaia-X) |
| Selective disclosure | Native SD-JWT |
| Holder binding | `cnf` claim with proof-of-possession |
| Status | `status_list` (Token Status List) |
| JS library | `@sd-jwt/sd-jwt-vc` |
| Python library | `sd-jwt-python` (OpenWallet Foundation) |
| Media type | `application/dc+sd-jwt` |

### Secondary: W3C VC-JOSE-COSE — for Gaia-X current + schema validation

| Aspect | Choice |
|--------|--------|
| Format | Compact JWS (`header.payload.signature`) |
| Algorithm | **ES256** (consistent with SD-JWT-VC) |
| JWT header | `{"alg": "ES256", "typ": "vc+ld+jwt"}` |
| Payload | Full W3C VCDM 2.0 JSON-LD |
| Key resolution | `did:web` (Gaia-X) + `x5c` (EUDI alignment) |
| JS library | npm `jose` |
| Python library | `joserfc` |

### Key Management Migration: Ed25519 → P-256

| Aspect | Current | Target |
|--------|---------|--------|
| Algorithm | Ed25519 (EdDSA) | **P-256 (ES256)** |
| Key format | JWK OKP/Ed25519 | **JWK EC/P-256** |
| DID method | `did:key:z6Mk...` | `did:key:zDn...` (P-256) + `did:web` |
| Certificates | None | X.509 chains via `x5c` |

Ed25519 keys SHOULD still be supported for backwards compatibility and testing, but **ES256 MUST be the default** for EUDI compliance.

## Relationship Between Formats

```
                    ┌─────────────────────────────┐
                    │   LinkML Schema Definition   │
                    │   (harbour.yaml, etc.)       │
                    └──────────┬──────────────────┘
                               │ generates
                    ┌──────────▼──────────────────┐
                    │  JSON-LD Context + SHACL     │
                    │  (schema validation layer)   │
                    └──────────┬──────────────────┘
                               │ validates
              ┌────────────────┼────────────────┐
              ▼                ▼                 ▼
    ┌─────────────────┐  ┌──────────┐  ┌──────────────┐
    │ Example VCs      │  │ Signed   │  │ SD-JWT-VC    │
    │ (JSON-LD)        │  │ VC-JWT   │  │ (EUDI)       │
    │ development/test │  │ (Gaia-X) │  │ production   │
    └─────────────────┘  └──────────┘  └──────────────┘
```

- **LinkML / SHACL** validates the attribute schema (which fields exist, types, cardinality)
- **VC-JOSE-COSE** wraps the validated JSON-LD in a signed JWT (Gaia-X compliance)
- **SD-JWT-VC** maps the same attributes to flat JWT claims for EUDI wallets

A credential can exist in multiple formats simultaneously. The mapping from SHACL-validated JSON-LD to SD-JWT-VC claims is a serialization step, not a semantic one.

## Consequences

### Positive
- EUDI wallet compatible (SD-JWT-VC + ES256 + x5c)
- Gaia-X compatible (VC-JWT + did:web)
- Selective disclosure for privacy-sensitive fields
- Both Python and JS implementations exist for SD-JWT-VC
- Future-proof (SD-JWT-VC is the regulatory direction)

### Negative
- Two signing formats to maintain (SD-JWT-VC + VC-JOSE-COSE)
- ES256 is slower than Ed25519 (negligible for credential operations)
- X.509 certificate management adds operational complexity
- SD-JWT-VC mapping from JSON-LD needs explicit definition

### Migration Path (completed)
1. ~~Add ES256 (P-256) key generation alongside Ed25519~~
2. ~~Implement VC-JOSE-COSE signer/verifier (standard JWT with ES256)~~
3. ~~Implement SD-JWT-VC signer/verifier using OpenWallet Foundation libraries~~
4. ~~Add X.509 certificate chain support~~
5. ~~Define mapping: LinkML schema attributes → SD-JWT-VC claims~~
6. ~~Remove Ed25519Signature2018 implementation~~
7. ~~Update CI to test both formats in both runtimes~~

## References

### W3C
- [W3C VC Data Model v2](https://www.w3.org/TR/vc-data-model-2.0/)
- [W3C VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/)
- [W3C VC Data Integrity](https://www.w3.org/TR/vc-data-integrity/)

### IETF
- [SD-JWT-VC (draft-14)](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/)
- [SD-JWT (RFC 9901)](https://datatracker.ietf.org/doc/rfc9901/)
- [RFC 7515 — JWS](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 8037 — EdDSA for JOSE](https://www.rfc-editor.org/rfc/rfc8037)
- [RFC 9864 — EdDSA deprecation](https://www.rfc-editor.org/rfc/rfc9864)

### EUDI / eIDAS 2.0
- [EUDI Architecture Reference Framework](https://github.com/eu-digital-identity-wallet/eudi-doc-architecture-and-reference-framework)
- [EUDI ARF latest](https://eudi.dev/latest/architecture-and-reference-framework-main/)
- [PID Rulebook](https://github.com/eu-digital-identity-wallet/eudi-doc-attestation-rulebooks-catalog)
- [EUDI Standards Catalog](https://github.com/eu-digital-identity-wallet/eudi-doc-standards-and-technical-specifications)

### OpenID
- [OIDC4VP 1.0](https://github.com/openid/OpenID4VP)
- [OpenID4VC HAIP](https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html)
- [OIDC4VCI](https://openid.github.io/OpenID4VCI/openid-4-verifiable-credential-issuance-1_0.html)

### Gaia-X
- [Gaia-X ICAM Credential Format (24.07)](https://docs.gaia-x.eu/technical-committee/identity-credential-access-management/24.07/credential_format/)
- [Gaia-X Architecture — Credential Formats](https://gaia-x.gitlab.io/technical-committee/architecture-working-group/architecture-document/credential_formats_protocols/)

### Libraries
- [npm jose](https://www.npmjs.com/package/jose) — JavaScript JOSE
- [joserfc](https://pypi.org/project/joserfc/) — Python JOSE
- [@sd-jwt/sd-jwt-vc](https://www.npmjs.com/package/@sd-jwt/sd-jwt-vc) — JavaScript SD-JWT-VC (OpenWallet Foundation)
- [sd-jwt-python](https://github.com/openwallet-foundation-labs/sd-jwt-python) — Python SD-JWT (OpenWallet Foundation)
