# ADR-004: Key Management — ES256 (P-256) + X.509 + DID

**Status:** Accepted
**Date:** 2026-02-17
**Updated:** 2026-02-17 (ES256 required by EUDI HAIP, EdDSA deprecated by RFC 9864)
**Depends on:** [ADR-001](001-vc-securing-mechanism.md)

## Context

Verifiable Credentials require:
1. A **signing algorithm** — determines the cryptographic primitives
2. A **key format** — how keys are serialized and exchanged
3. A **key resolution method** — how a verifier discovers the public key from the credential

## Decision

### Algorithm: ES256 (ECDSA P-256) as primary, Ed25519 as secondary

The original choice of Ed25519 must be revised based on regulatory requirements:

**Why ES256 must be the primary algorithm:**
- **EUDI HAIP mandatory:** "Issuers, Verifiers, and Wallets MUST, at a minimum, support ECDSA with P-256 and SHA-256 (ES256)"
- **EdDSA deprecated:** RFC 9864 deprecates the `EdDSA` algorithm identifier in JOSE. The `joserfc` library already emits security warnings.
- **Gaia-X compatible:** Gaia-X requires RFC 7518 compliant algorithms; ES256 qualifies
- **X.509 ecosystem:** P-256 has universal support in certificate authorities and HSMs

**Why Ed25519 should still be supported:**
- Existing test fixtures use Ed25519
- `did:key:z6Mk...` identifiers are Ed25519-based
- Some Gaia-X implementations still use EdDSA
- Useful for development/testing (deterministic signatures)

| | ES256 (P-256) | Ed25519 |
|---|---|---|
| EUDI HAIP | **MUST** | Not mentioned |
| JOSE status | Active | Deprecated (RFC 9864) |
| Speed | ~10x slower | Fast |
| Key size | 64 bytes public | 32 bytes public |
| X.509 support | Universal | Limited |
| did:key prefix | `zDn...` | `z6Mk...` |
| Role in harbour | **Default** | Testing/legacy |

### Key Format: JWK (RFC 7517)

**ES256 key:**
```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "<base64url-encoded x coordinate>",
  "y": "<base64url-encoded y coordinate>"
}
```

**Ed25519 key (legacy):**
```json
{
  "kty": "OKP",
  "crv": "Ed25519",
  "x": "<base64url-encoded public key>"
}
```

### Key Resolution: X.509 (EUDI) + DID (Gaia-X)

Three mechanisms, serving different ecosystems:

| Method | Ecosystem | JOSE Header | Example |
|--------|-----------|-------------|---------|
| **X.509 chain** | EUDI | `x5c` | Certificate chain in JWT header |
| **did:web** | Gaia-X | `kid` | `did:web:did.ascs.digital:participants:bmw#key-1` |
| **did:key** | Testing | `kid` | `did:key:zDn...#zDn...` |

**X.509 (EUDI mandatory):**
- HAIP: "The public key MUST be included in the `x5c` JOSE header parameter"
- Certificate chain from issuer to trust anchor (e.g., eIDAS qualified certificate)
- Trust anchor certificate excluded from chain
- No self-signed end-entity certificates

**did:web (Gaia-X):**
- Resolves to DID Document at well-known URL
- DID Document contains JWK public key(s)
- Used for organizational identities (ASCS, BMW, etc.)
- Gaia-X GXDCH uses X.509 certificates as trust anchors for DIDs

**did:key (testing):**
- Public key encoded directly in identifier
- No network resolution needed
- `did:key:zDn...` for P-256, `did:key:z6Mk...` for Ed25519

## Migration from Current Implementation

| Component | Current | Target |
|-----------|---------|--------|
| `keys.py` `generate_*` | Ed25519 only | Add P-256 generation |
| `keys.py` `*_to_jwk` | OKP/Ed25519 | Add EC/P-256 |
| `keys.py` `*_to_did_key` | `z6Mk` multicodec | Add `zDn` P-256 multicodec |
| `signer.py` | `alg: EdDSA` | `alg: ES256` default |
| Test fixtures | Ed25519 JWK | Add P-256 JWK |
| New: `x509.py` | — | X.509 cert chain handling |

## Consequences

- `keys.py` grows to support both EC/P-256 and OKP/Ed25519
- New `x509.py` module for certificate chain validation
- Test fixtures expanded with P-256 keypairs
- ES256 is the default; Ed25519 available via explicit algorithm parameter
- JWK remains the interchange format between Python and JavaScript

## References

- [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864) — EdDSA deprecation in JOSE
- [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518) — JSON Web Algorithms (ES256 definition)
- [OpenID4VC HAIP](https://openid.github.io/OpenID4VC-HAIP/openid4vc-high-assurance-interoperability-profile-wg-draft.html) — ES256 mandate
- [did:key P-256](https://w3c-ccg.github.io/did-method-key/) — zDn prefix for P-256
