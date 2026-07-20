# ADR-003: No Canonicalization Required (for signatures)

**Status:** Accepted (amended 2026-07-06 — see [Amendment](#amendment-2026-07-content-digests-use-jcs))
**Date:** 2026-02-17
**Depends on:** [ADR-001](001-vc-securing-mechanism.md) (VC-JOSE-COSE)

> **Scope**: this ADR is about **signature verification**. Signatures remain
> canonicalization-free (bytes are preserved in the JWT). Since the digestSRI
> feature (PR #11), **content digests** do use RFC 8785 (JCS) — see the
> amendment below. The two do not conflict: a digest hashes a *document*, a
> signature covers *bytes on the wire*.

## Context

When signing structured data, the signer and verifier must agree on the exact byte sequence being signed. There are several approaches to ensure this:

| Approach | Used By | Complexity |
|----------|---------|------------|
| JSON-LD RDF Canonicalization (RDFC-1.0) | W3C Data Integrity Proofs | High — requires JSON-LD processor + RDF canonicalizer |
| JSON Canonicalization Scheme (JCS, RFC 8785) | Some custom systems | Medium — deterministic JSON serialization |
| JSON sorting (`json.dumps(sort_keys=True)`) | Current harbour implementation | Low — but non-standard, not interoperable |
| JWT payload (no canonicalization) | VC-JOSE-COSE, standard JWT | None — JWT signs raw bytes |

## Problem with Our Current Approach

The current `signer.py` uses `json.dumps(sort_keys=True, separators=(",", ":"))` as a "canonicalization" step. This is problematic:

1. **It is not a standard.** No specification defines "Python json.dumps with sort_keys" as a canonical form. JavaScript's `JSON.stringify` with sorted keys may produce different byte sequences for edge cases (Unicode escaping, number formatting).

2. **It is labeled wrong.** The proof says `Ed25519Signature2018`, which mandates URDNA2015 canonicalization. A verifier implementing the real spec would canonicalize differently and reject our signature.

3. **It creates a false dependency.** Both signer and verifier must use the exact same JSON serialization — if Python adds a space or JavaScript escapes a character differently, verification fails.

## Decision

**With VC-JOSE-COSE (ADR-001), no canonicalization is needed.**

In standard JWT signing:

1. The payload is serialized to bytes once (by the signer)
2. Those exact bytes are base64url-encoded into the JWT
3. The verifier decodes the same bytes from the JWT
4. The signature covers the exact bytes in the JWT, not a re-serialized version

```text
Signer:   VC dict → JSON bytes → base64url → JWT(header.payload.signature)
Verifier: JWT → base64url decode → JSON bytes → verify signature → parse JSON
```

The verifier never re-serializes the payload. It verifies the signature over the bytes that are already in the JWT. This is why JWT works across every language — there is no canonicalization step that could diverge.

### Comparison

| | Current (broken) | VC-JOSE-COSE (proposed) |
|---|---|---|
| Sign | canonicalize → sign canonical bytes → detach payload | serialize once → sign payload bytes → compact JWS |
| Verify | re-canonicalize → sign canonical bytes → compare | decode JWT → verify signature over encoded bytes |
| Cross-language risk | High (JSON serialization differs) | None (bytes are preserved in JWT) |
| Libraries needed | Custom code | Standard JWT library |

## Consequences

- Remove `_canonicalize()` from both signer and verifier
- No JCS (RFC 8785) or RDFC-1.0 in the signature path
- Signing/verification is a one-liner with any JOSE library
- Cross-runtime interoperability is guaranteed by JWT specification, not by our serialization code

## Amendment (2026-07): content digests use JCS

The digestSRI feature (`harbour.digest_sri`, PR #11) and the batched-evidence
Merkle leaves ([spec §4.1](../specs/batched-credential-evidence.md)) need a
deterministic hash of a JSON *document* — a different problem from signature
verification, where the signed bytes travel inside the JWT. For these content
digests both runtimes canonicalize with **RFC 8785 (JCS)** before hashing:

```text
digestSRI    = sha256( JCS(unsigned credential document) )
Merkle leaf  = sha256( 0x00 || JCS(issuer payload without `evidence`) )
```

The original decision stands unchanged for signatures: no canonicalization is
performed to sign or verify any JWT/SD-JWT.

## References

- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) — JSON Web Token (JWT)
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) — JSON Canonicalization Scheme (JCS) — used for content digests (see Amendment), not for signatures
- [W3C RDF Dataset Canonicalization](https://www.w3.org/TR/rdf-canon/) — RDFC-1.0, used by Data Integrity but not by JOSE
