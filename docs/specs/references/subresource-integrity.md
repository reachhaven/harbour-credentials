# W3C Subresource Integrity (SRI)

**Status:** W3C Recommendation
**URL:** https://www.w3.org/TR/SRI/

> This is a condensed reference of the parts of Subresource Integrity that
> Harbour relies on for the `digestSRI` integrity hash. It is **not** an original
> work — see the authoritative spec for normative text. SRI is referenced by W3C
> VC Data Model 2.0 (the `sriString` datatype) and by the Gaia-X Compliance
> Document 25.10 §10, which both defer to SRI for the integrity-hash format.

## Why this matters for Harbour

`harbour.gx:digestSRI` on a `harbour.gx:CompliantCredentialReference` binds a
Gaia-X compliance credential to the verifiable credentials it references. Its
value MUST be a valid SRI integrity-metadata string. The format below is the
single source of truth — example credentials (including third-party ones) that
use a different encoding are **not** authoritative.

## Integrity metadata format (§3.1, §3.2)

An integrity value is one or more hash expressions:

```abnf
integrity-metadata = *WSP hash-with-options *( 1*WSP hash-with-options ) *WSP
hash-with-options  = hash-expression *( "?" option-expression )
hash-expression    = hash-algorithm "-" base64-value
hash-algorithm     = "sha256" / "sha384" / "sha512"
base64-value       = 1*( ALPHA / DIGIT / "+" / "/" ) [ "=" [ "=" ] ]
```

- **Grammar:** `<hash-algorithm>-<base64-value>`, e.g.
  `sha384-H8BRh8j48O9oYatfu5AZzq6A9RINhZO5H16dQZngK7T62em8MUt1FLm52t+eX6xO`.
- **Encoding — STANDARD base64 (RFC 4648 §4).** The digest is base64-encoded:
  *"A base64 encoding is defined in Section 4 of [RFC4648]."* This is the
  `+` / `/` alphabet **with `=` padding** — **NOT** base64url (`-` / `_`) and
  **NOT** hexadecimal. Because standard base64 never contains `-`, the only `-`
  in a hash expression is the algorithm/value separator.
- **Case sensitivity:** base64 is case-sensitive; integrity strings are compared
  verbatim (no case folding).

## Hash algorithms (§3.2)

> "Conformant user agents MUST support the SHA-256, SHA-384, and SHA-512
> cryptographic hash functions for use as part of a request's integrity
> metadata."

Algorithm tokens, weakest to strongest: `sha256`, `sha384`, `sha512`.

## What is hashed (§3.3.* — matching algorithms / integrity validation)

SRI hashes the **raw bytes of the resource**:

> "Let `actualValue` be the result of applying `algorithm` to `bytes`."

A resource matches its metadata if the base64 of `actualValue` equals the
strongest provided `base64-value`.

## Harbour application

| SRI concept | Harbour |
|-------------|---------|
| Resource being hashed | The referenced Verifiable Credential |
| "Raw bytes" of that resource | **Canonical JSON** of the credential — recursively sorted keys, no insignificant whitespace, UTF-8, non-ASCII kept verbatim (RFC 8785 / JCS). A fixed byte representation chosen for reproducibility across re-serialization and across the Python/TypeScript runtimes. |
| Hash algorithm | `sha256` (default; `sha384` / `sha512` supported) |
| Encoding | Standard base64 (RFC 4648 §4), per this spec |
| Implementation | `harbour.digest_sri` (Python) / `digest-sri.ts` (TypeScript) |
| Verification | `make story` → `credentials.digest_sri_examples --check` and `yarn story:digests` |

Example (a Harbour credential reference):

```json
{
  "type": "harbour.gx:CompliantCredentialReference",
  "harbour.gx:credentialType": "gx:LegalPerson",
  "harbour.gx:digestSRI": "sha256-dl7zg1RuG2HhA97FckTfjuXIUxhc0Cagbp2MD4B6JTw="
}
```

> **Non-compliant encoding to avoid:** lowercase hex (e.g.
> `sha256-29784869cbb4...`, 64 hex chars). Hex is not part of SRI; it is used by
> the unrelated Harbour *delegation challenge* (see
> `delegation-challenge-encoding.md`), not by `digestSRI`.

## Authoritative source

Always defer to the original: https://www.w3.org/TR/SRI/
