# Token Status List (TSL) — draft-ietf-oauth-status-list-19

> **Source:** <https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/>
> **Authors:** T. Looker (MATTR), P. Bastian (Bundesdruckerei), C. Bormann (SPRIND)
> **Status:** Standards Track Internet-Draft (expires 21 September 2026)
> **Full text:** `token-status-list-draft-19.txt` (this directory)

## Abstract

Defines a status mechanism called **Token Status List (TSL)**, with data
structures and processing rules for representing the status of tokens secured
by JOSE or COSE — including JWT, SD-JWT, SD-JWT-VC, CWT, and ISO mdoc.

## Key Concepts

### Architecture

```
+----------------+  describes status  +------------------+
|  Status List   |------------------->| Referenced Token  |
| (JSON or CBOR) |<-------------------| (JOSE, COSE, ..) |
+-------+--------+     references     +------------------+
        |
        | embedded in
        v
+-------------------+
| Status List Token |
|   (JWT or CWT)    |
+-------------------+
```

### Roles

| Role | Description |
|------|-------------|
| **Issuer** | Issues Referenced Tokens to Holder |
| **Status Issuer** | Issues Status List Tokens (may be same as Issuer) |
| **Status Provider** | Hosts Status List Tokens on accessible endpoint |
| **Holder** | Receives and presents Referenced Tokens |
| **Relying Party** | Validates Referenced Tokens by fetching Status List |

### Status List (§4)

A compressed byte array where each Referenced Token is allocated an index
during issuance. The value at that index encodes the token's status.

- **bits**: 1, 2, 4, or 8 bits per token (supporting 2–256 status values)
- **lst**: base64url-encoded DEFLATE+ZLIB compressed byte array
- Scales to millions of tokens while remaining small (herd privacy)

### Status List Token (§5)

#### JWT Format

```json
{
  "alg": "ES256",
  "kid": "12",
  "typ": "statuslist+jwt"
}
.
{
  "exp": 2291720170,
  "iat": 1686920170,
  "status_list": {
    "bits": 1,
    "lst": "eNrbuRgAAhcBXQ"
  },
  "sub": "https://example.com/statuslists/1",
  "ttl": 43200
}
```

Required claims: `sub` (URI of this status list), `iat`, `status_list`.
Recommended: `exp`, `ttl` (cache lifetime in seconds).

### Referenced Token (§6)

A Referenced Token includes a `status` claim pointing to its position
in a Status List:

```json
{
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://example.com/statuslists/1"
    }
  }
}
```

For **SD-JWT-VC**, the `status` claim is part of the JWT payload:

```json
{
  "vct": "https://example.com/credential/type",
  "iss": "https://issuer.example.com",
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://issuer.example.com/statuslists/1"
    }
  }
}
```

### Status Types (§7)

| Value | Name | Description |
|-------|------|-------------|
| 0x00 | VALID | Token is valid (default) |
| 0x01 | INVALID | Token is revoked/invalid |
| 0x02 | SUSPENDED | Token is temporarily suspended |
| 0x03 | APPLICATION_SPECIFIC | Application-defined meaning |

### Verification (§8)

1. Fetch Status List Token from the `uri` in the Referenced Token's `status` claim
2. Validate the Status List Token (signature, expiry, etc.)
3. Verify `sub` of Status List Token matches `uri` in Referenced Token
4. Extract the status value at position `idx` from the decompressed byte array
5. Interpret the status value per the Status Types registry

### Security Considerations (§11)

- Status List Token MUST be cryptographically signed
- Key resolution and trust chain validation required
- Careful handling of HTTP redirects (3xx)
- Expiration and caching policies to balance freshness vs. privacy

### Privacy Considerations (§12)

- **Herd privacy**: Large lists prevent correlation of individual tokens
- **Issuer tracking**: Status Provider may observe which tokens are checked
- **Unlinkability**: Multiple verifiers checking same list cannot correlate holders
- **External Status Provider**: Decouples issuer from status checks

## Relevance to Harbour

The `CRSetEntry` type in harbour-core-credential.yaml models the
`credentialStatus` claim for harbour credentials. It should align with
the TSL `status` claim structure:

```json
{
  "credentialStatus": {
    "type": "TokenStatusList",
    "statusListCredential": "https://issuer.example.com/statuslists/1",
    "statusListIndex": 0
  }
}
```

The SD-JWT-VC profile (draft-ietf-oauth-sd-jwt-vc) uses the TSL `status`
claim directly in the JWT payload, without the W3C VCDM `credentialStatus`
wrapper.

## Download Date

- **2026-03-20** (draft-19)
