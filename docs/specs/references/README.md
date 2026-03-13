# Reference Specifications

This directory contains downloaded copies of external specifications for offline reference and AI agent access.

## ⚠️ Important Notice

**These files are NOT original works of this project.**

They are copies of specifications published by their respective standards organizations. The original terms, conditions, and licenses of each specification apply.

## Files

| File | Source | Organization | License |
|------|--------|--------------|---------|
| `vc-data-model-2.0.md` | [W3C VC Data Model v2.0](https://www.w3.org/TR/vc-data-model-2.0/) | W3C | [W3C Document License](https://www.w3.org/copyright/document-license-2023/) |
| `did-core.md` | [W3C DIDs v1.0](https://www.w3.org/TR/did-core/) | W3C | [W3C Document License](https://www.w3.org/copyright/document-license-2023/) |
| `vc-jose-cose.md` | [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/) | W3C | [W3C Document License](https://www.w3.org/copyright/document-license-2023/) |
| `sd-jwt-rfc9901.md` | [RFC 9901: SD-JWT](https://www.rfc-editor.org/rfc/rfc9901) | IETF | [IETF Trust](https://trustee.ietf.org/license-info) |
| `sd-jwt-vc.md` | [SD-JWT-VC draft-15](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) | IETF | [IETF Trust](https://trustee.ietf.org/license-info) |
| `oid4vp-1.0.md` | [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | OpenID Foundation | [OpenID IPR](https://openid.net/intellectual-property/) |
| `oid4vp-1.0.txt` | Raw full spec text (3,834 lines) — retained for search | OpenID Foundation | [OpenID IPR](https://openid.net/intellectual-property/) |
| `gx-architecture-document-25.11.md` | [Gaia-X AD 25.11](https://docs.gaia-x.eu/technical-committee/architecture-document/25.11/) | Gaia-X AISBL | CC BY-NC-ND 4.0 |
| `gx-compliance-document-25.10.md` | [Gaia-X CD 25.10 (Loire)](https://docs.gaia-x.eu/policy-rules-committee/compliance-document/25.10/) | Gaia-X AISBL | CC BY-NC-ND 4.0 |
| `csc-data-model.md` | [CSC Data Model v1.0.0](https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/data-model-bindings.pdf) | Cloud Signature Consortium | CSC License |
| `did-ethr-method-spec.md` | [did:ethr Method Specification](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) | DIF | Apache-2.0 |
| `did-webs-spec.md` | [did:webs Specification](https://github.com/trustoverip/tswg-did-method-webs-specification) | Trust Over IP Foundation | [ToIP License](https://github.com/trustoverip/tswg-did-method-webs-specification/blob/main/LICENSE.md) |
| `keri-draft.md` | [KERI Draft](https://github.com/WebOfTrust/ietf-keri) | WebOfTrust / IETF | Apache 2.0 |

## Download Date

- `oid4vp-1.0.txt`, `did-webs-spec.md`, `keri-draft.md`: **2026-02-24**
- `vc-jose-cose.md`, `sd-jwt-vc.md`, `csc-data-model.md`: **2026-02-25**
- `oid4vp-1.0.md`, `vc-data-model-2.0.md`, `did-core.md`, `sd-jwt-rfc9901.md`, `gx-architecture-document-25.11.md`: **2026-03-10**

## Usage

These files are provided for:

1. **Offline reference** — Access specs without internet connectivity
2. **AI agent context** — Allow AI assistants to reference authoritative specifications
3. **Version pinning** — Ensure consistent spec versions during development

## Updates

To update these references:

```bash
# OID4VP
curl -sL "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html" | \
  python3 -c "..." > oid4vp-1.0.txt

# did:ethr (from GitHub)
# See download script in repository

# KERI
curl -sL "https://raw.githubusercontent.com/WebOfTrust/ietf-keri/main/draft-ssmith-keri.md" \
  -o keri-draft.md
```

## Authoritative Sources

Always refer to the original sources for the most up-to-date and legally binding versions:

- **W3C VC Data Model**: https://www.w3.org/TR/vc-data-model-2.0/
- **W3C DID Core**: https://www.w3.org/TR/did-core/
- **W3C VC-JOSE-COSE**: https://www.w3.org/TR/vc-jose-cose/
- **SD-JWT (RFC 9901)**: https://www.rfc-editor.org/rfc/rfc9901
- **SD-JWT-VC**: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
- **OpenID4VP**: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- **Gaia-X Architecture**: https://docs.gaia-x.eu/technical-committee/architecture-document/25.11/
- **did:ethr**: https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md
- **did:web** *(superseded)*: https://w3c-ccg.github.io/did-method-web/
- **did:webs**: https://trustoverip.github.io/tswg-did-method-webs-specification/
- **KERI**: https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html
- **CSC Data Model**: https://cloudsignatureconsortium.org/resources/

## Disclaimer

These copies are provided "as is" for convenience. The Harbour Credentials project makes no warranties about the accuracy or completeness of these copies. For authoritative interpretations, consult the original specifications and their issuing organizations.
