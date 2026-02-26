# Reference Specifications

This directory contains downloaded copies of external specifications for offline reference and AI agent access.

## ⚠️ Important Notice

**These files are NOT original works of this project.**

They are copies of specifications published by their respective standards organizations. The original terms, conditions, and licenses of each specification apply.

## Files

| File | Source | Organization | License |
|------|--------|--------------|---------|
| `oid4vp-1.0.txt` | [OpenID4VP 1.0](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) | OpenID Foundation | [OpenID IPR](https://openid.net/intellectual-property/) |
| `vc-jose-cose.md` | [VC-JOSE-COSE](https://www.w3.org/TR/vc-jose-cose/) | W3C | [W3C Document License](https://www.w3.org/copyright/document-license-2023/) |
| `sd-jwt-vc.md` | [SD-JWT-VC draft-14](https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/) | IETF | [IETF Trust](https://trustee.ietf.org/license-info) |
| `csc-data-model.md` | [CSC Data Model v1.0.0](https://cloudsignatureconsortium.org/wp-content/uploads/2025/10/data-model-bindings.pdf) | Cloud Signature Consortium | CSC License |
| `did-web-method.txt` | [did:web Specification](https://w3c-ccg.github.io/did-method-web/) | W3C CCG | [W3C Document License](https://www.w3.org/copyright/document-license-2023/) |
| `did-webs-spec.md` | [did:webs Specification](https://github.com/trustoverip/tswg-did-method-webs-specification) | Trust Over IP Foundation | [ToIP License](https://github.com/trustoverip/tswg-did-method-webs-specification/blob/main/LICENSE.md) |
| `keri-draft.md` | [KERI Draft](https://github.com/WebOfTrust/ietf-keri) | WebOfTrust / IETF | Apache 2.0 |

## Download Date

- `oid4vp-1.0.txt`, `did-web-method.txt`, `did-webs-spec.md`, `keri-draft.md`: **2026-02-24**
- `vc-jose-cose.md`, `sd-jwt-vc.md`, `csc-data-model.md`: **2026-02-25**

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

# did:web
curl -sL "https://w3c-ccg.github.io/did-method-web/" | \
  python3 -c "..." > did-web-method.txt

# did:webs (from GitHub)
# See download script in repository

# KERI
curl -sL "https://raw.githubusercontent.com/WebOfTrust/ietf-keri/main/draft-ssmith-keri.md" \
  -o keri-draft.md
```

## Authoritative Sources

Always refer to the original sources for the most up-to-date and legally binding versions:

- **OpenID4VP**: https://openid.net/specs/openid-4-verifiable-presentations-1_0.html
- **did:web**: https://w3c-ccg.github.io/did-method-web/
- **did:webs**: https://trustoverip.github.io/tswg-did-method-webs-specification/
- **KERI**: https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html
- **W3C DID Core**: https://www.w3.org/TR/did-core/
- **W3C VC Data Model**: https://www.w3.org/TR/vc-data-model-2.0/
- **W3C VC-JOSE-COSE**: https://www.w3.org/TR/vc-jose-cose/
- **SD-JWT-VC**: https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/
- **SD-JWT (RFC 9901)**: https://www.rfc-editor.org/rfc/rfc9901
- **CSC Data Model**: https://cloudsignatureconsortium.org/resources/

## Disclaimer

These copies are provided "as is" for convenience. The Harbour Credentials project makes no warranties about the accuracy or completeness of these copies. For authoritative interpretations, consult the original specifications and their issuing organizations.
