# DID Method Evaluation: did:web vs did:webs

**Version**: 2.0.0
**Date**: 2026-02-26
**Status**: Decision Record

---

## 1. Executive Summary

This document evaluates `did:web` and `did:webs` DID methods for use in Harbour Credentials.

**Decision**: Use `did:webs` for all Harbour identities (infrastructure and participants). The wallet-transparent KERI architecture (§8) enables `did:webs` without requiring wallet-side KERI support.

---

## 2. Overview

| Method | Description |
|--------|-------------|
| **did:web** | DID method that uses web domains for identifier resolution. DID documents are hosted as JSON files at well-known URLs. |
| **did:webs** | Extension of did:web that adds KERI (Key Event Receipt Infrastructure) for cryptographically verifiable key history and rotation. |

---

## 3. Feature Comparison

| Feature | did:web | did:webs |
|---------|---------|----------|
| **Web hosting** | ✅ Simple HTTPS | ✅ HTTPS + KERI AID |
| **Key rotation** | Manual update to did.json | ✅ Cryptographic key event log (KEL) |
| **Key history** | ❌ No verifiable history | ✅ Full verifiable history via KERI |
| **Revocation audit** | Trust web server | ✅ Cryptographically verifiable |
| **Offline verification** | ❌ Requires live fetch | ✅ Can verify with cached KEL |
| **Compromise recovery** | ❌ Difficult (trust server) | ✅ Pre-rotation keys |
| **Spec status** | W3C CCG Stable | ToIP Draft (active development) |
| **Complexity** | Low | High (KERI infrastructure) |

---

## 4. Tooling Maturity (as of 2026-02)

### 4.1 Libraries

| Tool | did:web | did:webs |
|------|---------|----------|
| **Python** | Multiple (did-resolver, etc.) | `keri` v1.3.4 on PyPI ✅ |
| **TypeScript/JS** | did-resolver, veramo | Limited |
| **Universal Resolver** | ✅ Supported | ✅ Supported |

### 4.2 Implementations

| Implementation | Stars | Status | Notes |
|----------------|-------|--------|-------|
| **keripy** (WebOfTrust) | 74★ | Active (v2.0.0-dev5) | Core KERI Python library |
| **did-webs-resolver** (Hyperledger Labs) | 13★ | Active | Reference resolver |
| **Veridian Wallet** (Cardano Foundation) | 139★ | Active | KERI-native mobile wallet |

### 4.3 Specification Status

| Spec | Organization | Status | Last Update |
|------|--------------|--------|-------------|
| **did:web** | W3C CCG | Stable | 2023 |
| **did:webs** | Trust Over IP | Draft | Feb 2026 |
| **KERI** | WebOfTrust/IETF | Draft | Active |

---

## 5. did:webs Advantages

### 5.1 Cryptographic Key History

With did:web, when a key is rotated, the old key is simply replaced. There's no cryptographic proof of what the previous key was or when it was rotated.

With did:webs, every key event (rotation, revocation) is recorded in a Key Event Log (KEL) that is cryptographically chained:

```
Inception Event → Rotation Event 1 → Rotation Event 2 → ...
```

Each event is signed by the previous key, creating an unbroken chain of custody.

### 5.2 Pre-rotation (Compromise Recovery)

did:webs supports **pre-rotation**: when creating a key, you also commit to the hash of the next key. If your current key is compromised, the attacker cannot rotate to their own key because they don't know your pre-committed next key.

### 5.3 Offline Verification

With did:web, verifiers must fetch the current DID document from the web server each time. With did:webs, the KEL can be cached and verified offline—the cryptographic chain provides assurance even without network access.

---

## 6. did:webs Concerns

### 6.1 Specification Maturity

- No formal 1.0 release from Trust Over IP
- Still evolving (breaking changes possible)
- Limited interoperability testing

### 6.2 Operational Complexity

did:webs requires KERI infrastructure:

- **Witnesses**: Nodes that sign and store key events (for availability)
- **Watchers**: Nodes that monitor for duplicity (for security)
- **KERI Agent**: Software to manage key events

This is significantly more complex than hosting a `did.json` file.

### 6.3 Wallet Support

| Wallet | did:web | did:webs |
|--------|---------|----------|
| Altme | ✅ | ❌ |
| Sphereon | ✅ | ❌ |
| walt.id | ✅ | ❌ |
| Veridian | ❌ | ✅ |

Most VC wallets support did:web natively. did:webs support is limited to KERI-specific wallets.

---

## 7. Current Harbour Implementation (did:webs)

Harbour uses `did:webs` identifiers for all entities. The wallet-transparent
KERI architecture (§8) provides cryptographic key history without requiring
wallet-side KERI support.

### 7.1 DID Structure

From [`examples/did-webs/`](../../examples/did-webs/):

| Entity | DID | Keys |
|--------|-----|------|
| Trust Anchor | `did:webs:reachhaven.com:ENVSnGVU_q39C0Lsim8CtXP_c0TbQW7BBndLVnBeDPXo` | `#key-1` (assertionMethod) |
| Signing Service | `did:webs:harbour.reachhaven.com:Er9_mnFstIFyj7JXhHtf7BTHAaUXkaFoJQq96z8WycDQ` | `#key-1` (assertionMethod), `#key-2` (capabilityDelegation) |
| Participants | `did:webs:participants.harbour.reachhaven.com:legal-persons:<uuid>:<AID>` | `#key-1` (assertionMethod) |
| Users | `did:webs:users.altme.example:natural-persons:<uuid>:<AID>` | `#key-1` (assertionMethod) |

### 7.2 Trust Model

- Trust Anchor (`did:webs:reachhaven.com:ENVSnGVU...`) is the root of trust
- Signing Service is the sole credential issuer, authorized via evidence VPs
- Trust Anchor has a `LinkedCredentialService` endpoint for its self-signed credential
- Naming policy: all DID paths use UUID segments (never real names or org names)

### 7.3 Credential Issuance Chain

1. Trust Anchor authorizes org → VP with self-signed LegalPersonCredential
2. Org authorizes employee → VP with org's LegalPersonCredential (SD-JWT, PII redacted)
3. Signing Service issues all credentials with authorization VPs as evidence

---

## 8. Wallet-Transparent did:webs Architecture

A key architectural insight: **wallets don't need native KERI support** if Harbour operates the KERI infrastructure.

### 8.1 The Insight

KERI key events are just signed messages. Any wallet that can sign with ES256/P-256 can sign a KERI rotation event—it doesn't need to "understand" KERI semantics.

```
┌─────────────────────────────────────────────────────────────────┐
│                         HARBOUR                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │
│  │   KERI      │  │  Witnesses  │  │  did:webs Resolution    │  │
│  │   Agent     │  │  (3+ nodes) │  │  & KEL Management       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              ▲
                              │ Signs rotation events,
                              │ VPs, etc. (just ES256)
                              │
┌─────────────────────────────────────────────────────────────────┐
│                      ANY VC WALLET                               │
│                                                                  │
│     ┌──────────────────┐      Wallet only needs to:             │
│     │   P-256 Key      │      ✓ Hold private key                │
│     │   (ES256)        │      ✓ Sign payloads when asked        │
│     └──────────────────┘      ✗ No KERI awareness needed        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 8.2 Protocol Flow

| Step | Wallet Action | Harbour Action |
|------|---------------|----------------|
| **DID Creation** | Generate P-256 keypair, share public key | Create KERI inception event, publish to witnesses |
| **Normal Use** | Sign VPs with P-256 key | Resolve did:webs, verify signatures against KEL |
| **Key Rotation** | Sign rotation payload with OLD key | Construct rotation event, coordinate witnesses, update KEL |
| **Verification** | (nothing) | Full KERI verification with key history |

### 8.3 Rotation Protocol

When a user needs to rotate their key:

1. **User** generates new P-256 keypair in wallet
2. **Harbour** constructs KERI rotation event payload
3. **Harbour** sends payload to wallet for signing (standard ES256 signature request)
4. **Wallet** signs with OLD key (wallet doesn't know this is "KERI"—it's just a signature)
5. **Harbour** publishes signed rotation event to KERI witnesses
6. **Harbour** updates did:webs document

The wallet's view: "Harbour asked me to sign something, I signed it."

### 8.4 Implications

| Concern | Resolution |
|---------|------------|
| Wallet support | ✅ Any ES256-capable wallet works |
| Complexity | Contained in Harbour infrastructure |
| User experience | No change from did:web |
| Cryptographic guarantees | Full KERI benefits (verifiable key history) |
| Operational burden | Harbour operates witnesses (can be distributed) |

### 8.5 Considerations

1. **Trust**: Users must trust Harbour to correctly manage their KERI events
2. **Availability**: Harbour witnesses must be highly available
3. **Signing UX**: Wallet must support signing arbitrary payloads (most do)
4. **Pre-rotation**: Still requires Harbour to manage pre-rotation commitments

This architecture provides KERI's cryptographic benefits while maintaining compatibility with the existing wallet ecosystem.

---

## 9. Migration Status

Migration to `did:webs` is complete for identity modeling. All example
identities, DID documents, and credential examples now use `did:webs`.

### Completed

- [x] All Harbour infrastructure DIDs use `did:webs` (Trust Anchor, Signing Service)
- [x] All participant/user DIDs use `did:webs` with UUID paths
- [x] DID documents created for all actors (`examples/did-webs/`)
- [x] Credential examples updated with `did:webs` issuers and subjects
- [x] Wallet-transparent architecture designed (§8) — any ES256 wallet works

### Remaining Infrastructure Work

- [ ] KERI witness infrastructure deployed (Harbour-operated, 3+ witnesses recommended)
- [ ] Rotation signing protocol implemented in Harbour
- [ ] did:webs resolver integrated for production verification (or use Universal Resolver)

---

## 10. Recommendation

### Current

**Use did:webs** with the wallet-transparent KERI architecture (§8):

1. ✅ P-256 keys (ES256 algorithm)
2. ✅ Stable fragment IDs for key references (`#key-1`, `#key-2`)
3. ✅ Trust Anchor with self-signed credential (root of trust)
4. ✅ Signing Service as sole credential issuer
5. ✅ UUID-only DID paths (privacy-preserving)
6. ✅ Wallet-transparent KERI (any ES256 wallet works)

### Remaining Infrastructure Work

- [ ] KERI witness infrastructure deployed (Harbour-operated, 3+ witnesses)
- [ ] Rotation signing protocol implemented
- [ ] did:webs resolver integrated for production verification
- [x] ~~3+ wallets support did:webs~~ **NOT REQUIRED** — wallet-transparent architecture

---

## 11. References

### Specifications

- [did:web Method Specification](https://w3c-ccg.github.io/did-method-web/) (W3C CCG)
- [did:webs Method Specification](https://trustoverip.github.io/tswg-did-method-webs-specification/) (Trust Over IP)
- [KERI Specification](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html) (IETF Draft)
- [W3C DID Core](https://www.w3.org/TR/did-core/) (W3C Recommendation)

### Implementations

- [keripy](https://github.com/WebOfTrust/keripy) - Python KERI implementation
- [did-webs-resolver](https://github.com/hyperledger-labs/did-webs-resolver) - Hyperledger Labs
- [Veridian Wallet](https://github.com/cardano-foundation/veridian-wallet) - KERI-native wallet

### Local Copies

Reference specifications are stored in `docs/specs/references/` for offline access:

- `did-web-method.txt` - did:web specification
- `did-webs-spec.md` - did:webs specification (concatenated)
- `keri-draft.md` - KERI IETF draft
- `oid4vp-1.0.txt` - OpenID4VP specification

---

## 12. Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2026-02-26 | Migrated to did:webs; updated section 7 for current implementation |
| 1.1.0 | 2026-02-24 | Updated recommendation based on wallet-transparent KERI insight |
| 1.0.0 | 2026-02-24 | Initial evaluation and decision |
