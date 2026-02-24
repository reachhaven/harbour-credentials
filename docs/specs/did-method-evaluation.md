# DID Method Evaluation: did:web vs did:webs

**Version**: 1.0.0  
**Date**: 2026-02-24  
**Status**: Decision Record

---

## 1. Executive Summary

This document evaluates `did:web` and `did:webs` DID methods for use in Harbour Credentials and the SimpulseID ecosystem.

**Decision**: Use `did:web` for v1 with documented key rotation practices. Consider `did:webs` migration for v2 when tooling matures.

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

## 7. Current SimpulseID Implementation (did:web)

Our current did:web implementation includes key rotation best practices:

### 7.1 Key Rotation Model

From `examples/did-web/README.md`:

1. **Stable fragment IDs**: Key fragments (`#wallet-key-1`) never change
2. **Revocation timestamps**: Old keys marked with `"revoked": "<timestamp>"`
3. **Active key tracking**: Only non-revoked keys in `assertionMethod`

```json
{
  "verificationMethod": [
    {
      "id": "did:web:example.com:users:alice#wallet-key-1",
      "type": "JsonWebKey",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", ... },
      "revoked": "2026-01-15T00:00:00Z"
    },
    {
      "id": "did:web:example.com:users:alice#wallet-key-2",
      "type": "JsonWebKey",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", ... }
    }
  ],
  "assertionMethod": [
    "did:web:example.com:users:alice#wallet-key-2"
  ]
}
```

### 7.2 Trust Model

- All DIDs controlled by `did:web:did.ascs.digital:services:trust-anchor`
- ASCS operates the web server (centralized trust anchor)
- Signatures are attestations, not control grants

### 7.3 Limitations

- Key history not cryptographically verifiable
- Must trust ASCS to honestly report revocations
- No protection against server compromise

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

## 9. Migration Path to did:webs

If/when did:webs matures, migration could follow this path:

### Phase 1: Dual Resolution
- Maintain did:web documents as-is
- Add KERI AID to DID documents
- Resolve both methods, prefer did:webs when available

### Phase 2: KERI Infrastructure
- Deploy KERI witnesses (minimum 3 recommended)
- Set up watchers for duplicity detection
- Migrate high-value DIDs (trust anchor, services) first

### Phase 3: Full Migration
- Convert all user DIDs to did:webs
- Deprecate did:web-only resolution
- Update wallet integrations

### Prerequisites for Migration (Updated)

Based on the wallet-transparent architecture (§8), migration prerequisites are significantly reduced:

- [ ] KERI witness infrastructure deployed (Harbour-operated, 3+ witnesses recommended)
- [ ] Rotation signing protocol implemented in Harbour
- [ ] did:webs resolver integrated (or use Universal Resolver)
- [x] ~~3+ major wallets support did:webs~~ **NOT REQUIRED** — Any ES256 wallet works
- [x] ~~did:webs spec reaches 1.0~~ **NOT BLOCKING** — Architecture is spec-compatible

---

## 10. Recommendation

### For v1 (Current)

**Use did:web** with the following practices:

1. ✅ P-256 keys (ES256 algorithm)
2. ✅ Stable fragment IDs for key references
3. ✅ Revocation timestamps (never delete keys)
4. ✅ Trust anchor pattern (centralized control with attestations)
5. ✅ Document key rotation procedures

### For v2 (Future)

**Implement wallet-transparent did:webs**:

1. Deploy KERI infrastructure in Harbour (witnesses, watchers)
2. Implement rotation signing protocol (wallet signs KERI events as regular ES256 payloads)
3. Add did:webs resolution alongside did:web

**Key insight**: We don't need to wait for wallet ecosystem support. Harbour can provide did:webs benefits to **any ES256-capable wallet** by operating the KERI infrastructure server-side. The wallet just signs—Harbour handles the KERI complexity.

### Migration Prerequisites (Updated)

- [ ] KERI witness infrastructure deployed (Harbour-operated)
- [ ] Rotation signing protocol implemented
- [ ] did:webs resolver integrated
- [ ] ~~3+ wallets support did:webs~~ (NOT required with transparent architecture)

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
| 1.1.0 | 2026-02-24 | Updated recommendation based on wallet-transparent KERI insight |
| 1.0.0 | 2026-02-24 | Initial evaluation and decision |
