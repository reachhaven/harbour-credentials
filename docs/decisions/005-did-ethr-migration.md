# ADR-005: Migration from did:web / did:webs to did:ethr

## Status

**Status:** Accepted

## Context

Harbour previously supported two DID methods:

- **did:web** — W3C CCG specification; DID documents hosted at well-known HTTPS URLs
- **did:webs** — ToIP/KERI extension; adds key event logs for cryptographic key history

Both methods rely on web server infrastructure for DID document publication and discovery.
This creates dependencies on DNS, TLS certificate authorities, and hosting availability that
conflict with the project's goal of decentralised, self-sovereign identity.

The ENVITED-X ecosystem requires:

1. Decentralised identity anchoring without web server dependencies
2. Verifiable key rotation history
3. P-256 key support (for EUDI/HAIP compliance)
4. Low-cost operations for credential issuance at scale

## Decision

Replace `did:web` and `did:webs` with **`did:ethr`** (ERC-1056 / EthereumDIDRegistry)
deployed on **Base** (Coinbase L2 rollup).

### Key design choices

| Aspect | Decision |
|--------|----------|
| **Blockchain** | Base (L2 rollup on Ethereum) |
| **Chain ID** | Testnet: 84532 (`0x14a34`), Mainnet: 8453 (`0x2105`) |
| **Contract** | ERC-1056 EthereumDIDRegistry (standard or custom with P-256 support) |
| **P-256 keys** | Registered as on-chain attributes via `setAttribute()` |
| **Controller** | Smart contract manages identity ownership |
| **DID format** | `did:ethr:<chainId>:<ethereumAddress>` |

### DID document structure

The EthereumDIDRegistry resolves DID documents from on-chain events:

- `DIDOwnerChanged` → `controller` field
- `DIDDelegateChanged` → `verificationMethod` entries (delegates)
- `DIDAttributeChanged` → `verificationMethod` entries (attributes like P-256 keys)

## Consequences

### Positive

- **No web server dependency** — DID resolution reads blockchain state
- **Immutable audit trail** — All identity changes recorded on-chain
- **True decentralisation** — No DNS/TLS trust assumptions
- **Low cost** — Base L2 gas fees are minimal
- **Broad tooling** — `ethr-did-resolver` (JS), Python resolver libraries available
- **P-256 compatible** — Keys registered as typed attributes

### Negative

- **Gas costs** — Each identity operation requires a transaction (mitigated by L2 pricing)
- **Key material change** — Ethereum addresses derived from key material (secp256k1 native, P-256 via attributes)
- **Migration effort** — All examples, tests, and documentation require updates
- **KERI features lost** — Key event logs, witness network, pre-rotation not available (acceptable tradeoff)

### Neutral

- **did:key** remains supported for ephemeral/testing identifiers
- **X.509 (x5c)** remains supported for EUDI alignment
- **Archived specs** — did-web-method.txt and did-webs-spec.md retained in docs/specs/references/ for historical reference

## References

- [ERC-1056: Ethereum Lightweight Identity](https://eips.ethereum.org/EIPS/eip-1056)
- [did:ethr Method Specification](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md)
- [Base Documentation](https://docs.base.org/)
- [ADR-001: VC Securing Mechanism](001-vc-securing-mechanism.md)
- [ADR-004: Key Management](004-key-management.md)
