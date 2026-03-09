# DID Method Evaluation: did:ethr

> **Decision**: Harbour uses `did:ethr` (ERC-1056 / EthereumDIDRegistry) on **Base** (L2 rollup)
> as its primary DID method, replacing the previously evaluated `did:web` and `did:webs`.
>
> This document summarizes the evaluation and rationale.

## Glossary

| Term | Definition |
|------|-----------|
| **did:ethr** | DID method anchored on Ethereum-compatible blockchains via ERC-1056 (EthereumDIDRegistry). Supports key rotation, delegate management, and attribute registration through on-chain events. |
| **did:web** | *(Superseded)* DID method that uses web domains for identifier resolution. DID documents hosted as JSON files at well-known URLs. |
| **did:webs** | *(Superseded)* Extension of did:web that adds KERI for cryptographically verifiable key history. |
| **did:key** | Ephemeral DID method encoding a single public key. Used for testing and wallet-generated identifiers. |
| **ERC-1056** | Ethereum Improvement Proposal defining the EthereumDIDRegistry smart contract. |
| **Base** | Coinbase L2 rollup on Ethereum, providing low-cost transactions with Ethereum security. |

## Why did:ethr?

### Comparison with Previous Methods

| Feature | did:web | did:webs | did:ethr |
|---------|---------|----------|----------|
| Resolution | HTTPS fetch | HTTPS + KERI | On-chain events |
| Key rotation | Replace file | KEL append | On-chain `changeOwner` / `setAttribute` |
| Revocation | Delete document | KEL revocation | `revokeDelegate` / `changeOwner(0x0)` |
| Offline verification | ❌ | ✅ (via KEL) | ✅ (via cached events) |
| Infrastructure | Web server | Web server + KERI node | EVM node (public RPCs available) |
| Decentralisation | ❌ (DNS/TLS) | Partial (KERI witnesses) | ✅ (blockchain) |
| P-256 support | Native | Native | Via `setAttribute()` (delegate keys) |
| Wallet support | Broad | Limited (KERI wallets) | Broad (ethers.js, MetaMask, etc.) |
| Cost per operation | Free (hosting) | Free (hosting) | Gas fees (low on Base L2) |

### Key Advantages

1. **No web server dependency** — DID documents are resolved from on-chain events, not HTTPS endpoints
2. **Cryptographic key history** — All key changes are permanently recorded on-chain
3. **True decentralisation** — No reliance on DNS or TLS certificate authorities
4. **P-256 key registration** — Custom smart contract registers P-256 keys as on-chain attributes
5. **Low cost on Base** — L2 gas fees are orders of magnitude cheaper than Ethereum mainnet
6. **Broad ecosystem support** — `ethr-did-resolver` available for JS/TS, Python resolver libraries available

## DID Format

```
did:ethr:<chainId>:<address>

# Base Sepolia Testnet (development)
did:ethr:0x14a34:0x71C7656EC7ab88b098defB751B7401B5f6d8976F

# Base Mainnet (production)
did:ethr:0x2105:0x71C7656EC7ab88b098defB751B7401B5f6d8976F
```

## DID Document Resolution

The `ethr-did-resolver` reconstructs DID documents by reading `DIDAttributeChanged`,
`DIDDelegateChanged`, and `DIDOwnerChanged` events from the EthereumDIDRegistry contract.

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/suites/secp256k1recovery-2020/v2"
  ],
  "id": "did:ethr:0x14a34:0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
  "controller": "did:ethr:0x14a34:0xC0FFEEbabe000000000000000000000000000001",
  "verificationMethod": [
    {
      "id": "...#controller",
      "type": "EcdsaSecp256k1RecoveryMethod2020",
      "controller": "...",
      "blockchainAccountId": "eip155:84532:0x71C7656EC7ab88b098defB751B7401B5f6d8976F"
    },
    {
      "id": "...#delegate-1",
      "type": "JsonWebKey",
      "controller": "...",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
    }
  ],
  "authentication": ["...#controller", "...#delegate-1"],
  "assertionMethod": ["...#controller", "...#delegate-1"]
}
```

## Key Management

| Context | DID Method | kid Format |
|---------|-----------|------------|
| **EUDI** | X.509 | `x5c` header (no kid) |
| **Gaia-X** | `did:ethr` | `did:ethr:0x14a34:<address>#delegate-1` |
| **Testing** | `did:key` | `did:key:zDn...#zDn...` |

### Identity Architecture

| Role | DID Pattern | Key Usage |
|------|-------------|-----------|
| Signing Service | `did:ethr:0x14a34:<service-address>` | `#delegate-1` (assertionMethod), `#delegate-2` (capabilityDelegation) |
| Trust Anchor | `did:ethr:0x14a34:<anchor-address>` | `#delegate-1` (assertionMethod) |
| Participants | `did:ethr:0x14a34:<participant-address>` | `#delegate-1` (assertionMethod) |
| Users | `did:ethr:0x14a34:<user-address>` | `#delegate-1` (assertionMethod) |

## Network Configuration

| Network | Chain ID | Hex | Use |
|---------|----------|-----|-----|
| Base Sepolia | 84532 | 0x14a34 | Development, testing |
| Base Mainnet | 8453 | 0x2105 | Production |

### RPC Endpoints

- **Sepolia**: `https://sepolia.base.org`
- **Mainnet**: `https://mainnet.base.org`

## Migration from did:web / did:webs

The migration from did:web/did:webs to did:ethr involves:

1. **Deriving Ethereum addresses** from existing P-256 key material
2. **Registering P-256 keys** as on-chain attributes via `setAttribute()`
3. **Updating all credential examples** to use `did:ethr` identifiers
4. **Deploying EthereumDIDRegistry** (or using existing deployment) on Base

See `examples/did-ethr/` for migrated DID document examples.

## References

- [did:ethr Method Specification](https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md) (DIF)
- [ERC-1056: Ethereum Lightweight Identity](https://eips.ethereum.org/EIPS/eip-1056)
- [ethr-did-resolver](https://github.com/decentralized-identity/ethr-did-resolver) (JavaScript)
- [Base Documentation](https://docs.base.org/)

### Archived Specifications

These specifications are retained for historical reference but are no longer the active DID method:

- `did-web-method.txt` — did:web specification (W3C CCG) *(superseded)*
- `did-webs-spec.md` — did:webs specification (ToIP) *(superseded)*
- `did-ethr-method-spec.md` — did:ethr method specification (active)
