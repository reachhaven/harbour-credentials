# DID Method Evaluation: did:ethr

> **Decision**: Harbour uses `did:ethr` on **Base** (L2 rollup) as its primary
> DID method, replacing the previously evaluated `did:web` and `did:webs`.
>
> This document summarizes the rationale and the current Harbour resolver profile.

## Glossary

| Term | Definition |
|------|-----------|
| **did:ethr** | DID method anchored on Ethereum-compatible blockchains via ERC-1056-style contract state. |
| **did:web** | *(Superseded)* DID method that uses web domains for identifier resolution. |
| **did:webs** | *(Superseded)* Extension of did:web that adds KERI for cryptographically verifiable key history. |
| **did:key** | Ephemeral DID method encoding a single public key. Used for testing and wallet-generated identifiers. |
| **ERC-1056** | Ethereum Improvement Proposal defining the EthereumDIDRegistry smart contract pattern. |
| **Base** | Coinbase L2 rollup on Ethereum, providing low-cost transactions with Ethereum security. |

## Why did:ethr?

### Comparison with Previous Methods

| Feature | did:web | did:webs | did:ethr |
|---------|---------|----------|----------|
| Resolution | HTTPS fetch | HTTPS + KERI | Base contract state + resolver |
| Key rotation | Replace file | KEL append | On-chain updates |
| Revocation | Delete document | KEL revocation | Contract state / resolver policy |
| Offline verification | ❌ | ✅ (via KEL) | ✅ (via cached events/state) |
| Infrastructure | Web server | Web server + KERI node | EVM node + resolver |
| Decentralisation | ❌ (DNS/TLS) | Partial (KERI witnesses) | ✅ (blockchain anchored) |
| P-256 support | Native | Native | First-class in Harbour profile |
| Wallet support | Broad | Limited (KERI wallets) | Broad for ES256 consumers |
| Cost per operation | Free (hosting) | Free (hosting) | Gas fees (low on Base L2) |

### Key Advantages

1. **No web server dependency** — DID documents are resolved from Base state, not HTTPS endpoints
2. **Cryptographic key history** — Key changes are anchored on-chain
3. **True decentralisation** — No reliance on DNS or TLS certificate authorities
4. **P-256-first examples** — Resolver output surfaces P-256 controller keys directly
5. **Low cost on Base** — L2 gas fees are much lower than Ethereum mainnet
6. **Composability** — Service/program DIDs can be modelled as externally controlled resources

## DID Format

```text
did:ethr:<chainId>:<address>

# Base Sepolia Testnet (development)
did:ethr:0x14a34:0x71C7656EC7ab88b098defB751B7401B5f6d8976F

# Base Mainnet (production)
did:ethr:0x2105:0x71C7656EC7ab88b098defB751B7401B5f6d8976F
```

Depending on resolver/tooling, production DIDs may also be rendered with an
explicit EIP-155 network segment such as `did:ethr:eip155:8453:<address>`.
The checked-in Harbour examples keep the hexadecimal chain-ID form because that
matches the current example fixtures and downstream validation setup.

## DID Document Resolution

Harbour examples assume a project-specific resolver profile on top of Base:

- **signer DIDs** expose a local P-256 `JsonWebKey` as `#controller`
- **optional secondary keys** appear as `#delegate-N`
- **resource DIDs** (programs, services) may use the root DID Core `controller`
  property to point at an owning DID instead of exposing a local signing key

These JSON examples represent the **resolved verifier-facing DID document**, not
the raw ERC-1056 owner state. In the Harbour identity architecture, managed DID
addresses are deterministic and keyless, while an on-chain `IdentityController`
contract owns the ERC-1056 identities, verifies relayed P-256-signed
instructions, and publishes the DID document attributes that the resolver turns
into the JSON-LD surface shown here.

Example signer DID output:

```json
{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    {
      "JsonWebKey": "https://w3id.org/security#JsonWebKey",
      "publicKeyJwk": {
        "@id": "https://w3id.org/security#publicKeyJwk",
        "@type": "@json"
      }
    }
  ],
  "id": "did:ethr:0x14a34:0x71C7656EC7ab88b098defB751B7401B5f6d8976F",
  "verificationMethod": [
    {
      "id": "...#controller",
      "type": "JsonWebKey",
      "controller": "...",
      "publicKeyJwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
    }
  ],
  "authentication": ["...#controller"],
  "assertionMethod": ["...#controller"]
}
```

## Key Management

| Context | DID Method | kid Format |
|---------|-----------|------------|
| **EUDI** | X.509 | `x5c` header (no kid) |
| **Gaia-X / Harbour** | `did:ethr` | `did:ethr:0x14a34:<address>#controller` |
| **Testing** | `did:key` | `did:key:zDn...#zDn...` |

### Identity Architecture

| Role | DID Pattern | Key Usage |
|------|-------------|-----------|
| Signing Service | `did:ethr:0x14a34:<service-address>` | `#controller` (assertionMethod), `#delegate-1` (capabilityDelegation) |
| Trust Anchor | `did:ethr:0x14a34:<anchor-address>` | `#controller` (assertionMethod) |
| Participants | `did:ethr:0x14a34:<participant-address>` | `#controller` (assertionMethod) |
| Users | `did:ethr:0x14a34:<user-address>` | `#controller` (assertionMethod) |

Natural participants use standard SSI wallets and sign authorization material
with P-256 keys; they do not need Ethereum private keys. A relay submits the
resulting instructions on-chain, and `IdentityController` enforces nonce and
threshold checks before updating ERC-1056 state.

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

1. **Anchoring identifiers on Base**
2. **Registering P-256 keys** so the resolver can surface them in the DID document
3. **Updating credential examples** to use `did:ethr` identifiers and `#controller` kids
4. **Deploying resolver support** for the Harbour Base profile

See `examples/did-ethr/` for migrated DID document examples.

## References

- [did:ethr Method Specification](references/did-ethr-method-spec.md) (local reference copy)
- [ERC-1056: Ethereum Lightweight Identity](https://eips.ethereum.org/EIPS/eip-1056)
- [ethr-did-resolver](https://github.com/decentralized-identity/ethr-did-resolver) (baseline reference)
- [Base Documentation](https://docs.base.org/)
- `docs/did-identity-system.md` — Harbour-specific on-chain identity architecture overview

### Archived Specifications

These specifications are retained for historical reference but are no longer the active DID method:

- `did-web-method.txt` — did:web specification (W3C CCG) *(superseded)*
- `did-webs-spec.md` — did:webs specification (ToIP) *(superseded)*
- `references/did-ethr-method-spec.md` — did:ethr method specification (active reference baseline)
