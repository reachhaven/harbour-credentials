# did:ethr DID Documents

Example DID documents for the Harbour identity ecosystem, using `did:ethr` (ERC-1056)
on **Base** (chain ID `84532` / `0x14a34` for testnet).

## Entities

| File | Role | DID |
|------|------|-----|
| `harbour-signing-service.did.json` | Signing service (issues credentials) | `did:ethr:0x14a34:0x9c2f...c697` |
| `harbour-trust-anchor.did.json` | Trust anchor (root of trust) | `did:ethr:0x14a34:0xf8ab...38c3` |
| `legal-person-0aa6d7ea-...did.json` | Legal person (participant) | `did:ethr:0x14a34:0xf7ef...dab` |
| `natural-person-550e8400-...did.json` | Natural person (user) | `did:ethr:0x14a34:0x26e4...16c9` |

## DID Document Structure

Each document follows the `did:ethr` resolved format:

- **`@context`** includes `secp256k1recovery-2020/v2` for the controller VM
- **`controller`** points to the smart contract that manages identity ownership
- **`#controller`** verification method: `EcdsaSecp256k1RecoveryMethod2020` with `blockchainAccountId`
- **`#delegate-N`** verification methods: P-256 `JsonWebKey` keys registered as on-chain attributes

## Controller

All identities are governed by a smart contract controller:
```
did:ethr:0x14a34:0xC0FFEEbabe000000000000000000000000000001
```
This is a placeholder address — the actual contract will be deployed to Base.

## Key Management

P-256 keys (ES256) are the primary signing keys, registered on-chain via `setAttribute()`.
The secp256k1 controller key provides blockchain-native identity ownership.

## Usage

These DID documents are referenced by:
- `examples/*.json` — Credential examples (issuer, subject, holder)
- `examples/gaiax/*.json` — Gaia-X specific credential examples
- `tests/` — Test fixtures and assertions
