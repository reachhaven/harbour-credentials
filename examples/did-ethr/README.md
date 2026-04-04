# did:ethr DID Documents

Example DID documents for the Harbour identity ecosystem, using `did:ethr` on
**Base** (chain ID `84532` / `0x14a34` for testnet).

These examples assume the Harbour/Base resolver exposes signer-controlled
P-256 keys directly in the resolved DID document.

Behind that resolved view, Harbour uses deterministic keyless DID addresses and
an on-chain `IdentityController` contract that owns the ERC-1056 identities,
verifies relayed P-256-signed instructions, and publishes DID attributes. The
JSON files in this directory show the **resolved DID document surface consumed
by wallets and verifiers**, not the raw registry ownership metadata.

## Entities

| File | Role | DID |
|------|------|-----|
| `harbour-signing-service.did.json` | Signing service (issues credentials) | `did:ethr:0x14a34:0x9c2f...c697` |
| `harbour-trust-anchor.did.json` | Trust anchor (root of trust) | `did:ethr:0x14a34:0xf8ab...38c3` |
| `legal-person-0aa6d7ea-...did.json` | Legal person (participant) | `did:ethr:0x14a34:0xf7ef...dab` |
| `natural-person-550e8400-...did.json` | Natural person (user) | `did:ethr:0x14a34:0x26e4...16c9` |

## DID Document Structure

Each signer DID document follows the Harbour example profile:

- **`#controller`** is a local P-256 `JsonWebKey` and the primary ES256 signing key
- **`#delegate-N`** entries are optional additional P-256 keys
- **`#service-N`** entries represent DID services when present

For Harbour, this means the example JSON output models the signing keys that
matter to wallets and verifiers, while any chain anchoring or recovery state is
left to the Base contract and resolver implementation.

## Key Management

- Trust Anchor, Legal Person, and Natural Person use `#controller` for issuance or consent flows
- The Signing Service uses `#controller` for issuing credentials and `#delegate-1`
  for delegated transaction signing
- All example signatures use ES256 over P-256 keys
- Natural persons approve actions with wallet-held P-256 keys; a relay can
  submit the resulting signed instructions on-chain without requiring users to
  hold Ethereum private keys

## Usage

These DID documents are referenced by:

- `examples/*.json` — Credential examples (issuer, subject, holder)
- `examples/gaiax/*.json` — Gaia-X specific credential examples
- `tests/` — Test fixtures and assertions
- `docs/did-identity-system.md` — detailed Harbour on-chain identity overview
