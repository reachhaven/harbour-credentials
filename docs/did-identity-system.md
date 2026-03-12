# DID Identity System: did:ethr + P-256 + IdentityController

## Overview

Haven uses `did:ethr:eip155:8453` (Base mainnet, [ERC-1056](https://github.com/uport-project/ethr-did-registry)) as the single DID method for all dataspace participants. ERC-1056 is a battle-tested registry (deployed since 2018) with established resolver tooling (ethr-did-resolver, universal resolver).

The key design challenge: natural participants (admins, users) use standard SSI wallets (with OID4VC interface), not Ethereum wallets. They cannot submit Ethereum transactions directly without complicating UX or severely limiting compatible wallets. This is a limitation of interface protocols and key types. The `IdentityController` contract bridges this gap.

## Why P-256?

P-256 (secp256r1, ES256) is the dominant curve in SSI/OIDC ecosystems — hardware security keys (FIDO2/WebAuthn), mobile secure enclaves, and many OID4VC wallets suport P-256 natively. Ethereum wallets use secp256k1, which is incompatible. Rather than requiring participants to hold Ethereum wallets, Haven verifies P-256 signatures on-chain using the **EIP-7212 precompile** (available on Base).

## ERC-1056 and DID Documents

ERC-1056 stores DID document data as on-chain events. Resolvers replay these events to construct a DID document. The two relevant operations:

- `setAttribute(identity, name, value, validity)` — publishes a DID document attribute (e.g., a public key or service endpoint) as an event
- `changeOwner(identity, newOwner)` — transfers control of the DID

Each Ethereum address implicitly has a DID: `did:ethr:eip155:8453:0x<addr>`. By default, the address itself is its own controller. Haven overrides this by calling `changeOwner` to make `IdentityController` the ERC-1056 owner of all managed identities.

## Address Model

Managed DID addresses are **deterministic and keyless** — there is no corresponding Ethereum private key:

| Entity                   | Address derivation                                          |
| ------------------------ | ----------------------------------------------------------- |
| Trust Anchor (TA)        | `address(uint160(keccak256(abi.encode(taAddress, nonce))))` |
| Legal Participant (LP)   | same pattern                                                |
| Natural Participant (NP) | same pattern                                                |

`IdentityController` is set as `owners[addr]` in ERC-1056 for all of these. This means only `IdentityController` can update their DID documents — and it only does so after verifying a valid P-256 signature from an authorized key.

While the TA (or at least one party of a consortium) must have a full Ethereum account to submit everyone's transactions to the blockchain, the TA also gets a keyless DID to allow easy management by its admins.

## P-256 Keys in DID Documents

P-256 public keys are stored in DID documents via `setAttribute` using `JsonWebKey2020` encoding:

- **Admin keys** (LP/TA admins) → `verificationMethod`, `assertionMethod`, `authentication` (in their NP DID and in their LP/TA DID) — authorize management operations on behalf of the entity
- **NP keys** → `verificationMethod`, `assertionMethod`, `authentication` (in their NP DID) — NPs sign VPs for credential presentation and on-chain authorization

The contract stores key hashes (`keccak256(qx || qy)`) in its own mapping for efficient on-chain lookup, separate from the DID document attributes.

## IdentityController: How It Works

`IdentityController` is a UUPS-upgradeable contract that:

1. **Owns** TA/LP/NP addresses in ERC-1056
2. **Stores** authorized P-256 key hashes per DID address
3. **Verifies** P-256 signatures on-chain (EIP-7212)
4. **Translates** verified instructions into ERC-1056 calls

### Instruction Flow

NPs never submit Ethereum transactions directly. The flow:

1. NP constructs an instruction payload (pipe-delimited text, HI1 format)
2. NP signs it with their P-256 key — specifically as the nonce inside a JWT VP (the JWT's nonce claim contains `sha256(instruction)` as a hex string)
3. Anyone (TA, org relay, third party relay) submits `(jwtEvidence[], instruction)` (array because signature threshold can be set >1) to `IdentityController.execute()`
4. Contract verifies: correct nonce, authorized key hashes, valid P-256 JWT signatures
5. Contract dispatches the instruction → calls ERC-1056

The relay is permissionless — anyone can submit a valid signed instruction. This ensures no single point of failure and makes the system resistant to censorship.

### Replay Protection

Each DID has a sequential `nonces[did]` counter stored in the contract. The instruction includes the current nonce value; the contract rejects any instruction with a mismatched nonce and increments it on success.

### M-of-N Multisig

Each DID has a configurable threshold (`thresholds[did]`). `execute()` requires at least `threshold` distinct authorized P-256 signatures in the evidence array. Threshold 0 means the identity is deactivated. This can be used by NPs, but is meant to provide a more resilient identity to large LPs.

### Supported Instructions

| Instruction      | Effect                                                         |
| ---------------- | -------------------------------------------------------------- |
| `SetAttr`        | `registry.setAttribute(...)` — publish DID document attribute  |
| `RevokeAttr`     | `registry.revokeAttribute(...)`                                |
| `AddDelegate`    | `registry.addDelegate(...)` — add a delegate on-chain key      |
| `RevokeDelegate` | `registry.revokeDelegate(...)`                                 |
| `AddKey`         | add P-256 key hash to controller key set                       |
| `RemoveKey`      | remove P-256 key hash (blocked if it would undercut threshold) |
| `SetThreshold`   | update M-of-N threshold                                        |
| `Deactivate`     | `registry.changeOwner(did, address(0))`, threshold → 0         |

### JWT Evidence Structure

Each piece of evidence is a P-256-signed JWT. The contract reconstructs the JWT message on-chain from caller-supplied parts:

```text
msgHash = sha256(base64url(header) + "." + base64url(prefix + sha256Hex(instruction) + suffix))
```

The `sha256Hex(instruction)` is the nonce embedded in the JWT payload. This ties the JWT signature cryptographically to the specific instruction being executed — the P-256 signature provably covers the instruction content.

## Bootstrap

A new DID is bootstrapped via `bootstrapIdentityFull(salt, adminQx, adminQy)` (admin in the sense of controller):

1. Deploys a `DIDHandover` contract via CREATE2 (deterministic address derived from `keccak256(msg.sender || salt)`)
2. `DIDHandover` constructor automatically calls `registry.changeOwner(self, identityController)` — transfers ERC-1056 ownership
3. `IdentityController` records the first admin P-256 key hash and sets threshold to 1
4. `IdentityController` also sets the admin key as `verificationMethod`, `assertionMethod`, `authentication` to the DID document (ERC-1056)

The resulting DID address is the `DIDHandover` contract address. It has no private key; only `IdentityController` can act on it.

## Summary of Relationships

```text
P-256 key (SSI wallet)
    │ signs JWT VP (nonce = sha256(instruction))
    ▼
IdentityController.execute(evs[], instruction)
    │ verifies P-256 sig on-chain (EIP-7212)
    │ checks keyHash ∈ controllerKeys[did]
    │ checks nonce, threshold
    ▼
EthereumDIDRegistry (ERC-1056)
    │ emits attribute/delegate events
    ▼
DID document (did:ethr:eip155:8453:0x<addr>)
    resolved by ethr-did-resolver
```
