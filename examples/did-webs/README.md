# did:webs Example Documents

This folder contains static example DID documents for the `did:webs` identifiers
used in `examples/*.json`.

## Scope and Boundary

- These files are modeling examples for Harbour v1.
- This repository does **not** resolve `did:webs` identifiers and does **not**
  validate `keri.cesr` streams.
- Integrators must host corresponding `did.json` and `keri.cesr` resources in
  production according to the `did:webs` method specification.

## Naming Policy

All identifiers use **UUID path segments** — never real names, organization names,
or other identifying information in the DID path. This prevents DID IRIs from
leaking identity at the public layer.

## Credential Issuance Model

The Harbour Signing Service is the **sole issuer** of all credentials. It uses
two keys in its DID document:

| Key | Relationship | Purpose |
|-----|-------------|---------|
| `#key-1` | `assertionMethod` | Signs all issued credentials |
| `#key-2` | `capabilityDelegation` | Signs delegated blockchain transactions |

Authorization is proven via `CredentialEvidence` VPs:

- **LegalPersonCredential**: Trust Anchor presents VP with its self-signed
  LegalPersonCredential (root of trust, publicly resolvable via
  `LinkedCredentialService`).
- **NaturalPersonCredential**: Organization presents VP with its
  LegalPersonCredential (SD-JWT, sensitive fields redacted).

## Example Identities

### Server-side (Harbour infrastructure)

| Actor | DID | File |
|-------|-----|------|
| Trust Anchor | `did:webs:reachhaven.com:ENVSnGVU_q39C0Lsim8CtXP_c0TbQW7BBndLVnBeDPXo` | `harbour-trust-anchor.did.json` |
| Signing Service | `did:webs:harbour.reachhaven.com:Er9_mnFstIFyj7JXhHtf7BTHAaUXkaFoJQq96z8WycDQ` | `harbour-signing-service.did.json` |

### User-side (wallet-registered)

| Actor | DID | Wallet (`did:jwk`) | File |
|-------|-----|--------------------|------|
| Legal person | `did:webs:participants.harbour.reachhaven.com:legal-persons:0aa6d7ea-27ef-416f-abf8-9cb634884e66:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe` | `did:jwk:eyJ...vbyJ9` | `legal-person-0aa6d7ea-27ef-416f-abf8-9cb634884e66.did.json` |
| Natural person | `did:webs:users.altme.example:natural-persons:550e8400-e29b-41d4-a716-446655440000:EKYGGh-FtAphGmSZbsuBs_t4qpsjYJ2ZqvMKluq9OxmP` | `did:jwk:eyJ...TLRY` | `natural-person-550e8400-e29b-41d4-a716-446655440000.did.json` |

## Trust Anchor Self-Signed Credential

The Trust Anchor holds a self-signed `LegalPersonCredential` where
`issuer == credentialSubject.id`. This is analogous to a root CA certificate.
It is linked from the Trust Anchor's DID document via a
`harbour:LinkedCredentialService` service endpoint, making it publicly resolvable.

See [`../trust-anchor-credential.json`](../trust-anchor-credential.json).

See [`../README.md`](../README.md) for the complete user journey.
