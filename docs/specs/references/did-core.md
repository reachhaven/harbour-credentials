# W3C Decentralized Identifiers (DIDs) v1.0

**Status:** W3C Recommendation
**URL:** https://www.w3.org/TR/did-core/

## Key Normative Requirements

### DID Syntax (§3.1)

- A DID is a simple URI: `did:<method>:<method-specific-id>`
- DID URLs extend DIDs with path, query, and fragment components.
- DIDs MUST conform to the ABNF grammar defined in the specification.

### DID Subject (§5.1.1)

- Every DID document MUST have an `id` property.
- The value MUST be the DID that the document describes.

### DID Controller (§5.1.2)

- `controller` — OPTIONAL. A URI or set of URIs identifying the entity
  authorized to make changes to the DID document.
- When present, value MUST be a string or an ordered set of strings,
  each of which is a DID.

### Verification Methods (§5.2)

- `verificationMethod` — OPTIONAL. Array of verification method objects.
- Each verification method MUST have: `id`, `type`, `controller`.
- Key material MUST be expressed using `publicKeyJwk` or
  `publicKeyMultibase` (§5.2.1).
- Multiple verification methods MAY be present.

### Verification Relationships (§5.3)

| Relationship | Purpose | Section |
|-------------|---------|---------|
| `authentication` | Prove DID controller identity | §5.3.1 |
| `assertionMethod` | Issue verifiable credentials | §5.3.2 |
| `keyAgreement` | Establish secure communication channels | §5.3.3 |
| `capabilityInvocation` | Invoke cryptographic capabilities | §5.3.4 |
| `capabilityDelegation` | Delegate capabilities to others | §5.3.5 |

### Services (§5.4)

- `service` — OPTIONAL. Array of service objects.
- Each service entry MUST have: `id`, `type`, `serviceEndpoint`.
- `serviceEndpoint` can be a URI, a map, or a set of these.
- Service values MUST be unique.

### Representations (§6)

- JSON (§6.2) and JSON-LD (§6.3) are specified representations.
- JSON-LD context: `https://www.w3.org/ns/did/v1`
- Media types: `application/did+json`, `application/did+ld+json`

## Property Summary (Core)

| Property | Requirement | Type | Section |
|----------|-------------|------|---------|
| `id` | MUST | DID URI | §5.1.1 |
| `controller` | OPTIONAL | DID or set of DIDs | §5.1.2 |
| `alsoKnownAs` | OPTIONAL | set of URIs | §5.1.3 |
| `verificationMethod` | OPTIONAL | array of objects | §5.2 |
| `authentication` | OPTIONAL | array of methods/refs | §5.3.1 |
| `assertionMethod` | OPTIONAL | array of methods/refs | §5.3.2 |
| `keyAgreement` | OPTIONAL | array of methods/refs | §5.3.3 |
| `capabilityInvocation` | OPTIONAL | array of methods/refs | §5.3.4 |
| `capabilityDelegation` | OPTIONAL | array of methods/refs | §5.3.5 |
| `service` | OPTIONAL | array of service objects | §5.4 |

## Harbour Usage

Harbour models a subset of DID Core:

- `DIDDocument` class with `controller`, `service`, `verificationMethod`
- `VerificationMethod` class with `controller`, `blockchainAccountId` (extension)
- Service types: `TrustAnchorService`, `CRSetRevocationRegistryService`,
  `LinkedCredentialService`
- DID method: `did:ethr` on Base L2 (see ADR-005)
