# Credential Data Model

This page documents the LinkML schema inheritance hierarchy, composition
patterns, and trust chain architecture used by Harbour Credentials.

## Schema File Structure

```text
linkml/
├── w3c-vc.yaml                   # W3C VC Data Model v2.0 envelope
├── harbour-core-credential.yaml  # Abstract base, evidence, revocation, DID
└── harbour-gx-credential.yaml    # Gaia-X domain layer (participants)
```

Each file builds on the previous one through LinkML `imports`.

## Import Chain

```mermaid
graph LR
    W["w3c-vc.yaml<br/><i>VC envelope</i>"]
    H["harbour-core-credential.yaml<br/><i>Abstract base + infra</i>"]
    G["harbour-gx-credential.yaml<br/><i>Gaia-X domain</i>"]

    W --> H
    H --> G

    style W fill:#e3f2fd,stroke:#1565c0
    style H fill:#f3e5f5,stroke:#6a1b9a
    style G fill:#e8f5e9,stroke:#2e7d32
```

Downstream consumers (e.g. SimpulseID) import `harbour-core-credential`
via an import map and define their own credential types on top.

---

## Credential Type Hierarchy

All credential types inherit from `HarbourCredential`, which strengthens
the optional W3C VC v2.0 envelope fields into a harbour-specific profile.

```mermaid
classDiagram
    class W3C_VC_Envelope {
        <<w3c-vc.yaml>>
        +uri issuer
        +datetime validFrom
        +datetime validUntil
        +Evidence[] evidence
        +CredentialStatus[] credentialStatus
    }

    class HarbourCredential {
        <<abstract>>
        issuer : uri ⟨required⟩
        validFrom : datetime ⟨required⟩
        validUntil : datetime
        evidence : Evidence[] ⟨required⟩
        credentialStatus : CRSetEntry[] ⟨required⟩
    }

    class LegalPersonCredential {
        class_uri = harbour:LegalPersonCredential
        vct = "…/LegalPersonCredential"
        validFrom : required
        evidence : required
    }

    class NaturalPersonCredential {
        class_uri = harbour:NaturalPersonCredential
        vct = "…/NaturalPersonCredential"
        validFrom : required
        evidence : required
    }

    W3C_VC_Envelope <|-- HarbourCredential : imports + strengthens
    HarbourCredential <|-- LegalPersonCredential
    HarbourCredential <|-- NaturalPersonCredential
```

### What `HarbourCredential` Strengthens

The W3C VC Data Model v2.0 defines most envelope fields as optional.
`HarbourCredential` tightens these for the harbour profile:

| Field | W3C VC v2.0 | HarbourCredential |
|-------|-------------|-------------------|
| `issuer` | optional | **required** |
| `validFrom` | optional | **required** |
| `validUntil` | optional | optional |
| `evidence` | optional | **required** |
| `credentialStatus` | optional | **required** (range: `CRSetEntry`) |

!!! note "Downstream overrides"
    Consumers like SimpulseID may loosen these constraints via `slot_usage`.
    For example, SimpulseID makes `evidence` and `credentialStatus` optional
    for its credential types.

---

## Evidence Hierarchy

Evidence documents how a credential's claims were verified. Harbour defines
an abstract base with two concrete types:

```mermaid
classDiagram
    class Evidence {
        <<abstract>>
        type : string ⟨required⟩
        verifier : uri ⟨required⟩
        verificationMethod : uri ⟨required⟩
    }

    class CredentialEvidence {
        evidenceDocument : uri
        subjectPresence : string
        documentPresence : string
    }

    class DelegatedSignatureEvidence {
        challenge : string ⟨required⟩
        domain : string ⟨required⟩
    }

    Evidence <|-- CredentialEvidence
    Evidence <|-- DelegatedSignatureEvidence
```

**`CredentialEvidence`** — attests that a human verifier checked documents
(identity papers, registration certificates) before issuance.

**`DelegatedSignatureEvidence`** — attests that the subject authorized a
signing service to act on their behalf via an OID4VP challenge-response
flow. See [Delegated Signing](../guide/delegated-signing.md).

---

## Credential Subject Types

Subject types define what a credential asserts about a person or
organisation. These are **not** inherited from `HarbourCredential` — they
are standalone classes used as the `credentialSubject` value.

```mermaid
classDiagram
    class LegalPerson {
        class_uri = harbour:LegalPerson
        name : string
        gxParticipant : Any
    }

    class NaturalPerson {
        class_uri = harbour:NaturalPerson
        name : string
        gxParticipant : Any
        givenName : string
        familyName : string
        email : string
        memberOf : uri
    }
```

### Credential ↔ Subject Pairing

| Credential Type | Subject Type | Use Case |
|----------------|-------------|----------|
| `LegalPersonCredential` | `LegalPerson` | Organisation identity |
| `NaturalPersonCredential` | `NaturalPerson` | Individual identity |

---

## Gaia-X Composition Pattern

Gaia-X Trust Framework defines **closed SHACL shapes** (`sh:closed true`)
on `gx:LegalPerson` and `gx:Participant`. Adding any non-gx property to
a `gx:` node violates the closed shape constraint.

Harbour solves this with **composition** — the outer harbour node owns
harbour-specific properties, and a nested blank node carries only
gx-valid properties:

```mermaid
graph TD
    subgraph "harbour:LegalPerson (outer node)"
        A["harbour:name = 'ACME Corp'"]
        B["harbour:gxParticipant"]
    end

    subgraph "_:b0 (gx blank node)"
        C["@type = gx:LegalPerson"]
        D["gx:registrationNumber = …"]
        E["gx:legalAddress = …"]
        F["gx:headquartersAddress = …"]
    end

    B --> C

    style A fill:#f3e5f5,stroke:#6a1b9a
    style B fill:#f3e5f5,stroke:#6a1b9a
    style C fill:#e8f5e9,stroke:#2e7d32
    style D fill:#e8f5e9,stroke:#2e7d32
    style E fill:#e8f5e9,stroke:#2e7d32
    style F fill:#e8f5e9,stroke:#2e7d32
```

### Why Not Extend gx:LegalPerson Directly?

Adding harbour properties to a `gx:` node violates `sh:closed`:

```turtle
# ❌ Wrong — SHACL violation
harbour:MyOrg a gx:LegalPerson ;
    gx:registrationNumber … ;
    harbour:extraField "value" .
```

Composition keeps gx shapes intact:

```turtle
# ✅ Correct — separate nodes
harbour:MyOrg a harbour:LegalPerson ;
    harbour:name "ACME" ;
    harbour:gxParticipant [
        a gx:LegalPerson ;
        gx:registrationNumber …
    ] .
```

The `gxParticipant` slot has `range: Any` because the nested content is
validated by Gaia-X's own SHACL shapes (`gx.shacl.ttl`), not harbour's.
Harbour generates its SHACL with `exclude_imports=True` to keep shape
sets separate.

---

## Revocation Infrastructure

Harbour uses a **Credential Revocation Set (CRSet)** mechanism for
status management:

```mermaid
classDiagram
    class CRSetEntry {
        class_uri = harbour:CRSetEntry
        type : string ⟨required⟩
        statusPurpose : string ⟨required⟩
        statusListIndex : integer ⟨required⟩
        statusListCredential : uri ⟨required⟩
    }
```

Each credential carries a `credentialStatus` array of `CRSetEntry`
objects pointing to an on-chain or hosted status list.

---

## DID Document Model

Harbour defines a DID Document structure for key resolution and service
discovery:

```mermaid
classDiagram
    class DIDDocument {
        verificationMethod : VerificationMethod[]
        service : Service[]
    }

    class VerificationMethod {
        type : string ⟨required⟩
        controller : uri ⟨required⟩
        publicKeyJwk : string
    }

    class Service {
        <<union>>
    }

    class TrustAnchorService {
        type : string ⟨required⟩
        serviceEndpoint : uri ⟨required⟩
    }

    class LinkedCredentialService {
        type : string ⟨required⟩
        serviceEndpoint : uri ⟨required⟩
    }

    class CRSetRevocationRegistryService {
        type : string ⟨required⟩
        serviceEndpoint : uri ⟨required⟩
    }

    DIDDocument --> VerificationMethod
    DIDDocument --> Service
    Service <|-- TrustAnchorService
    Service <|-- LinkedCredentialService
    Service <|-- CRSetRevocationRegistryService
```

---

## Artifact Generation Pipeline

LinkML schemas produce three types of artifacts:

```mermaid
flowchart LR
    S["LinkML Schema<br/>(.yaml)"] --> OWL["OWL Ontology<br/>(.owl.ttl)"]
    S --> SHACL["SHACL Shapes<br/>(.shacl.ttl)"]
    S --> CTX["JSON-LD Context<br/>(.context.jsonld)"]

    OWL --> V["SHACL Validation"]
    SHACL --> V
    CTX --> V
    V --> E["Example Credentials<br/>(.json)"]

    style S fill:#fff3e0,stroke:#e65100
    style OWL fill:#e3f2fd,stroke:#1565c0
    style SHACL fill:#fce4ec,stroke:#c62828
    style CTX fill:#e8f5e9,stroke:#2e7d32
    style V fill:#f3e5f5,stroke:#6a1b9a
    style E fill:#fffde7,stroke:#f57f17
```

| Artifact | Purpose | Generated By |
|----------|---------|-------------|
| **OWL** (`.owl.ttl`) | Class hierarchy and property definitions | `gen-owl` |
| **SHACL** (`.shacl.ttl`) | Validation constraints (required, ranges, cardinality) | `HarbourShaclGenerator` |
| **JSON-LD Context** (`.context.jsonld`) | Term-to-IRI mappings for JSON-LD serialisation | `DomainContextGenerator` |

Run `make generate` to regenerate all artifacts from schemas.

---

## Complete Class Map

For quick reference, every class defined across all three schema files:

| Class | Schema File | Abstract | Parent | Domain |
|-------|-------------|----------|--------|--------|
| `HarbourCredential` | core | ✅ | *(W3C VC envelope)* | Core |
| `Evidence` | core | ✅ | — | Core |
| `CredentialEvidence` | core | — | `Evidence` | Core |
| `DelegatedSignatureEvidence` | core | — | `Evidence` | Core |
| `CRSetEntry` | core | — | — | Core |
| `DIDDocument` | core | — | — | Core |
| `VerificationMethod` | core | — | — | Core |
| `TrustAnchorService` | core | — | *(Service union)* | Core |
| `LinkedCredentialService` | core | — | *(Service union)* | Core |
| `CRSetRevocationRegistryService` | core | — | *(Service union)* | Core |
| `LegalPersonCredential` | gx | — | `HarbourCredential` | Gaia-X |
| `NaturalPersonCredential` | gx | — | `HarbourCredential` | Gaia-X |
| `LegalPerson` | gx | — | — | Gaia-X |
| `NaturalPerson` | gx | — | — | Gaia-X |
