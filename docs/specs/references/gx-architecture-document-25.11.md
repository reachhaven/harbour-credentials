# Gaia-X Architecture Document 25.11

**Status:** Published (November 2025)
**Publisher:** Gaia-X European Association for Data and Cloud AISBL
**URL:** https://docs.gaia-x.eu/technical-committee/architecture-document/25.11/
**PDF:** https://docs.gaia-x.eu/technical-committee/architecture-document/25.11/pdf/document.pdf
**License:** CC BY-NC-ND 4.0

## Local Artifacts

The Gaia-X ontology, SHACL shapes, and JSON-LD context are maintained
locally in the ontology-management-base (OMB) submodule:

| File | Path (relative to OMB root) |
|------|-----------------------------|
| OWL ontology | `artifacts/gx/gx.owl.ttl` |
| SHACL shapes | `artifacts/gx/gx.shacl.ttl` |
| JSON-LD context | `artifacts/gx/gx.context.jsonld` |
| Version | `artifacts/gx/VERSION` → `25.11+fix.1` |
| Properties summary | `artifacts/gx/PROPERTIES.md` |

**Source submodule:** `submodules/service-characteristics` (upstream GitLab)
**Namespace:** `https://w3id.org/gaia-x/development#` (prefix `gx:`)

## Overview

The Gaia-X Architecture Document defines the technical framework for
the Gaia-X ecosystem, including identity, trust, and compliance
requirements for participants and service offerings. It specifies
SHACL shapes and ontology terms under the `gx:` namespace.

## Key Concepts for Harbour

### Participant Types

| Type | Namespace | Description |
|------|-----------|-------------|
| `gx:Participant` | `https://w3id.org/gaia-x/development#` | Base participant type |
| `gx:LegalPerson` | `https://w3id.org/gaia-x/development#` | Organization participant (extends gx:Participant) |

### gx:LegalPersonShape (from `gx.shacl.ttl`)

The shape is **closed** (`sh:closed true`), meaning only declared properties
are permitted on `gx:LegalPerson` nodes:

| Property | Type | Required | Description |
|----------|------|----------|-------------|
| `gx:registrationNumber` | `gx:RegistrationNumber` | MUST (≥1) | Country's registration number (EUID, EORI, vatID, leiCode) |
| `gx:legalAddress` | `gx:Address` | MUST (=1) | Full legal/registered address |
| `gx:headquartersAddress` | `gx:Address` | MUST (=1) | Full physical HQ address |
| `gx:parentOrganizationOf` | `gx:LegalPerson` | OPTIONAL | Parent org links |
| `gx:subOrganisationOf` | `gx:LegalPerson` | OPTIONAL | Subsidiary links (mandated entities) |
| `schema:name` | `xsd:string` | OPTIONAL (≤1) | Human-readable name |
| `schema:description` | `xsd:string` | OPTIONAL (≤1) | Description |

### Compliance Model — Why Not Extend gx:LegalPerson Directly?

Because `gx:LegalPersonShape` has `sh:closed true`:

- Adding ANY property not in the shape to a `gx:LegalPerson` node
  will **fail** SHACL validation.
- Harbour cannot extend `gx:LegalPerson` with additional properties.
- Therefore Harbour uses a **separate compliance attestation type**:
  `harbour.gx:LegalPerson` carries only compliance enforcement slots
  (VC references + metadata). Entity data lives in the referenced
  plain `gx:LegalPerson` input VC.

### Compliance Pattern

```
harbour.gx:LegalPerson                 # compliance attestation node
  ├── harbour.gx:compliantLegalPersonVC # → gx:LegalPerson VC ref + digestSRI
  ├── harbour.gx:compliantRegistrationVC # → gx:VatID VC ref + digestSRI
  ├── harbour.gx:compliantTermsVC       # → gx:Issuer VC ref + digestSRI
  ├── harbour.gx:labelLevel "SC"
  ├── harbour.gx:engineVersion "2.11.0"
  ├── harbour.gx:rulesVersion "CD25.10"
  └── harbour.gx:validatedCriteria [...]
```

This pattern keeps gx closed shapes intact — entity data stays on the
gx nodes, compliance metadata stays on the harbour node.

### Trust Framework Compliance

- Participants MUST present Gaia-X Compliance Credentials.
- Compliance credentials are issued by Gaia-X-accredited notaries.
- The Gaia-X Compliance Service validates participant data against
  SHACL shapes and issues compliance credentials.

## Related Documents

| Document | URL |
|----------|-----|
| Gaia-X Ontology (IRI) | https://w3id.org/gaia-x/development |
| Gaia-X Shapes (catalog IRI) | https://w3id.org/gaia-x/development#shapes |
| Gaia-X Trust Framework | https://docs.gaia-x.eu/ |
| Gaia-X Compliance Service | https://compliance.gaia-x.eu/ |
| Gaia-X Registry | https://registry.gaia-x.eu/ |
| Upstream submodule (GitLab) | https://gitlab.com/gaia-x/technical-committee/service-characteristics-working-group/service-characteristics |

## Harbour Usage

- `harbour-gx-credential.yaml` defines `LegalPersonCredential` and
  `NaturalPersonCredential` with compliance enforcement slots.
- `LegalPersonCredential` IS the compliance credential — holding a valid
  one means Haven verified the three underlying Gaia-X VCs (LegalPerson,
  VatID, Issuer/T&C). See [GX-CD 25.10](gx-compliance-document-25.10.md).
- `harbour.gx:LegalPerson` is a pure compliance attestation type with
  SHACL-enforced `CompliantCredentialReference` slots.
- `harbour.gx:NaturalPerson` extends `gx:Participant` directly.
- Domain SHACL is generated with `exclude_imports=True` to keep
  harbour shapes separate from gx shapes.
- Version tracking via `artifacts/gx/VERSION` and `verify-version.sh`.
