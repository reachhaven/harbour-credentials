# Gaia-X Compliance Document 25.10 (Loire)

**Status:** Published (2024)
**Publisher:** Gaia-X European Association for Data and Cloud AISBL
**Release:** Loire (CD25.10)
**URL:** https://docs.gaia-x.eu/policy-rules-committee/compliance-document/25.10/
**PDF:** https://docs.gaia-x.eu/policy-rules-committee/compliance-document/25.10/pdf/document.pdf
**License:** CC BY-NC-ND 4.0

## Key Sections

| Section | Title | URL |
|---------|-------|-----|
| §3 | Introduction & Scope | https://docs.gaia-x.eu/policy-rules-committee/compliance-document/25.10/Introduction_and_scope/ |
| §5 | Compliance Criteria for Participants | https://docs.gaia-x.eu/policy-rules-committee/compliance-document/25.10/criteria_participant/ |
| §8 | Gaia-X Trust Anchors | https://docs.gaia-x.eu/policy-rules-committee/compliance-document/25.10/Gaia-X_Trust_Anchors/ |
| §10 | Label Format | https://docs.gaia-x.eu/policy-rules-committee/compliance-document/latest/annex_label_format/ |
| §12 | Process for Becoming Gaia-X Compliant | https://docs.gaia-x.eu/policy-rules-committee/compliance-document/25.10/Process/ |

## Related Ontology Pages

| Type | URL |
|------|-----|
| gx:Participant (abstract) | https://docs.gaia-x.eu/ontology/development/classes/Participant/ |
| gx:LegalPerson | https://docs.gaia-x.eu/ontology/development/classes/LegalPerson/ |
| gx:Issuer (T&C) | https://docs.gaia-x.eu/ontology/development/classes/Issuer/ |

---

## §3 Introduction & Scope

### §3.1 Design Principles — Label Levels

Gaia-X defines four conformity assessment schemes:

| Property | Standard Compliance (SC) | Level 1 (L1) | Level 2 (L2) | Level 3 (L3) |
|----------|:---:|:---:|:---:|:---:|
| Declaration of Service or Product | ✔️ | ✔️ | ✔️ | ✔️ |
| Signed with verified method (e.g. eIDAS) | ✔️ | ✔️ | ✔️ | ✔️ |
| Automated validation by GXDCH | ✔️ | ✔️ | ✔️ | ✔️ |
| Automated verification by GXDCH | ✔️ | ✔️ | ➕ | ➕ |
| Data Exchange Policies | ✔️ | ✔️ | ✔️ | ✔️ |
| Certified Label Logo | | ✔️ | ✔️ | ✔️ |
| Data protection by EU legislation | | | ✔️ | ✔️ |
| Manual verification by CAB | | | ✔️ | ✔️ |
| Provider Headquarter within EU | | | | ✔️ |

### §3.3 Extendibility

Gaia-X Compliance applies to **all** Gaia-X Service Offerings. There shall
be a Gaia-X Credential for **all** entities defined in the Gaia-X Conceptual
model: Participant (incl. Consumer/Provider), Service Offering, Resource.

The Gaia-X Compliance scheme can be extended by an ecosystem as detailed in
the Architecture Document.

### §3.4 Period of Validity

The targeted updating period is 18 months. Participants may remain qualified
under former requirements for max 12 months after a revision.

---

## §5 Compliance Criteria for Participants

A Gaia-X Participant is a legal or natural person that has a Gaia-X
Participant Credential. A Gaia-X Participant can take several roles:
consumer, producer, federator, operator, intermediary.

### §5.1 Criteria

**Criterion PA1.1**: The participant issuing its own Gaia-X Participant
Credential shall provide the information according to the Gaia-X Participant
ontology (https://docs.gaia-x.eu/ontology/development/classes/Participant/)
and shall agree and sign the Gaia-X Terms & Conditions as described in the
Gaia-X Ontology for Issuers
(https://docs.gaia-x.eu/ontology/development/classes/Issuer/).

In case the participant is a legal person, the participant (or its power of
attorney) shall provide information according to the Gaia-X Legal Person
ontology (https://docs.gaia-x.eu/ontology/development/classes/LegalPerson/).

**Required for:** Standard Compliance (SC) — declaration. N/A for L1-L3.

### Gaia-X Terms & Conditions

> The Gaia-X credentials issuer agrees to update its Gaia-X credentials
> about any changes, be it technical, organisational, or legal — especially
> but not limited to contractual in regards to the indicated attributes
> present in the Gaia-X credentials.
>
> The certificate or public key of the keypair used to sign Gaia-X
> Credentials will be marked as untrusted where the Gaia-X European
> Association for Data and Cloud becomes aware of any inaccurate statements
> regarding the claims which results in non-compliance with the Compliance
> Document.

### Three Required Gaia-X VCs for Participant Compliance

Per PA1.1, a compliant participant must present these three VCs:

1. **gx:LegalPerson** — Self-signed entity identity credential
   - Contains: registrationNumber (≥1), legalAddress (=1), headquartersAddress (=1)
   - Ontology: https://docs.gaia-x.eu/ontology/development/classes/LegalPerson/
   - SHACL: sh:closed true (no additional properties allowed on gx:LegalPerson nodes)

2. **gx:VatID** (or other RegistrationNumber) — Notary-signed registration number
   - Signed by an accredited Gaia-X Notary after verification against Trusted Data Sources
   - Trusted Data Sources: EORI (EC API), leiCode (GLEIF API), local (OpenCorporate), vatID (VIES)
   - See §8.3

3. **gx:Issuer** — Self-signed Terms & Conditions acceptance
   - Contains: gx:gaiaxTermsAndConditions (SHA-256 hash of T&C text)
   - Ontology: https://docs.gaia-x.eu/ontology/development/classes/Issuer/

These three VCs are bundled into a Verifiable Presentation and submitted to
the Gaia-X Compliance Service (GXDCH). On success, a compliance credential
(Gaia-X Label) is issued.

---

## §8 Gaia-X Trust Anchors

Trust Anchors are bodies/parties accredited by Gaia-X to issue attestations
about specific claims. They are NOT necessarily Root CAs — they can be
relative to different properties in a claim.

### §8.2 Trust Anchor Types

**§8.2.1 Signee's Role** — For specific dependent attributes, a criterion
can mandate that an attribute must be signed by the same issuer (signee) of
another attribute.

**§8.2.2 Trust Service Provider (TSP)** — All claims must be signed with
cryptographic material traceable to a Trust Anchor (usually a TSP). Accepted
TSP categories:

- EEA: eIDAS Regulation (EU) No 910/2014
- India: CCA
- South Korea: KTNET
- UAE: PASS
- Global fallback: Extended Validation (EV) SSL certificates

### §8.3 Trusted Data Sources and Notaries

When a Trust Anchor cannot issue cryptographic material directly, Gaia-X
accredits Notaries to convert "not machine readable" proofs into "machine
readable" proofs. A Gaia-X Notary must be a Gaia-X participant.

Accredited Trusted Data Sources for registration numbers:
- **EORI**: EC API (https://ec.europa.eu/taxation_customs/dds2/eos/validation/services/validation?wsdl)
- **leiCode**: GLEIF API (https://www.gleif.org/en/lei-data/gleif-api)
- **local**: OpenCorporate API (https://api.opencorporates.com/)
- **vatID**: VIES API (https://ec.europa.eu/taxation_customs/vies/checkVatTestService.wsdl)

---

## §10 Label Format

A Gaia-X Label is a machine readable, structured and signed document (VC)
containing at minimum:

- Label ID (unique identifier)
- Participant ID (unique identifier)
- Participant Business ID (firm business ID)
- Service Offering (for which the Label applies)
- Conformity assessment scheme (SC, L1, L2, or L3)
- Reference to the assessment scheme version (e.g. CD25.10)
- Compliance Service ID (GXDCH instance)
- Compliance Service version (software version)
- Issuance date
- Validity start and end date

---

## §12 Process for Becoming a Gaia-X Compliant User

Prerequisites:
1. Familiar with Gaia-X concepts (VCs, digital signatures, certificates, wallets)
2. Has an EV SSL or eIDAS certificate; public part published via DID:WEB
3. Familiar with Architecture Document workflow

Steps:
- **A**: User wants Gaia-X Compliant VCs
- **B**: User chooses VC type (e.g. LegalParticipant) from Gaia-X Registry
- **C**: User chooses method: Wizard (https://wizard.lab.gaia-x.eu/) or
  direct API (https://compliance.gaia-x.eu/)
- **D**: User creates credential payload with mandatory + optional attributes
- **E**: User signs credentials with their private key
- **F**: User creates a Verifiable Presentation including all required VCs
- **G**: User calls Gaia-X Compliance Service (connected to GXDCH instances)
- **H1**: If verification fails → error message with issue details
- **H2**: If verification succeeds → user receives Gaia-X Verifiable Credential

The Gaia-X VC contains proof of verification, signed by the Clearing House.
After receiving it, the participant can claim Gaia-X Conformant status.

Storage options:
1. JSON file on user's device
2. Digital wallet
3. Pushed to Credential Event Service (basis for Federated Catalogues)

---

## Harbour Mapping

Harbour maps the Gaia-X compliance flow as follows:

| Gaia-X Concept | Harbour Implementation |
|----------------|----------------------|
| Compliance Service (GXDCH) | Haven (compliance service) |
| gx:LegalPerson VC | `examples/gaiax/gx-legal-person.json` |
| gx:VatID VC (notary) | `examples/gaiax/gx-registration-number.json` |
| gx:Issuer VC (T&C) | `examples/gaiax/gx-terms-and-conditions.json` |
| Compliance Credential (Label) | `harbour.gx:LegalPersonCredential` |
| Label Level | `harbour.gx:labelLevel` (SC, L1, L2, L3) |
| Assessment version | `harbour.gx:rulesVersion` (e.g. "CD25.10") |
| Compliance engine version | `harbour.gx:engineVersion` |
| Validated criteria | `harbour.gx:validatedCriteria` (URI list) |
| digestSRI on CompliantCredentialReference | Integrity hash per [SRI] spec |

### Key Design Decision

`harbour.gx:LegalPersonCredential` IS the compliance credential — holding
a valid one means Haven has verified all three required Gaia-X VCs. The
input VCs are plain Gaia-X (type: VerifiableCredential only, no harbour
envelope). SHACL shapes enforce the presence of all three VC references
with `sh:minCount 1` — machine-readable enforcement that the Gaia-X Loire
specification process leaves implicit.
