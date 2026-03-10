# W3C Verifiable Credentials Data Model v2.0

**Status:** W3C Recommendation
**URL:** https://www.w3.org/TR/vc-data-model-2.0/
**JSON-LD Context:** https://www.w3.org/ns/credentials/v2
**Vocabulary:** https://www.w3.org/2018/credentials/

## Key Normative Requirements

### @context (§4.3)

- MUST be an ordered set where the first item is `https://www.w3.org/ns/credentials/v2`.
- Subsequent items MUST be URLs or objects processable as JSON-LD contexts.

### Identifiers — id (§4.4)

- OPTIONAL. If present, MUST be a single URL (may be dereferenceable).
- Applies to VC, VP, and credentialSubject.
- RECOMMENDED: URL that resolves to machine-readable info about the id.

### Types — type (§4.5)

- MUST be present. Maps to `@type` in JSON-LD.
- MUST include `VerifiableCredential` for credentials.
- Values MUST be terms or absolute URL strings resolvable via @context.

### Issuer (§4.7)

- A verifiable credential MUST have an `issuer` property.
- Value MUST be either a URL or an object containing an `id` property
  whose value is a URL.
- The issuer is expected to be the entity that asserts the claims.

### Credential Subject (§4.8)

- A verifiable credential MUST contain a `credentialSubject` property.
- Value MUST be one or more objects, each describing claims about a subject.
- Each object MAY have an `id` property (URL identifying the subject).

### Validity Period (§4.9)

- `validFrom` — OPTIONAL. If present, value MUST be an xsd:dateTimeStamp
  (ISO 8601 with mandatory timezone offset).
  Represents the earliest date/time the credential is valid.
- `validUntil` — OPTIONAL. If present, value MUST be an xsd:dateTimeStamp.
  Represents the latest date/time the credential is valid.
- Both properties are OPTIONAL per the base spec; profiles MAY make them
  REQUIRED (e.g., Harbour profile requires validFrom).

### Status (§4.10)

- `credentialStatus` — OPTIONAL.
- If present, value MUST be one or more objects, each containing:
  - `id` — MUST be a URL identifying the status information.
  - `type` — MUST be present, identifying the status mechanism.
- The status mechanism is extensible (e.g., BitstringStatusList, CRSet).
- Verifiers SHOULD check credential status during verification.

### Data Schemas (§4.11)

- `credentialSchema` — OPTIONAL.
- If present, each entry MUST have `id` (URL) and `type`.

### Evidence (§5.6)

- `evidence` — OPTIONAL (0..*).
- Provides information about the process/evidence the issuer used
  when evaluating the claims.
- Each evidence object MUST specify its `type`.
- Evidence objects MAY contain arbitrary additional properties.

### Securing Mechanisms (§4.12)

- A conforming document MUST be secured by at least one securing mechanism.
- Two approaches specified:
  - **Embedded proof** — Verifiable Credential Data Integrity 1.0 (`proof` property)
  - **Enveloping proof** — VC-JOSE-COSE (JWT/SD-JWT/COSE wrapping)

### Media Types (§6.2)

| Media Type | Purpose |
|------------|---------|
| `application/vc` | Verifiable Credential (JSON-LD) |
| `application/vp` | Verifiable Presentation (JSON-LD) |

## Property Summary

| Property | Requirement | Type | Section |
|----------|-------------|------|---------|
| `@context` | MUST | ordered set of URLs/objects | §4.3 |
| `id` | OPTIONAL | URL | §4.4 |
| `type` | MUST | set of strings | §4.5 |
| `name` | OPTIONAL | string or language map | §4.6 |
| `description` | OPTIONAL | string or language map | §4.6 |
| `issuer` | MUST | URL or object with id | §4.7 |
| `credentialSubject` | MUST | object or array of objects | §4.8 |
| `validFrom` | OPTIONAL | xsd:dateTimeStamp | §4.9 |
| `validUntil` | OPTIONAL | xsd:dateTimeStamp | §4.9 |
| `credentialStatus` | OPTIONAL | object or array of objects | §4.10 |
| `credentialSchema` | OPTIONAL | object or array of objects | §4.11 |
| `evidence` | OPTIONAL | object or array of objects | §5.6 |
| `refreshService` | OPTIONAL | object or array of objects | §5.4 |
| `termsOfUse` | OPTIONAL | object or array of objects | §5.5 |

## Harbour Profile Deviations

Harbour makes the following properties stricter than the base spec:

| Property | W3C Base | Harbour Profile |
|----------|----------|-----------------|
| `issuer` | MUST | MUST (same) |
| `validFrom` | OPTIONAL | MUST (stricter) |
| `credentialStatus` | OPTIONAL | MUST (stricter, range: CRSetEntry) |
| `evidence` | OPTIONAL | OPTIONAL (same, but MUST on LegalPerson/NaturalPerson credentials) |
