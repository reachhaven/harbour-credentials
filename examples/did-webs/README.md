# did:webs Example Documents

This folder contains static example DID documents for the `did:webs` identifiers
used in `examples/*.json`.

## Scope and Boundary

- These files are modeling examples for Harbour v1.
- This repository does **not** resolve `did:webs` identifiers and does **not**
  validate `keri.cesr` streams.
- Integrators must host corresponding `did.json` and `keri.cesr` resources in
  production according to the `did:webs` method specification.

## Naming Policy in These Examples

- Natural person identifiers use a UUID path segment and do not carry real
  names in the DID path.
- Legal person identifiers may use an organization suffix (for example
  `bmw_ag`) in the DID path.

## Example IDs

- Natural person:
  `did:webs:users.altme.example:natural-persons:550e8400-e29b-41d4-a716-446655440000:EKYGGh-FtAphGmSZbsuBs_t4qpsjYJ2ZqvMKluq9OxmP`
- Legal person:
  `did:webs:participants.example.com:legal-persons:bmw_ag:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe`
- EmailPass issuer (legal person):
  `did:webs:issuers.altme.example:legal-persons:altme_sas:EMtR9m3wZ5xV2k8sP4jQ7nH1cD6bL0fYgAaUu2hCqK9M`

## EmailPass Modeling

EmailPass is modeled as a verifiable credential used inside `CredentialEvidence`.
It is **not** a DID verification relationship. The binding to `did:webs` comes from
the EmailPass VC issuer DID and its DID document in this folder.
