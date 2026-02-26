"""Tests for claim mappings: W3C VCDM JSON-LD <-> SD-JWT-VC flat claims."""

import json
from pathlib import Path

from credentials.claim_mapping import (
    MAPPINGS,
    create_mapping,
    get_mapping_for_vc,
    register_mapping,
    sd_jwt_claims_to_vc,
    vc_to_sd_jwt_claims,
)

_REPO_ROOT = Path(__file__).resolve().parent
while _REPO_ROOT.name != "harbour-credentials" and _REPO_ROOT != _REPO_ROOT.parent:
    _REPO_ROOT = _REPO_ROOT.parent

EXAMPLES_DIR = _REPO_ROOT / "examples"


def _load_fixture(name: str) -> dict:
    """Load a credential example from the examples directory."""
    with open(EXAMPLES_DIR / name) as f:
        return json.load(f)


class TestHarbourLegalPersonMapping:
    def test_vc_to_claims(self):
        vc = _load_fixture("legal-person-credential.json")
        mapping = MAPPINGS["harbour:LegalPersonCredential"]
        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)

        assert (
            claims["iss"]
            == "did:webs:harbour.reachhaven.com:Er9_mnFstIFyj7JXhHtf7BTHAaUXkaFoJQq96z8WycDQ"
        )
        assert (
            claims["sub"]
            == "did:webs:participants.harbour.reachhaven.com:legal-persons:0aa6d7ea-27ef-416f-abf8-9cb634884e66:ENro7uf0ePmiK3jdTo2YCdXLqW7z7xoP6qhhBou6gBLe"
        )
        assert claims["name"] == "Example Corporation GmbH"
        assert claims["legalName"] == "Example Corporation GmbH"
        assert "registrationNumber" in claims
        assert "registrationNumber" in disclosable

    def test_has_credential_status(self):
        vc = _load_fixture("legal-person-credential.json")
        assert "credentialStatus" in vc
        status = vc["credentialStatus"][0]
        assert status["type"] == "harbour:CRSetEntry"
        assert status["statusPurpose"] == "revocation"

    def test_subject_is_harbour_legal_person(self):
        """Verify the subject uses harbour:LegalPerson (outer node only)."""
        vc = _load_fixture("legal-person-credential.json")
        subject_type = vc["credentialSubject"]["type"]
        assert subject_type == "harbour:LegalPerson"

    def test_gx_inner_node_exists(self):
        """Verify gx:LegalPerson data lives in the gxParticipant inner node."""
        vc = _load_fixture("legal-person-credential.json")
        subject = vc["credentialSubject"]
        gx = subject["gxParticipant"]
        assert gx["type"] == "gx:LegalPerson"
        assert "schema:name" in gx
        assert "gx:registrationNumber" in gx
        # gx properties must NOT be on the outer node
        # schema:name is on both nodes (outer via harbour, inner via gx)
        assert "gx:registrationNumber" not in subject

    def test_roundtrip(self):
        vc = _load_fixture("legal-person-credential.json")
        mapping = MAPPINGS["harbour:LegalPersonCredential"]
        claims, _ = vc_to_sd_jwt_claims(vc, mapping)
        reconstructed = sd_jwt_claims_to_vc(
            claims, mapping, "harbour:LegalPersonCredential"
        )
        assert (
            reconstructed["credentialSubject"]["gxParticipant"]["schema:name"]
            == vc["credentialSubject"]["gxParticipant"]["schema:name"]
        )


class TestHarbourNaturalPersonMapping:
    def test_vc_to_claims(self):
        vc = _load_fixture("natural-person-credential.json")
        mapping = MAPPINGS["harbour:NaturalPersonCredential"]
        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)

        assert claims["givenName"] == "Alice"
        assert claims["familyName"] == "Smith"
        assert claims["email"] == "alice.smith@example.com"
        assert "givenName" in disclosable
        assert "email" in disclosable

    def test_has_credential_status(self):
        vc = _load_fixture("natural-person-credential.json")
        assert "credentialStatus" in vc
        status = vc["credentialStatus"][0]
        assert status["type"] == "harbour:CRSetEntry"

    def test_has_evidence(self):
        vc = _load_fixture("natural-person-credential.json")
        assert "evidence" in vc
        evidence = vc["evidence"][0]
        assert evidence["type"] == "harbour:CredentialEvidence"

    def test_subject_is_harbour_natural_person(self):
        """Verify the subject uses harbour:NaturalPerson (outer node only)."""
        vc = _load_fixture("natural-person-credential.json")
        subject_type = vc["credentialSubject"]["type"]
        assert subject_type == "harbour:NaturalPerson"

    def test_gx_inner_node_exists(self):
        """Verify gx:Participant data lives in the gxParticipant inner node."""
        vc = _load_fixture("natural-person-credential.json")
        subject = vc["credentialSubject"]
        gx = subject["gxParticipant"]
        assert gx["type"] == "gx:Participant"

    def test_roundtrip(self):
        vc = _load_fixture("natural-person-credential.json")
        mapping = MAPPINGS["harbour:NaturalPersonCredential"]
        claims, _ = vc_to_sd_jwt_claims(vc, mapping)
        reconstructed = sd_jwt_claims_to_vc(
            claims, mapping, "harbour:NaturalPersonCredential"
        )
        assert (
            reconstructed["credentialSubject"]["schema:givenName"]
            == vc["credentialSubject"]["schema:givenName"]
        )


class TestMappingDiscovery:
    def test_get_mapping_for_harbour_credential(self):
        vc = _load_fixture("legal-person-credential.json")
        mapping = get_mapping_for_vc(vc)
        assert mapping is not None
        assert "LegalPersonCredential" in mapping["vct"]

    def test_get_mapping_for_unknown(self):
        vc = {"type": ["VerifiableCredential", "UnknownType"]}
        mapping = get_mapping_for_vc(vc)
        assert mapping is None


class TestCustomMapping:
    def test_register_and_use_custom_mapping(self):
        # Create a custom mapping
        custom = create_mapping(
            vct="https://example.com/credentials/CustomCredential",
            claims={
                "credentialSubject.customField": "customField",
            },
            selectively_disclosed=["customField"],
        )

        # Register it
        register_mapping("harbour:CustomCredential", custom)

        # Use it
        vc = {
            "type": ["VerifiableCredential", "harbour:CustomCredential"],
            "issuer": "did:web:issuer.example.com",
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:web:subject.example.com",
                "customField": "custom-value",
            },
            "credentialStatus": [
                {
                    "id": "did:web:issuer.example.com:revocation#abc123",
                    "type": "harbour:CRSetEntry",
                    "statusPurpose": "revocation",
                }
            ],
        }

        mapping = get_mapping_for_vc(vc)
        assert mapping is not None

        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)
        assert claims["customField"] == "custom-value"
        assert "customField" in disclosable

        # Clean up
        del MAPPINGS["harbour:CustomCredential"]
