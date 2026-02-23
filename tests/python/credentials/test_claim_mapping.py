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

        assert claims["iss"] == "did:web:trust-anchor.example.com"
        assert claims["sub"] == "did:web:participant.example.com"
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
        """Verify the subject uses harbour:LegalPerson (wraps gx:LegalPerson)."""
        vc = _load_fixture("legal-person-credential.json")
        types = vc["credentialSubject"]["type"]
        assert "harbour:LegalPerson" in types
        assert "gx:LegalPerson" in types

    def test_roundtrip(self):
        vc = _load_fixture("legal-person-credential.json")
        mapping = MAPPINGS["harbour:LegalPersonCredential"]
        claims, _ = vc_to_sd_jwt_claims(vc, mapping)
        reconstructed = sd_jwt_claims_to_vc(
            claims, mapping, "harbour:LegalPersonCredential"
        )
        assert (
            reconstructed["credentialSubject"]["gx:legalName"]
            == vc["credentialSubject"]["gx:legalName"]
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
        assert evidence["type"] == "harbour:EmailVerification"

    def test_subject_is_harbour_natural_person(self):
        """Verify the subject uses harbour:NaturalPerson (extends gx:Participant)."""
        vc = _load_fixture("natural-person-credential.json")
        types = vc["credentialSubject"]["type"]
        assert "harbour:NaturalPerson" in types
        assert "gx:Participant" in types

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


class TestHarbourServiceOfferingMapping:
    def test_vc_to_claims(self):
        vc = _load_fixture("service-offering-credential.json")
        mapping = MAPPINGS["harbour:ServiceOfferingCredential"]
        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)

        assert claims["sub"] == "did:web:provider.example.com:services:data-api"
        assert claims["name"] == "Example Data API"
        assert "description" in disclosable

    def test_has_credential_status(self):
        vc = _load_fixture("service-offering-credential.json")
        assert "credentialStatus" in vc
        status = vc["credentialStatus"][0]
        assert status["type"] == "harbour:CRSetEntry"

    def test_subject_is_harbour_service_offering(self):
        """Verify the subject uses harbour:ServiceOffering (wraps gx:ServiceOffering)."""
        vc = _load_fixture("service-offering-credential.json")
        types = vc["credentialSubject"]["type"]
        assert "harbour:ServiceOffering" in types
        assert "gx:ServiceOffering" in types
        status = vc["credentialStatus"][0]
        assert status["type"] == "harbour:CRSetEntry"


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
