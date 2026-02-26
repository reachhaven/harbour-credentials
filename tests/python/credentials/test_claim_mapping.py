"""Tests for claim mappings: W3C VCDM JSON-LD <-> SD-JWT-VC flat claims."""

import json
from pathlib import Path

from credentials.claim_mapping import (
    GAIAX_MAPPINGS,
    GAIAX_NS,
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
GAIAX_EXAMPLES_DIR = EXAMPLES_DIR / "gaiax"


def _load_fixture(name: str, gaiax: bool = False) -> dict:
    """Load a credential example from the examples directory."""
    base = GAIAX_EXAMPLES_DIR if gaiax else EXAMPLES_DIR
    with open(base / name) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Base harbour skeleton tests
# ---------------------------------------------------------------------------


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
        # Base mapping has no gx claims
        assert "legalName" not in claims
        assert "registrationNumber" not in claims
        assert disclosable == []

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

    def test_no_gx_participant(self):
        """Base skeleton must not contain gxParticipant."""
        vc = _load_fixture("legal-person-credential.json")
        assert "gxParticipant" not in vc["credentialSubject"]

    def test_no_gaiax_context(self):
        """Base skeleton must not reference the Gaia-X namespace."""
        vc = _load_fixture("legal-person-credential.json")
        assert GAIAX_NS not in vc["@context"]

    def test_roundtrip(self):
        vc = _load_fixture("legal-person-credential.json")
        mapping = MAPPINGS["harbour:LegalPersonCredential"]
        claims, _ = vc_to_sd_jwt_claims(vc, mapping)
        reconstructed = sd_jwt_claims_to_vc(
            claims, mapping, "harbour:LegalPersonCredential"
        )
        assert (
            reconstructed["credentialSubject"]["name"]
            == vc["credentialSubject"]["name"]
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

    def test_no_gx_participant(self):
        """Base skeleton must not contain gxParticipant."""
        vc = _load_fixture("natural-person-credential.json")
        assert "gxParticipant" not in vc["credentialSubject"]

    def test_no_gaiax_context(self):
        """Base skeleton must not reference the Gaia-X namespace."""
        vc = _load_fixture("natural-person-credential.json")
        assert GAIAX_NS not in vc["@context"]

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


# ---------------------------------------------------------------------------
# Gaia-X domain extension tests
# ---------------------------------------------------------------------------


class TestGaiaxLegalPersonMapping:
    def test_vc_to_claims(self):
        vc = _load_fixture("legal-person-credential.json", gaiax=True)
        mapping = GAIAX_MAPPINGS["harbour:LegalPersonCredential"]
        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)

        # Gaia-X extension uses gxParticipant.schema:name, not outer name
        assert "name" not in claims
        assert claims["legalName"] == "Example Corporation GmbH"
        assert "registrationNumber" in claims
        assert "registrationNumber" in disclosable

    def test_gx_inner_node_exists(self):
        """Verify gx:LegalPerson data lives in the gxParticipant inner node."""
        vc = _load_fixture("legal-person-credential.json", gaiax=True)
        subject = vc["credentialSubject"]
        gx = subject["gxParticipant"]
        assert gx["type"] == "gx:LegalPerson"
        assert "schema:name" in gx
        assert "gx:registrationNumber" in gx
        # gx properties must NOT be on the outer node
        assert "gx:registrationNumber" not in subject

    def test_has_gaiax_context(self):
        """Gaia-X extension must include the Gaia-X namespace in @context."""
        vc = _load_fixture("legal-person-credential.json", gaiax=True)
        assert GAIAX_NS in vc["@context"]

    def test_no_outer_name(self):
        """Gaia-X extension should NOT have name on the outer node."""
        vc = _load_fixture("legal-person-credential.json", gaiax=True)
        assert "name" not in vc["credentialSubject"]

    def test_roundtrip(self):
        vc = _load_fixture("legal-person-credential.json", gaiax=True)
        mapping = GAIAX_MAPPINGS["harbour:LegalPersonCredential"]
        claims, _ = vc_to_sd_jwt_claims(vc, mapping)
        reconstructed = sd_jwt_claims_to_vc(
            claims, mapping, "harbour:LegalPersonCredential"
        )
        assert (
            reconstructed["credentialSubject"]["gxParticipant"]["schema:name"]
            == vc["credentialSubject"]["gxParticipant"]["schema:name"]
        )


class TestGaiaxNaturalPersonMapping:
    def test_vc_to_claims(self):
        vc = _load_fixture("natural-person-credential.json", gaiax=True)
        mapping = GAIAX_MAPPINGS["harbour:NaturalPersonCredential"]
        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)

        assert claims["givenName"] == "Alice"
        assert claims["gxName"] == "Alice Smith"
        assert "gxName" in disclosable

    def test_gx_inner_node_exists(self):
        """Verify gx:Participant data lives in the gxParticipant inner node."""
        vc = _load_fixture("natural-person-credential.json", gaiax=True)
        subject = vc["credentialSubject"]
        gx = subject["gxParticipant"]
        assert gx["type"] == "gx:Participant"

    def test_no_outer_name(self):
        """Gaia-X extension should NOT have name on the outer node."""
        vc = _load_fixture("natural-person-credential.json", gaiax=True)
        assert "name" not in vc["credentialSubject"]

    def test_has_gaiax_context(self):
        """Gaia-X extension must include the Gaia-X namespace in @context."""
        vc = _load_fixture("natural-person-credential.json", gaiax=True)
        assert GAIAX_NS in vc["@context"]


# ---------------------------------------------------------------------------
# Context-aware mapping discovery
# ---------------------------------------------------------------------------


class TestMappingDiscovery:
    def test_get_mapping_for_harbour_skeleton(self):
        """Base skeleton (no Gaia-X context) should return base mapping."""
        vc = _load_fixture("legal-person-credential.json")
        mapping = get_mapping_for_vc(vc)
        assert mapping is not None
        assert "LegalPersonCredential" in mapping["vct"]
        # Base mapping should NOT have gxParticipant paths
        assert "credentialSubject.gxParticipant.schema:name" not in mapping["claims"]

    def test_get_mapping_for_gaiax_extension(self):
        """Gaia-X extension (with Gaia-X context) should return Gaia-X mapping."""
        vc = _load_fixture("legal-person-credential.json", gaiax=True)
        mapping = get_mapping_for_vc(vc)
        assert mapping is not None
        assert "LegalPersonCredential" in mapping["vct"]
        # Gaia-X mapping should have gxParticipant paths
        assert "credentialSubject.gxParticipant.schema:name" in mapping["claims"]

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
