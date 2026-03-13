"""Tests for claim mappings: W3C VCDM JSON-LD <-> SD-JWT-VC flat claims."""

import json
from pathlib import Path

from credentials.claim_mapping import (
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


def _load_fixture(name: str) -> dict:
    """Load a credential example from the gaiax examples directory."""
    with open(GAIAX_EXAMPLES_DIR / name) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Gaia-X domain tests (primary — all domain examples live in gaiax/)
# ---------------------------------------------------------------------------


class TestGaiaxLegalPersonMapping:
    def test_vc_to_claims(self):
        vc = _load_fixture("legal-person-credential.json")
        mapping = MAPPINGS["harbour.gx:LegalPersonCredential"]
        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)

        assert (
            claims["iss"]
            == "did:ethr:0x14a34:0x9c2f52ea812629d0d35b2786ae26633d03a8c697"
        )
        assert (
            claims["sub"]
            == "did:ethr:0x14a34:0xf7ef72f0ad8256df1a731ca0cb26230683518dab"
        )
        assert claims["labelLevel"] == "SC"
        assert "engineVersion" in claims
        assert "engineVersion" in disclosable

    def test_has_credential_status(self):
        vc = _load_fixture("legal-person-credential.json")
        assert "credentialStatus" in vc
        status = vc["credentialStatus"][0]
        assert status["type"] == "harbour:CRSetEntry"
        assert status["statusPurpose"] == "revocation"

    def test_subject_is_harbour_gx_legal_person(self):
        """Verify the subject uses harbour.gx:LegalPerson."""
        vc = _load_fixture("legal-person-credential.json")
        subject_type = vc["credentialSubject"]["type"]
        assert subject_type == "harbour.gx:LegalPerson"

    def test_has_gaiax_context(self):
        """Gaia-X extension must include the Gaia-X namespace in @context."""
        vc = _load_fixture("legal-person-credential.json")
        assert GAIAX_NS in vc["@context"]

    def test_roundtrip(self):
        vc = _load_fixture("legal-person-credential.json")
        mapping = MAPPINGS["harbour.gx:LegalPersonCredential"]
        claims, _ = vc_to_sd_jwt_claims(vc, mapping)
        reconstructed = sd_jwt_claims_to_vc(
            claims, mapping, "harbour.gx:LegalPersonCredential"
        )
        assert (
            reconstructed["credentialSubject"]["harbour.gx:labelLevel"]
            == vc["credentialSubject"]["harbour.gx:labelLevel"]
        )


class TestGaiaxNaturalPersonMapping:
    def test_vc_to_claims(self):
        vc = _load_fixture("natural-person-credential.json")
        mapping = MAPPINGS["harbour.gx:NaturalPersonCredential"]
        claims, disclosable = vc_to_sd_jwt_claims(vc, mapping)

        assert claims["givenName"] == "Alice"
        assert claims["familyName"] == "Smith"
        assert "givenName" in disclosable
        assert (
            claims["memberOf"]
            == "did:ethr:0x14a34:0xf7ef72f0ad8256df1a731ca0cb26230683518dab"
        )

    def test_has_credential_status(self):
        vc = _load_fixture("natural-person-credential.json")
        assert "credentialStatus" in vc
        status = vc["credentialStatus"][0]
        assert status["type"] == "harbour:CRSetEntry"

    def test_has_evidence(self):
        vc = _load_fixture("natural-person-credential.json")
        assert "evidence" in vc
        evidence = vc["evidence"][0]
        ev_type = evidence["type"]
        if isinstance(ev_type, list):
            assert "harbour:CredentialEvidence" in ev_type
        else:
            assert ev_type == "harbour:CredentialEvidence"

    def test_subject_is_harbour_gx_natural_person(self):
        """Verify the subject uses harbour.gx:NaturalPerson."""
        vc = _load_fixture("natural-person-credential.json")
        subject_type = vc["credentialSubject"]["type"]
        assert subject_type == "harbour.gx:NaturalPerson"

    def test_has_gaiax_context(self):
        """Gaia-X extension must include the Gaia-X namespace in @context."""
        vc = _load_fixture("natural-person-credential.json")
        assert GAIAX_NS in vc["@context"]


# ---------------------------------------------------------------------------
# Context-aware mapping discovery
# ---------------------------------------------------------------------------


class TestMappingDiscovery:
    def test_get_mapping_for_gaiax_legal_person(self):
        """Gaia-X legal person should return the flat mapping."""
        vc = _load_fixture("legal-person-credential.json")
        mapping = get_mapping_for_vc(vc)
        assert mapping is not None
        assert "LegalPersonCredential" in mapping["vct"]
        assert "credentialSubject.harbour\\.gx:labelLevel" in mapping["claims"]

    def test_get_mapping_for_gaiax_natural_person(self):
        """Gaia-X natural person should return the flat mapping."""
        vc = _load_fixture("natural-person-credential.json")
        mapping = get_mapping_for_vc(vc)
        assert mapping is not None
        assert "NaturalPersonCredential" in mapping["vct"]
        assert "credentialSubject.givenName" in mapping["claims"]

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
            "issuer": "did:ethr:0x14a34:0x212025b9751231b17ead53fdcaad8ddeffa0106c",
            "validFrom": "2024-01-01T00:00:00Z",
            "credentialSubject": {
                "id": "did:ethr:0x14a34:0xe21cf53752b534301cd285712734ab1710260543",
                "customField": "custom-value",
            },
            "credentialStatus": [
                {
                    "id": "did:ethr:0x14a34:0x212025b9751231b17ead53fdcaad8ddeffa0106c:revocation#abc123",
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
