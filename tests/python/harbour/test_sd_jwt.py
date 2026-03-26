"""Tests for SD-JWT-VC issuance and verification."""

import pytest

from harbour.keys import (
    generate_p256_keypair,
    p256_public_key_to_jwk,
    public_key_to_jwk,
)
from harbour.sd_jwt import issue_sd_jwt_vc, verify_sd_jwt_vc
from harbour.verifier import VerificationError

SAMPLE_CLAIMS = {
    "iss": "did:ethr:0x14a34:0x212025b9751231b17ead53fdcaad8ddeffa0106c",
    "iat": 1723972522,
    "exp": 1913990400,
    "legalName": "Example Corporation GmbH",
    "legalForm": "GmbH",
    "countryCode": "DE",
    "email": "info@example.com",
}

VCT = "https://w3id.org/reachhaven/harbour/core/v1/LegalPersonCredential"


class TestSDJWTVCIssuance:
    def test_issue_produces_sd_jwt_format(self, p256_private_key):
        sd_jwt = issue_sd_jwt_vc(SAMPLE_CLAIMS, p256_private_key, vct=VCT)
        parts = sd_jwt.split("~")
        # At minimum: issuer-jwt and trailing empty
        assert len(parts) >= 2
        assert parts[-1] == ""  # trailing ~
        # First part is a JWS (3 dot-separated segments)
        assert len(parts[0].split(".")) == 3

    def test_issue_with_disclosable_claims(self, p256_private_key):
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS,
            p256_private_key,
            vct=VCT,
            disclosable=["email", "countryCode"],
        )
        parts = sd_jwt.split("~")
        # issuer-jwt + 2 disclosures + trailing empty = 4 parts
        assert len(parts) == 4
        # Disclosures are non-empty base64url strings
        assert all(len(p) > 0 for p in parts[1:3])

    def test_issue_includes_vct_in_payload(self, p256_private_key, p256_public_key):
        sd_jwt = issue_sd_jwt_vc(SAMPLE_CLAIMS, p256_private_key, vct=VCT)
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)
        assert result["vct"] == VCT

    def test_issue_with_cnf(self, p256_private_key, p256_public_key):
        holder_pub_jwk = p256_public_key_to_jwk(p256_public_key)
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS,
            p256_private_key,
            vct=VCT,
            cnf={"jwk": holder_pub_jwk},
        )
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)
        assert "cnf" in result
        assert result["cnf"]["jwk"]["crv"] == "P-256"


class TestSDJWTVCVerification:
    def test_verify_all_disclosed(self, p256_private_key, p256_public_key):
        sd_jwt = issue_sd_jwt_vc(SAMPLE_CLAIMS, p256_private_key, vct=VCT)
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)
        assert result["legalName"] == "Example Corporation GmbH"
        assert (
            result["iss"]
            == "did:ethr:0x14a34:0x212025b9751231b17ead53fdcaad8ddeffa0106c"
        )

    def test_verify_with_selective_disclosure(self, p256_private_key, p256_public_key):
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS,
            p256_private_key,
            vct=VCT,
            disclosable=["email", "countryCode"],
        )
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)
        # Both disclosable claims should be disclosed (all disclosures present)
        assert result["email"] == "info@example.com"
        assert result["countryCode"] == "DE"
        # Non-disclosable claims are always present
        assert result["legalName"] == "Example Corporation GmbH"

    def test_verify_partial_disclosure(self, p256_private_key, p256_public_key):
        """Remove one disclosure to simulate holder hiding a claim."""
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS,
            p256_private_key,
            vct=VCT,
            disclosable=["email", "countryCode"],
        )
        # Remove the first disclosure (keep only one)
        parts = sd_jwt.split("~")
        # parts: [issuer_jwt, disc1, disc2, ""]
        partial = f"{parts[0]}~{parts[2]}~"
        result = verify_sd_jwt_vc(partial, p256_public_key)
        # One claim should be missing, one present
        disclosed_keys = set(result.keys())
        # At least one of email/countryCode should be present, one missing
        assert len(disclosed_keys & {"email", "countryCode"}) == 1

    def test_verify_wrong_key_fails(self, p256_private_key):
        sd_jwt = issue_sd_jwt_vc(SAMPLE_CLAIMS, p256_private_key, vct=VCT)
        _, wrong_public = generate_p256_keypair()
        with pytest.raises(VerificationError):
            verify_sd_jwt_vc(sd_jwt, wrong_public)

    def test_verify_expected_vct_mismatch(self, p256_private_key, p256_public_key):
        sd_jwt = issue_sd_jwt_vc(SAMPLE_CLAIMS, p256_private_key, vct=VCT)
        with pytest.raises(VerificationError, match="VCT mismatch"):
            verify_sd_jwt_vc(
                sd_jwt, p256_public_key, expected_vct="https://wrong.example.com/vc"
            )

    def test_tamper_issuer_jwt(self, p256_private_key, p256_public_key):
        sd_jwt = issue_sd_jwt_vc(SAMPLE_CLAIMS, p256_private_key, vct=VCT)
        parts = sd_jwt.split("~")
        jwt_parts = parts[0].split(".")
        # Corrupt signature
        sig = jwt_parts[2]
        corrupted = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        parts[0] = f"{jwt_parts[0]}.{jwt_parts[1]}.{corrupted}"
        tampered = "~".join(parts)
        with pytest.raises(VerificationError):
            verify_sd_jwt_vc(tampered, p256_public_key)


class TestSDJWTVCEd25519:
    """SD-JWT-VC tests with Ed25519 keys."""

    def test_issue_and_verify_ed25519(self, ed25519_private_key, ed25519_public_key):
        sd_jwt = issue_sd_jwt_vc(SAMPLE_CLAIMS, ed25519_private_key, vct=VCT)
        result = verify_sd_jwt_vc(sd_jwt, ed25519_public_key)
        assert result["vct"] == VCT
        assert result["legalName"] == "Example Corporation GmbH"

    def test_selective_disclosure_ed25519(
        self, ed25519_private_key, ed25519_public_key
    ):
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS,
            ed25519_private_key,
            vct=VCT,
            disclosable=["email", "countryCode"],
        )
        result = verify_sd_jwt_vc(sd_jwt, ed25519_public_key)
        assert result["email"] == "info@example.com"
        assert result["countryCode"] == "DE"

    def test_wrong_key_type_fails(self, ed25519_private_key, p256_public_key):
        sd_jwt = issue_sd_jwt_vc(SAMPLE_CLAIMS, ed25519_private_key, vct=VCT)
        with pytest.raises(VerificationError):
            verify_sd_jwt_vc(sd_jwt, p256_public_key)

    def test_cnf_with_ed25519(self, ed25519_private_key, ed25519_public_key):
        holder_jwk = public_key_to_jwk(ed25519_public_key)
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS,
            ed25519_private_key,
            vct=VCT,
            cnf={"jwk": holder_jwk},
        )
        result = verify_sd_jwt_vc(sd_jwt, ed25519_public_key)
        assert result["cnf"]["jwk"]["crv"] == "Ed25519"


# ---------------------------------------------------------------------------
# Structured (nested) selective disclosure — RFC 9901 §6.2
# ---------------------------------------------------------------------------

NESTED_CLAIMS = {
    "iss": "did:ethr:0x14a34:0x212025b9751231b17ead53fdcaad8ddeffa0106c",
    "iat": 1723972522,
    "exp": 1913990400,
    "credentialSubject": {
        "id": "did:ethr:0x14a34:0x9d273DCaC2f6367968d61caf69A7E3177fd81048",
        "harbourCredential": "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890",
        "legalForm": "AG",
        "duns": "313995269",
        "email": "imprint@bmw.com",
        "url": "https://www.bmwgroup.com/",
        "gxParticipant": {
            "name": "Bayerische Motoren Werke Aktiengesellschaft",
        },
    },
}

NESTED_VCT = "https://w3id.org/ascs-ev/simpulse-id/v1/ParticipantCredential"


class TestStructuredDisclosure:
    """Structured SD-JWT with _sd at nested levels per RFC 9901 §6.2."""

    def test_nested_disclosure_issue_format(self, p256_private_key):
        """Nested disclosable paths produce disclosures."""
        sd_jwt = issue_sd_jwt_vc(
            NESTED_CLAIMS,
            p256_private_key,
            vct=NESTED_VCT,
            disclosable=[
                "credentialSubject.email",
                "credentialSubject.duns",
                "credentialSubject.url",
            ],
        )
        parts = sd_jwt.split("~")
        # issuer-jwt + 3 disclosures + trailing empty = 5 parts
        assert len(parts) == 5

    def test_nested_disclosure_verify_all(self, p256_private_key, p256_public_key):
        """All disclosures present → full nested structure reconstructed."""
        sd_jwt = issue_sd_jwt_vc(
            NESTED_CLAIMS,
            p256_private_key,
            vct=NESTED_VCT,
            disclosable=[
                "credentialSubject.email",
                "credentialSubject.duns",
            ],
        )
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)

        # Always-disclosed nested claims preserved
        assert result["credentialSubject"]["legalForm"] == "AG"
        assert result["credentialSubject"]["gxParticipant"]["name"] == (
            "Bayerische Motoren Werke Aktiengesellschaft"
        )
        # Selectively-disclosed claims present (all disclosures provided)
        assert result["credentialSubject"]["email"] == "imprint@bmw.com"
        assert result["credentialSubject"]["duns"] == "313995269"

    def test_nested_partial_disclosure(self, p256_private_key, p256_public_key):
        """Remove one nested disclosure → holder hides a claim."""
        sd_jwt = issue_sd_jwt_vc(
            NESTED_CLAIMS,
            p256_private_key,
            vct=NESTED_VCT,
            disclosable=[
                "credentialSubject.email",
                "credentialSubject.duns",
                "credentialSubject.url",
            ],
        )
        # Remove first two disclosures, keep only the third
        parts = sd_jwt.split("~")
        partial = f"{parts[0]}~{parts[3]}~"
        result = verify_sd_jwt_vc(partial, p256_public_key)

        # Structure preserved, always-disclosed claims present
        assert result["credentialSubject"]["legalForm"] == "AG"
        # Only one of the three disclosable claims should be present
        sd_keys = {"email", "duns", "url"}
        present = sd_keys & set(result["credentialSubject"].keys())
        assert len(present) == 1

    def test_mixed_flat_and_nested(self, p256_private_key, p256_public_key):
        """Mix of top-level and nested disclosable paths."""
        claims = {
            "iss": "did:ethr:0x14a34:0x212025b9751231b17ead53fdcaad8ddeffa0106c",
            "topSecret": "classified",
            "nested": {
                "sensitive": "hidden-value",
                "public": "visible",
            },
        }
        sd_jwt = issue_sd_jwt_vc(
            claims,
            p256_private_key,
            vct=VCT,
            disclosable=["topSecret", "nested.sensitive"],
        )
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)

        assert result["topSecret"] == "classified"
        assert result["nested"]["sensitive"] == "hidden-value"
        assert result["nested"]["public"] == "visible"

    def test_nested_disclosure_preserves_always_disclosed(
        self, p256_private_key, p256_public_key
    ):
        """Non-disclosable nested claims stay in cleartext."""
        sd_jwt = issue_sd_jwt_vc(
            NESTED_CLAIMS,
            p256_private_key,
            vct=NESTED_VCT,
            disclosable=["credentialSubject.email"],
        )
        # Remove the email disclosure
        parts = sd_jwt.split("~")
        no_disclosures = f"{parts[0]}~"
        result = verify_sd_jwt_vc(no_disclosures, p256_public_key)

        # All non-disclosable claims preserved
        cs = result["credentialSubject"]
        assert cs["id"] == "did:ethr:0x14a34:0x9d273DCaC2f6367968d61caf69A7E3177fd81048"
        assert cs["harbourCredential"] == "urn:uuid:a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        assert cs["legalForm"] == "AG"
        assert cs["duns"] == "313995269"
        assert cs["url"] == "https://www.bmwgroup.com/"
        assert cs["gxParticipant"]["name"] == "Bayerische Motoren Werke Aktiengesellschaft"
        # Email should NOT be present (disclosure was removed)
        assert "email" not in cs

    def test_nonexistent_path_ignored(self, p256_private_key, p256_public_key):
        """Disclosable path that doesn't exist in claims is silently skipped."""
        sd_jwt = issue_sd_jwt_vc(
            NESTED_CLAIMS,
            p256_private_key,
            vct=NESTED_VCT,
            disclosable=["credentialSubject.nonexistent"],
        )
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)
        # No disclosures created, all claims present as always-disclosed
        assert result["credentialSubject"]["email"] == "imprint@bmw.com"

    def test_sd_alg_at_root_only(self, p256_private_key, p256_public_key):
        """_sd_alg should appear only at root level, not in nested objects."""
        import base64
        import json

        sd_jwt = issue_sd_jwt_vc(
            NESTED_CLAIMS,
            p256_private_key,
            vct=NESTED_VCT,
            disclosable=["credentialSubject.email"],
        )
        # Decode the issuer JWT payload
        issuer_jwt = sd_jwt.split("~")[0]
        payload_b64 = issuer_jwt.split(".")[1]
        payload = json.loads(
            base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        )
        # _sd_alg at root
        assert payload["_sd_alg"] == "sha-256"
        # _sd inside credentialSubject (where disclosure lives)
        assert "_sd" in payload["credentialSubject"]
        # NO _sd_alg inside credentialSubject
        assert "_sd_alg" not in payload["credentialSubject"]
