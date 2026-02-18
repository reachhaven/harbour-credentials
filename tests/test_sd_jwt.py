"""Tests for SD-JWT-VC issuance and verification."""

import pytest

from harbour.jose.keys import generate_p256_keypair, p256_public_key_to_jwk
from harbour.jose.sd_jwt import issue_sd_jwt_vc
from harbour.jose.sd_jwt_verifier import verify_sd_jwt_vc
from harbour.jose.verifier import VerificationError


SAMPLE_CLAIMS = {
    "iss": "did:web:did.ascs.digital:participants:ascs",
    "iat": 1723972522,
    "exp": 1913990400,
    "legalName": "Bayerische Motoren Werke AG",
    "legalForm": "AG",
    "countryCode": "DE",
    "email": "imprint@bmw.com",
}

VCT = "https://w3id.org/ascs-ev/simpulse-id/credentials/v1/ParticipantCredential"


class TestSDJWTVCIssuance:
    def test_issue_produces_sd_jwt_format(self, p256_private_key):
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS, p256_private_key, vct=VCT
        )
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
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS, p256_private_key, vct=VCT
        )
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
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS, p256_private_key, vct=VCT
        )
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)
        assert result["legalName"] == "Bayerische Motoren Werke AG"
        assert result["iss"] == "did:web:did.ascs.digital:participants:ascs"

    def test_verify_with_selective_disclosure(
        self, p256_private_key, p256_public_key
    ):
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS,
            p256_private_key,
            vct=VCT,
            disclosable=["email", "countryCode"],
        )
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)
        # Both disclosable claims should be disclosed (all disclosures present)
        assert result["email"] == "imprint@bmw.com"
        assert result["countryCode"] == "DE"
        # Non-disclosable claims are always present
        assert result["legalName"] == "Bayerische Motoren Werke AG"

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
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS, p256_private_key, vct=VCT
        )
        _, wrong_public = generate_p256_keypair()
        with pytest.raises(VerificationError):
            verify_sd_jwt_vc(sd_jwt, wrong_public)

    def test_verify_expected_vct_mismatch(
        self, p256_private_key, p256_public_key
    ):
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS, p256_private_key, vct=VCT
        )
        with pytest.raises(VerificationError, match="VCT mismatch"):
            verify_sd_jwt_vc(
                sd_jwt, p256_public_key, expected_vct="https://wrong.example.com/vc"
            )

    def test_tamper_issuer_jwt(self, p256_private_key, p256_public_key):
        sd_jwt = issue_sd_jwt_vc(
            SAMPLE_CLAIMS, p256_private_key, vct=VCT
        )
        parts = sd_jwt.split("~")
        jwt_parts = parts[0].split(".")
        # Corrupt signature
        sig = jwt_parts[2]
        corrupted = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        parts[0] = f"{jwt_parts[0]}.{jwt_parts[1]}.{corrupted}"
        tampered = "~".join(parts)
        with pytest.raises(VerificationError):
            verify_sd_jwt_vc(tampered, p256_public_key)
