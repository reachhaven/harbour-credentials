"""Tests for SD-JWT VP (Verifiable Presentations with selective disclosure)."""

import base64
import json
import secrets

import pytest
from harbour.keys import generate_p256_keypair, p256_public_key_to_did_key
from harbour.sd_jwt import issue_sd_jwt_vc
from harbour.sd_jwt_vp import issue_sd_jwt_vp, verify_sd_jwt_vp
from harbour.verifier import VerificationError


@pytest.fixture
def issuer_keypair():
    """Generate issuer key pair."""
    return generate_p256_keypair()


@pytest.fixture
def holder_keypair():
    """Generate holder key pair."""
    return generate_p256_keypair()


@pytest.fixture
def sample_sd_jwt_vc(issuer_keypair, holder_keypair):
    """Create a sample SD-JWT-VC for testing."""
    private_key, public_key = issuer_keypair
    holder_private, holder_public = holder_keypair
    holder_did = p256_public_key_to_did_key(holder_public)

    # SD-JWT-VC uses flat claims (not nested credentialSubject)
    claims = {
        "iss": "did:web:issuer.example.com",
        "sub": holder_did,
        "givenName": "Alice",
        "familyName": "Smith",
        "email": "alice@example.com",
        "memberOf": "Example Organization",
        "role": "member",
    }

    # Create SD-JWT-VC with selective disclosure claims
    sd_jwt_vc = issue_sd_jwt_vc(
        claims,
        private_key,
        vct="https://example.com/MembershipCredential",
        disclosable=["givenName", "familyName", "email"],
    )

    return sd_jwt_vc


class TestIssueSDJWTVP:
    """Test SD-JWT VP issuance."""

    def test_issue_basic_vp(self, sample_sd_jwt_vc, holder_keypair):
        """Test basic VP issuance with all disclosures."""
        holder_private, _ = holder_keypair

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            nonce="test-nonce-123",
            audience="did:web:verifier.example.com",
        )

        # Should be a ~-separated string
        assert "~" in vp
        parts = vp.split("~")

        # Should have: vp-jwt, issuer-jwt, disclosures..., kb-jwt
        assert len(parts) >= 4

        # First part should be VP JWT
        vp_jwt = parts[0]
        header_b64 = vp_jwt.split(".")[0]
        header = json.loads(base64.urlsafe_b64decode(header_b64 + "=="))
        assert header["typ"] == "vp+sd-jwt"
        assert header["alg"] == "ES256"

        # Last part should be KB-JWT
        kb_jwt = parts[-1]
        kb_header_b64 = kb_jwt.split(".")[0]
        kb_header = json.loads(base64.urlsafe_b64decode(kb_header_b64 + "=="))
        assert kb_header["typ"] == "kb+jwt"

    def test_issue_with_selective_disclosure(self, sample_sd_jwt_vc, holder_keypair):
        """Test VP issuance with selective disclosure (only some claims)."""
        holder_private, _ = holder_keypair

        # Only disclose memberOf, hide PII
        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            disclosures=["memberOf"],
            nonce="nonce-456",
        )

        parts = vp.split("~")
        # Should have fewer disclosures than full
        # vp-jwt + issuer-jwt + 1 disclosure + kb-jwt = 4 parts
        # But memberOf is not an SD claim, so 0 disclosures included
        assert len(parts) >= 3

    def test_issue_with_no_disclosures(self, sample_sd_jwt_vc, holder_keypair):
        """Test VP issuance with no disclosures (max privacy)."""
        holder_private, _ = holder_keypair

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            disclosures=[],  # Empty list = no disclosures
            nonce="nonce-789",
        )

        parts = vp.split("~")
        # Should have: vp-jwt, issuer-jwt, kb-jwt (no disclosures)
        assert len(parts) >= 3

    def test_issue_with_evidence(self, sample_sd_jwt_vc, holder_keypair):
        """Test VP issuance with DelegatedSignatureEvidence."""
        holder_private, _ = holder_keypair

        evidence = [
            {
                "type": "DelegatedSignatureEvidence",
                "transactionData": {
                    "type": "harbour_delegate:data.purchase",
                    "credential_ids": ["simpulse_id"],
                    "nonce": secrets.token_urlsafe(16),
                    "iat": 1771934400,
                    "txn": {"assetId": "tx:abc123", "price": "100"},
                },
                "delegatedTo": "did:web:signing-service.example.com",
            }
        ]

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            evidence=evidence,
            nonce="tx-consent-nonce",
            audience="did:web:signing-service.example.com",
        )

        # Parse VP JWT payload to check evidence
        parts = vp.split("~")
        vp_jwt = parts[0]
        payload_b64 = vp_jwt.split(".")[1]
        payload = json.loads(
            base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        )

        assert "vp" in payload
        assert "evidence" in payload["vp"]
        assert len(payload["vp"]["evidence"]) == 1
        assert payload["vp"]["evidence"][0]["type"] == "DelegatedSignatureEvidence"

    def test_issue_with_holder_did(self, sample_sd_jwt_vc, holder_keypair):
        """Test VP issuance with holder DID."""
        holder_private, holder_public = holder_keypair
        holder_did = p256_public_key_to_did_key(holder_public)

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            holder_did=holder_did,
            nonce="holder-nonce",
        )

        # Parse VP JWT payload
        parts = vp.split("~")
        vp_jwt = parts[0]
        payload_b64 = vp_jwt.split(".")[1]
        payload = json.loads(
            base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        )

        assert payload.get("iss") == holder_did
        assert payload["vp"].get("holder") == holder_did


class TestVerifySDJWTVP:
    """Test SD-JWT VP verification."""

    def test_verify_basic_vp(self, sample_sd_jwt_vc, issuer_keypair, holder_keypair):
        """Test basic VP verification."""
        _, issuer_public = issuer_keypair
        holder_private, holder_public = holder_keypair

        nonce = "verify-test-nonce"
        audience = "did:web:verifier.example.com"

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            nonce=nonce,
            audience=audience,
        )

        result = verify_sd_jwt_vp(
            vp,
            issuer_public,
            holder_public,
            expected_nonce=nonce,
            expected_audience=audience,
        )

        assert "credential" in result
        assert result["nonce"] == nonce
        assert result["audience"] == audience

    def test_verify_disclosed_claims(
        self, sample_sd_jwt_vc, issuer_keypair, holder_keypair
    ):
        """Test that disclosed claims are returned."""
        _, issuer_public = issuer_keypair
        holder_private, holder_public = holder_keypair

        # Include all disclosures
        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
        )

        result = verify_sd_jwt_vp(vp, issuer_public, holder_public)

        cred = result["credential"]
        # Non-SD claims should always be present
        assert cred.get("memberOf") == "Example Organization"
        assert cred.get("role") == "member"
        # SD claims should be disclosed
        assert cred.get("givenName") == "Alice"
        assert cred.get("familyName") == "Smith"
        assert cred.get("email") == "alice@example.com"

    def test_verify_selective_disclosure(
        self, sample_sd_jwt_vc, issuer_keypair, holder_keypair
    ):
        """Test verification with partial disclosure."""
        _, issuer_public = issuer_keypair
        holder_private, holder_public = holder_keypair

        # Only disclose givenName
        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            disclosures=["givenName"],
        )

        result = verify_sd_jwt_vp(vp, issuer_public, holder_public)

        cred = result["credential"]
        # Disclosed claim should be present
        assert cred.get("givenName") == "Alice"
        # Other SD claims should NOT be present
        assert "familyName" not in cred
        assert "email" not in cred

    def test_verify_evidence(self, sample_sd_jwt_vc, issuer_keypair, holder_keypair):
        """Test that evidence is returned on verification."""
        _, issuer_public = issuer_keypair
        holder_private, holder_public = holder_keypair

        evidence = [
            {
                "type": "DelegatedSignatureEvidence",
                "transactionData": {
                    "type": "harbour_delegate:blockchain.approve",
                    "credential_ids": ["default"],
                    "nonce": "unique-consent-nonce",
                    "iat": 1771934400,
                    "txn": {"contract": "0x1234"},
                },
            }
        ]

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            evidence=evidence,
        )

        result = verify_sd_jwt_vp(vp, issuer_public, holder_public)

        assert "evidence" in result
        assert len(result["evidence"]) == 1
        assert result["evidence"][0]["type"] == "DelegatedSignatureEvidence"

    def test_verify_fails_wrong_issuer_key(self, sample_sd_jwt_vc, holder_keypair):
        """Test that verification fails with wrong issuer key."""
        holder_private, holder_public = holder_keypair
        _, wrong_issuer_public = generate_p256_keypair()

        vp = issue_sd_jwt_vp(sample_sd_jwt_vc, holder_private)

        with pytest.raises(VerificationError, match="VC JWT verification failed"):
            verify_sd_jwt_vp(vp, wrong_issuer_public, holder_public)

    def test_verify_fails_wrong_holder_key(
        self, sample_sd_jwt_vc, issuer_keypair, holder_keypair
    ):
        """Test that verification fails with wrong holder key."""
        _, issuer_public = issuer_keypair
        holder_private, _ = holder_keypair
        _, wrong_holder_public = generate_p256_keypair()

        vp = issue_sd_jwt_vp(sample_sd_jwt_vc, holder_private)

        with pytest.raises(VerificationError, match="VP JWT verification failed"):
            verify_sd_jwt_vp(vp, issuer_public, wrong_holder_public)

    def test_verify_fails_nonce_mismatch(
        self, sample_sd_jwt_vc, issuer_keypair, holder_keypair
    ):
        """Test that verification fails with nonce mismatch."""
        _, issuer_public = issuer_keypair
        holder_private, holder_public = holder_keypair

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            nonce="original-nonce",
        )

        with pytest.raises(VerificationError, match="Nonce mismatch"):
            verify_sd_jwt_vp(
                vp,
                issuer_public,
                holder_public,
                expected_nonce="wrong-nonce",
            )

    def test_verify_fails_audience_mismatch(
        self, sample_sd_jwt_vc, issuer_keypair, holder_keypair
    ):
        """Test that verification fails with audience mismatch."""
        _, issuer_public = issuer_keypair
        holder_private, holder_public = holder_keypair

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            audience="did:web:expected-verifier.example.com",
        )

        with pytest.raises(VerificationError, match="Audience mismatch"):
            verify_sd_jwt_vp(
                vp,
                issuer_public,
                holder_public,
                expected_audience="did:web:wrong-verifier.example.com",
            )


class TestDelegatedSigningFlow:
    """Test the complete delegated signing flow."""

    def test_delegated_consent_flow(self, issuer_keypair, holder_keypair):
        """Test the full delegated signing consent flow.

        This simulates:
        1. Issuer issues SD-JWT-VC to holder
        2. Holder creates VP with transaction consent evidence
        3. Signing service verifies VP and evidence
        """
        issuer_private, issuer_public = issuer_keypair
        holder_private, holder_public = holder_keypair
        holder_did = p256_public_key_to_did_key(holder_public)

        # Step 1: Issue credential to holder (SD-JWT-VC uses flat claims)
        claims = {
            "iss": "did:web:trusted-issuer.example.com",
            "sub": holder_did,
            "givenName": "Carlo",
            "familyName": "Rossi",
            "organization": "BMW",
            "role": "Purchaser",
        }

        sd_jwt_vc = issue_sd_jwt_vc(
            claims,
            issuer_private,
            vct="https://example.com/IdentityCredential",
            disclosable=["givenName", "familyName"],  # PII is selectively disclosable
        )

        # Step 2: Holder creates consent VP
        signing_service_did = "did:web:harbour.signing-service.example.com"
        consent_nonce = secrets.token_urlsafe(32)

        transaction_data = {
            "type": "harbour_delegate:data.purchase",
            "credential_ids": ["simpulse_id"],
            "nonce": consent_nonce,
            "iat": 1771934400,
            "description": "Purchase data asset XYZ for 100 ENVITED tokens",
            "txn": {
                "assetId": "tx:0xabc123def456",
                "price": "100",
                "currency": "ENVITED",
            },
        }

        evidence = [
            {
                "type": "DelegatedSignatureEvidence",
                "transactionData": transaction_data,
                "delegatedTo": signing_service_did,
            }
        ]

        challenge_nonce = secrets.token_urlsafe(16)

        # Create VP with:
        # - Only organization and role disclosed (not PII)
        # - Evidence containing transaction intent
        vp = issue_sd_jwt_vp(
            sd_jwt_vc,
            holder_private,
            disclosures=["organization"],  # Don't disclose givenName, familyName
            evidence=evidence,
            nonce=challenge_nonce,
            audience=signing_service_did,
            holder_did=holder_did,
        )

        # Step 3: Signing service verifies VP
        result = verify_sd_jwt_vp(
            vp,
            issuer_public,
            holder_public,
            expected_nonce=challenge_nonce,
            expected_audience=signing_service_did,
        )

        # Verify result
        assert result["holder"] == holder_did
        assert result["nonce"] == challenge_nonce
        assert result["audience"] == signing_service_did

        # Credential should have organization but NOT PII
        cred = result["credential"]
        assert cred.get("organization") == "BMW"
        assert "givenName" not in cred  # PII hidden
        assert "familyName" not in cred  # PII hidden

        # Evidence should contain transaction data
        assert len(result["evidence"]) == 1
        ev = result["evidence"][0]
        assert ev["type"] == "DelegatedSignatureEvidence"
        assert ev["transactionData"]["type"] == "harbour_delegate:data.purchase"
        assert ev["transactionData"]["nonce"] == consent_nonce
        assert ev["delegatedTo"] == signing_service_did

    def test_public_audit_privacy(self, issuer_keypair, holder_keypair):
        """Test that public audit can verify consent without seeing PII."""
        issuer_private, issuer_public = issuer_keypair
        holder_private, holder_public = holder_keypair
        holder_did = p256_public_key_to_did_key(holder_public)

        # Issue credential with PII (SD-JWT-VC uses flat claims)
        claims = {
            "iss": "did:web:issuer.example.com",
            "sub": holder_did,
            "name": "Confidential Person",
            "email": "secret@example.com",
            "publicRole": "Authorized Purchaser",
        }

        sd_jwt_vc = issue_sd_jwt_vc(
            claims,
            issuer_private,
            vct="https://example.com/VerifiableCredential",
            disclosable=["name", "email"],  # PII hidden by default
        )

        # Create VP with no PII disclosed
        evidence = [
            {
                "type": "DelegatedSignatureEvidence",
                "transactionData": {
                    "type": "harbour_delegate:blockchain.transfer",
                    "credential_ids": ["default"],
                    "nonce": "public-audit-nonce",
                    "iat": 1771934400,
                    "txn": {"recipient": "0x123", "amount": "1000"},
                },
            }
        ]

        vp = issue_sd_jwt_vp(
            sd_jwt_vc,
            holder_private,
            disclosures=["publicRole"],  # Only non-PII disclosed
            evidence=evidence,
            holder_did=holder_did,
        )

        # Public auditor verifies
        result = verify_sd_jwt_vp(vp, issuer_public, holder_public)

        # Can verify consent happened
        assert result["evidence"][0]["type"] == "DelegatedSignatureEvidence"

        # Can see authorized role
        assert result["credential"]["publicRole"] == "Authorized Purchaser"

        # Cannot see PII
        assert "name" not in result["credential"]
        assert "email" not in result["credential"]

        # DID is visible for audit trail
        assert result["holder"] == holder_did


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_invalid_sd_jwt_vc_format(self, holder_keypair):
        """Test handling of invalid SD-JWT-VC format."""
        holder_private, _ = holder_keypair

        with pytest.raises(ValueError, match="Invalid SD-JWT-VC format"):
            issue_sd_jwt_vp("not-a-valid-sd-jwt", holder_private)

    def test_invalid_sd_jwt_vp_format(self, issuer_keypair, holder_keypair):
        """Test handling of invalid SD-JWT VP format."""
        _, issuer_public = issuer_keypair
        _, holder_public = holder_keypair

        with pytest.raises(VerificationError, match="Invalid SD-JWT VP format"):
            verify_sd_jwt_vp("not~valid", issuer_public, holder_public)

    def test_empty_evidence_list(self, sample_sd_jwt_vc, holder_keypair):
        """Test VP with empty evidence list."""
        holder_private, _ = holder_keypair

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            evidence=[],  # Empty but not None
        )

        # Empty evidence list is treated as no evidence (not included in VP)
        parts = vp.split("~")
        vp_jwt = parts[0]
        payload_b64 = vp_jwt.split(".")[1]
        payload = json.loads(
            base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        )

        assert "evidence" not in payload["vp"]

    def test_multiple_evidence_items(self, sample_sd_jwt_vc, holder_keypair):
        """Test VP with multiple evidence items."""
        holder_private, _ = holder_keypair

        evidence = [
            {"type": "DelegatedSignatureEvidence", "transactionData": {}},
            {"type": "CredentialEvidence", "verifiablePresentation": "eyJ..."},
        ]

        vp = issue_sd_jwt_vp(
            sample_sd_jwt_vc,
            holder_private,
            evidence=evidence,
        )

        parts = vp.split("~")
        vp_jwt = parts[0]
        payload_b64 = vp_jwt.split(".")[1]
        payload = json.loads(
            base64.urlsafe_b64decode(payload_b64 + "=" * (-len(payload_b64) % 4))
        )

        assert len(payload["vp"]["evidence"]) == 2
