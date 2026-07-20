"""Tests for the dc+sd-jwt example issuance pipeline (batched evidence).

Verifies:
1. vct derivation, disclosable-path policy, and batch-authorizer detection
2. Plain issuance round-trips (issuer signature + selective disclosure)
3. Batch issuance: one authorization JWT shared across the batch, each
   credential's inclusion proof verifies, and the leaf is disclosure-invariant
4. ADR-006 mandate signing: every proof is executed by the Signing Service
   key, with ``kid`` naming the verification method in the issuer's document
"""

import json
from pathlib import Path

import pytest

from credentials.example_signer import (
    _intake_client_id,
    batch_authorizer,
    disclosable_paths,
    load_role_keyring,
    load_test_p256_keypair,
    process_batch,
    process_plain,
    vct_for_credential,
)
from credentials.verify_signed_examples import (
    _build_did_to_pub,
    _issuer_header,
    _raw_issuer_payload,
)
from harbour.batch_evidence import verify_batch_evidence
from harbour.keys import p256_public_key_to_did_key
from harbour.sd_jwt import verify_sd_jwt_vc

_REPO_ROOT = Path(__file__).resolve().parent
while _REPO_ROOT.name != "harbour-credentials" and _REPO_ROOT != _REPO_ROOT.parent:
    _REPO_ROOT = _REPO_ROOT.parent
GAIAX = _REPO_ROOT / "examples" / "gaiax"

TRUST_ANCHOR = "did:ethr:0x14a34:0x4d6246a7d1e60caa44b75e3af9b37ac8d6442774"


@pytest.fixture(scope="module")
def keyring():
    kr = load_role_keyring()
    if kr is None:
        pytest.skip("role keyring not available")
    return kr


@pytest.fixture(scope="module")
def did_to_pub(keyring):
    return _build_did_to_pub(keyring)


@pytest.fixture(scope="module")
def ss_pub(keyring, did_to_pub):
    """The Signing Service public key — verifies every proof (ADR-006)."""
    return did_to_pub[keyring.role_dids["haven"]]


@pytest.fixture(scope="module")
def fallback():
    priv, pub = load_test_p256_keypair()
    return priv, p256_public_key_to_did_key(pub)


def _load(name: str) -> dict:
    path = GAIAX / name
    if not path.exists():
        pytest.skip(f"{name} not present")
    return json.loads(path.read_text())


# --- pure helpers -----------------------------------------------------------


def test_vct_for_credential():
    assert (
        vct_for_credential(
            {"type": ["VerifiableCredential", "harbour.gx:LegalPersonCredential"]}
        )
        == "https://w3id.org/reachhaven/harbour/gx/v1/LegalPersonCredential"
    )
    assert (
        vct_for_credential(
            {"type": ["VerifiableCredential", "harbour:VerifiableCredential"]}
        )
        == "https://w3id.org/reachhaven/harbour/core/v1/VerifiableCredential"
    )
    assert vct_for_credential({"type": ["VerifiableCredential"]}).endswith(
        "VerifiableCredential"
    )


def test_disclosable_paths():
    vc = {
        "credentialSubject": {
            "id": "did:x",
            "type": "T",
            "givenName": "Alice",
            "email": "a@b.com",
        }
    }
    paths = disclosable_paths(vc)
    # Segment lists (not dot-strings) — claim keys may contain dots.
    assert ["credentialSubject", "givenName"] in paths
    assert ["credentialSubject", "email"] in paths
    assert ["credentialSubject", "id"] not in paths
    assert ["credentialSubject", "type"] not in paths


def test_disclosable_paths_dotted_keys_produce_disclosures():
    """Keys containing dots (harbour.gx:*) must yield working disclosures."""
    from harbour.sd_jwt import _apply_structured_disclosures

    vc = {
        "credentialSubject": {
            "id": "did:x",
            "harbour.gx:labelLevel": "BL",
            "harbour.gx:validatedCriteria": ["a"],
        }
    }
    paths = disclosable_paths(vc)
    assert len(paths) == 2
    payload, disclosures = _apply_structured_disclosures(vc, paths)
    assert len(disclosures) == 2
    assert len(payload["credentialSubject"]["_sd"]) == 2
    assert "harbour.gx:labelLevel" not in payload["credentialSubject"]


def test_batch_authorizer():
    lp = _load("legal-person-credential.json")
    assert batch_authorizer(lp) == TRUST_ANCHOR
    # no evidence → not a batch
    assert batch_authorizer({"type": ["VerifiableCredential"]}) is None


# --- issuance round-trips ---------------------------------------------------


def test_process_plain_round_trip(keyring, ss_pub, fallback, tmp_path):
    vc = _load("delegated-signing-receipt.json")
    process_plain(vc, tmp_path, "delegated-signing-receipt", keyring, fallback)
    sd = (tmp_path / "delegated-signing-receipt.sd-jwt").read_text().strip()
    # The Signing Service issues its own receipts and signs as itself.
    assert _issuer_header(sd)["kid"] == f"{vc['issuer']}#controller"
    disclosed = verify_sd_jwt_vc(sd, ss_pub)
    assert "credentialStatus" in disclosed
    # plain credentials carry no batch evidence
    assert batch_authorizer(_raw_issuer_payload(sd)) is None


def test_process_batch_one_signature_and_proofs(
    keyring, did_to_pub, ss_pub, fallback, tmp_path
):
    lp = _load("legal-person-credential.json")
    lpe = _load("legal-person-credential-embedded.json")  # same authorizer (TA)
    authorizer = batch_authorizer(lp)
    batch = [
        (Path("legal-person-credential.json"), lp, tmp_path),
        (Path("legal-person-credential-embedded.json"), lpe, tmp_path),
    ]
    process_batch(batch, authorizer, keyring, fallback)

    authorizer_pub = did_to_pub[authorizer]
    raws = {}
    for stem, vc in [
        ("legal-person-credential", lp),
        ("legal-person-credential-embedded", lpe),
    ]:
        sd = (tmp_path / f"{stem}.sd-jwt").read_text().strip()
        raw = _raw_issuer_payload(sd)
        raws[stem] = raw
        # Proof executed by the Signing Service via the issuer's mandate key.
        assert _issuer_header(sd)["kid"] == f"{vc['issuer']}#delegate-1"
        verify_sd_jwt_vc(sd, ss_pub)
        # The KB-JWT is addressed to the OID4VP intake verifier (spec §4.3).
        verify_batch_evidence(
            raw,
            raw["evidence"][0],
            authorizer_pub,
            expected_audience=_intake_client_id(keyring, fallback),
        )

    # One signature shared across the whole batch.
    auths = {r["evidence"][0]["authorization"] for r in raws.values()}
    assert len(auths) == 1
    # N=2 batch → each proof has exactly one sibling.
    for raw in raws.values():
        assert len(raw["evidence"][0]["merkleProof"]["path"]) == 1


def test_natural_person_selective_disclosure(keyring, ss_pub, fallback, tmp_path):
    np = _load("natural-person-credential.json")
    authorizer = batch_authorizer(np)
    # ADR-006: the organization issues its own members' credentials.
    assert np["issuer"] == authorizer
    process_batch(
        [(Path("natural-person-credential.json"), np, tmp_path)],
        authorizer,
        keyring,
        fallback,
    )
    sd = (tmp_path / "natural-person-credential.sd-jwt").read_text().strip()
    raw = _raw_issuer_payload(sd)
    # Raw issuer payload hides PII behind _sd digests...
    assert "givenName" not in raw["credentialSubject"]
    assert "_sd" in raw["credentialSubject"]
    # ...but a full verification (all disclosures present) reveals it.
    disclosed = verify_sd_jwt_vc(sd, ss_pub)
    assert disclosed["credentialSubject"]["givenName"] == "Alice"
    # N=1 degenerate batch → empty proof path.
    assert raw["evidence"][0]["merkleProof"]["path"] == []
