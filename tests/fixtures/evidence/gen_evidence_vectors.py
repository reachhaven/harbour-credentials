"""Generate the passkey-evidence test vectors.

Builds a small tenant (one signing key, trust anchor and organisation DID
documents, software passkeys), issues credentials with ``HavenWebAuthnEvidence``
(``docs/specs/passkey-evidence.md``) and writes:

- ``evidence-vectors.json``: evidence chains (single approvals, endorsements,
  revocation instructions), batch approvals (§5) and negative cases, each with
  the Python verifier's result. The TypeScript suite verifies the same vectors
  and must agree.
- ``merkle-vectors.json``: deterministic known answers for the Merkle tree.

Usage:
    uv run --extra dev python tests/fixtures/evidence/gen_evidence_vectors.py

The module also exports :class:`Tenant` and :class:`SoftAuthenticator` for the
unit tests, which build further chains and batches on the fly.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from joserfc import jws

from harbour._crypto import import_private_key
from harbour.evidence import (
    RELYING_PARTY_SERVICE_TYPE,
    build_webauthn_evidence,
    passkey_vm_id,
    payload_digest,
    static_resolver,
    verify_evidence_chain,
    verify_instruction_evidence,
)
from harbour.merkle import b64url_decode, b64url_encode, build_batch
from harbour.sd_jwt import build_sd_jwt_payload, sign_sd_jwt

OUT = Path(__file__).with_name("evidence-vectors.json")
MERKLE_OUT = Path(__file__).with_name("merkle-vectors.json")

NOW = 1_800_000_000
DAY = 86_400
HOST = "did.harbour.example"
RP_ID = "harbour.example"
ORIGIN = "https://harbour.example"
MEMBER_VCT = "haven:MemberCredential"
ORGANISATION_VCT = "haven:OrganisationCredential"
ASCS_USER_VCT = "simpulseid:UserCredential"
INSTRUCTION_CONTEXT = "https://schema.reachhaven.com/instructions/v1"


def _jwk(public_key) -> dict[str, str]:
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        n = public_key.public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64url_encode(n.x.to_bytes(32, "big")),
            "y": b64url_encode(n.y.to_bytes(32, "big")),
        }
    raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode(raw)}


def _thumbprint(jwk: dict[str, str]) -> str:
    """RFC 7638 SHA-256 thumbprint."""
    members = ("crv", "kty", "x", "y") if jwk["kty"] == "EC" else ("crv", "kty", "x")
    canonical = json.dumps({k: jwk[k] for k in members}, separators=(",", ":"))
    return b64url_encode(hashlib.sha256(canonical.encode()).digest())


class SoftAuthenticator:
    """A software WebAuthn authenticator: the same bytes a platform one makes."""

    def __init__(self, alg: str = "ES256"):
        self.alg = alg
        self._key = (
            ec.generate_private_key(ec.SECP256R1())
            if alg == "ES256"
            else Ed25519PrivateKey.generate()
        )
        self.jwk = _jwk(self._key.public_key())
        self.credential_id = b64url_encode(secrets.token_bytes(16))
        self._count = 0

    @property
    def authenticator(self) -> dict[str, Any]:
        return {"credentialId": self.credential_id, "jwk": self.jwk}

    def assert_(
        self,
        challenge: str,
        *,
        origin: str = ORIGIN,
        rp_id: str = RP_ID,
        flags: int = 0x05,
    ) -> dict[str, str]:
        """Assertion over *challenge* (base64url); ES256 signatures are DER."""
        client_data = json.dumps(
            {"type": "webauthn.get", "challenge": challenge, "origin": origin},
            separators=(",", ":"),
        ).encode()
        self._count += 1
        auth_data = (
            hashlib.sha256(rp_id.encode()).digest()
            + bytes([flags])
            + self._count.to_bytes(4, "big")
        )
        data = auth_data + hashlib.sha256(client_data).digest()
        signature = (
            self._key.sign(data, ec.ECDSA(hashes.SHA256()))
            if self.alg == "ES256"
            else self._key.sign(data)
        )
        return {
            "credentialId": self.credential_id,
            "authenticatorData": b64url_encode(auth_data),
            "clientDataJSON": b64url_encode(client_data),
            "signature": b64url_encode(signature),
        }


class Tenant:
    """One tenant: a signing key shared by every DID document it serves."""

    def __init__(self):
        self._signing_key = ec.generate_private_key(ec.SECP256R1())
        self.signing_jwk = _jwk(self._signing_key.public_key())
        self.service = f"did:web:{HOST}"
        self.trust_anchor = f"did:web:{HOST}:participants:trust-anchor"
        self.docs: dict[str, dict] = {}
        ta_doc = self.add_did(self.trust_anchor)
        ta_doc["authentication"] = []
        ta_doc["service"] = [
            {
                "id": f"{self.trust_anchor}#wallet",
                "type": RELYING_PARTY_SERVICE_TYPE,
                "serviceEndpoint": {"rpId": RP_ID, "origins": [ORIGIN]},
            }
        ]
        self.add_did(self.service)

    def kid(self, did: str) -> str:
        return f"{did}#key-{_thumbprint(self.signing_jwk)}"

    def add_did(self, did: str) -> dict:
        if did not in self.docs:
            kid = self.kid(did)
            self.docs[did] = {
                "@context": ["https://www.w3.org/ns/did/v1"],
                "id": did,
                "verificationMethod": [
                    {
                        "id": kid,
                        "type": "JsonWebKey",
                        "controller": did,
                        "publicKeyJwk": self.signing_jwk,
                    }
                ],
                "assertionMethod": [kid],
            }
        return self.docs[did]

    def add_trust_anchor_passkey(self, passkey: SoftAuthenticator) -> None:
        doc = self.docs[self.trust_anchor]
        vm_id = passkey_vm_id(self.trust_anchor, passkey.credential_id)
        doc["verificationMethod"].append(
            {
                "id": vm_id,
                "type": "JsonWebKey",
                "controller": self.trust_anchor,
                "publicKeyJwk": passkey.jwk,
            }
        )
        doc["authentication"].append(vm_id)

    @property
    def resolve_did(self):
        return static_resolver(self.docs)

    def _common(self, iss: str, sub: str, vct: str, iat: int) -> dict[str, Any]:
        return {
            "iss": iss,
            "sub": sub,
            "iat": iat,
            "exp": iat + 700 * DAY,
            "jti": f"urn:uuid:{uuid.uuid4()}",
            "credentialStatus": [
                {
                    "type": "CRSetEntry",
                    "id": "0x" + secrets.token_hex(32),
                    "statusPurpose": "revocation",
                    "statusServiceOperator": self.service,
                }
            ],
            "vct": vct,
        }

    def prepare_member(
        self,
        org: str,
        role: str,
        passkeys: SoftAuthenticator | list[SoftAuthenticator],
        *,
        sub: str | None = None,
        vct: str = MEMBER_VCT,
        member_of: str | list[str] | None = None,
        iat: int = NOW - 10 * DAY,
    ) -> tuple[dict, list[str]]:
        passkeys = passkeys if isinstance(passkeys, list) else [passkeys]
        claims = {
            **self._common(org, sub or f"urn:uuid:{uuid.uuid4()}", vct, iat),
            "cnf": {"jwk": passkeys[0].jwk},
            "memberOf": member_of or org,
            "role": role,
            "authenticators": [p.authenticator for p in passkeys],
            "givenName": "Ada",
            "familyName": "Lovelace",
        }
        return build_sd_jwt_payload(
            claims, vct=claims.pop("vct"), disclosable=["givenName", "familyName"]
        )

    def prepare_organisation(
        self, sub: str, name: str, *, iat: int = NOW - 10 * DAY
    ) -> tuple[dict, list[str]]:
        claims = {
            **self._common(self.trust_anchor, sub, ORGANISATION_VCT, iat),
            "name": name,
        }
        return build_sd_jwt_payload(claims, vct=claims.pop("vct"))

    def sign(self, payload: dict, disclosures: list[str], evidence: list) -> str:
        return sign_sd_jwt(
            {**payload, "evidence": evidence},
            disclosures,
            self._signing_key,
            kid=self.kid(payload["iss"]),
        )

    def sign_raw(self, payload: dict, *, typ: str) -> str:
        """Sign *payload* as is with an arbitrary ``typ`` (negative cases)."""
        header = {"alg": "ES256", "typ": typ, "kid": self.kid(payload["iss"])}
        body = json.dumps(payload, ensure_ascii=False).encode()
        key = import_private_key(self._signing_key, "ES256")
        return jws.serialize_compact(header, body, key, algorithms=["ES256"]) + "~"

    def approve_batch(
        self,
        prepared: list[tuple[dict, list[str]]],
        passkey: SoftAuthenticator,
        approver: dict[str, str],
        approver_credential: str | None = None,
        *,
        kind: str = "approval",
        **assert_kwargs,
    ) -> list[tuple[dict, list[str], dict]]:
        """One assertion over the root of *prepared*; returns the evidence per payload.

        A batch of one is ordinary single-payload evidence (no ``merklePath``).
        """
        batch = build_batch([p for p, _ in prepared])
        assertion = passkey.assert_(batch["challenge"], **assert_kwargs)
        return [
            (
                payload,
                disclosures,
                build_webauthn_evidence(
                    assertion,
                    approver=approver,
                    kind=kind,
                    approver_credential=approver_credential,
                    merkle_path=path,
                ),
            )
            for (payload, disclosures), path in zip(prepared, batch["paths"])
        ]

    def issue(
        self,
        prepared: tuple[dict, list[str]],
        passkey: SoftAuthenticator,
        approver: dict[str, str],
        approver_credential: str | None = None,
        **kwargs,
    ) -> tuple[dict, str]:
        """Approve one payload and sign it. Returns ``(signed payload, sd_jwt)``."""
        [(payload, disclosures, evidence)] = self.approve_batch(
            [prepared], passkey, approver, approver_credential, **kwargs
        )
        return {**payload, "evidence": [evidence]}, self.sign(
            payload, disclosures, [evidence]
        )


class Person:
    """A member with a passkey and the issued credential that lists it."""

    def __init__(self, payload: dict, sd_jwt: str, passkey: SoftAuthenticator):
        self.payload, self.sd_jwt, self.passkey = payload, sd_jwt, passkey

    @property
    def credential(self) -> str:
        """The issuer JWT with a trailing ``~``, as ``approverCredential``."""
        return self.sd_jwt.split("~")[0] + "~"

    def approver(self) -> dict[str, str]:
        member_of = self.payload["memberOf"]
        org = member_of if isinstance(member_of, str) else member_of[0]
        return {
            "sub": self.payload["sub"],
            "memberOf": org,
            "role": self.payload["role"],
        }


def generate() -> dict[str, Any]:
    tenant = Tenant()
    ta = tenant.trust_anchor
    acme = f"did:web:{HOST}:participants:acme"
    other = f"did:web:{HOST}:participants:other"
    for did in (
        acme,
        other,
        *(f"did:web:{HOST}:participants:org-{i}" for i in range(5)),
    ):
        tenant.add_did(did)

    ta_admin = SoftAuthenticator()
    tenant.add_trust_anchor_passkey(ta_admin)
    by_ta = {"sub": f"urn:uuid:{uuid.uuid4()}", "memberOf": ta, "role": "admin"}

    def person(org: str, role: str, approve: tuple, *, alg="ES256", **kwargs) -> Person:
        passkey = SoftAuthenticator(alg)
        key, approver, *rest = approve
        payload, sd_jwt = tenant.issue(
            tenant.prepare_member(org, role, passkey, **kwargs), key, approver, *rest
        )
        return Person(payload, sd_jwt, passkey)

    def by(p: Person) -> tuple:
        return (p.passkey, p.approver(), p.credential)

    acme_admin = person(acme, "admin", (ta_admin, by_ta))
    ed_admin = person(acme, "admin", (ta_admin, by_ta), alg="EdDSA")
    other_admin = person(other, "admin", (ta_admin, by_ta))
    member = person(acme, "member", by(acme_admin))

    cases: list[dict[str, Any]] = []

    def credential_case(name: str, description: str, sd_jwt: str) -> None:
        result = verify_evidence_chain(
            sd_jwt, resolve_did=tenant.resolve_did, trust_anchor_did=ta, now=NOW
        )
        cases.append(
            {
                "name": name,
                "description": description,
                "credential": sd_jwt,
                "expected": result.to_dict(),
            }
        )

    def instruction_case(
        name: str, description: str, instruction: dict, evidence: dict
    ) -> None:
        result = verify_instruction_evidence(
            instruction,
            evidence,
            resolve_did=tenant.resolve_did,
            trust_anchor_did=ta,
            now=NOW,
        )
        cases.append(
            {
                "name": name,
                "description": description,
                "instruction": instruction,
                "evidence": evidence,
                "expected": result.to_dict(),
            }
        )

    # --- single approvals -------------------------------------------------

    own_payload, own_disclosures = tenant.prepare_organisation(ta, "Trust Anchor")
    credential_case(
        "trust-anchor-own-credential",
        "The trust anchor's own organisation credential, evidence: [] (the root).",
        tenant.sign(own_payload, own_disclosures, []),
    )
    _, acme_org = tenant.issue(
        tenant.prepare_organisation(acme, "Acme GmbH"), ta_admin, by_ta
    )
    credential_case(
        "organisation-credential",
        "Organisation credential approved by a trust anchor admin passkey (step 5.1).",
        acme_org,
    )
    credential_case(
        "organisation-admin",
        "Member credential of an organisation admin, approved by a trust anchor admin.",
        acme_admin.sd_jwt,
    )
    credential_case(
        "member-by-org-admin",
        "Member credential approved by the organisation admin, chained through the admin's credential (step 5.2).",
        member.sd_jwt,
    )
    credential_case(
        "member-by-eddsa-admin",
        "Approved by an organisation admin whose passkey is Ed25519 (raw signature).",
        person(acme, "member", by(ed_admin)).sd_jwt,
    )
    credential_case(
        "memberof-array",
        "Member credential whose memberOf is an array with the organisation first.",
        person(
            acme,
            "member",
            by(acme_admin),
            vct=ASCS_USER_VCT,
            member_of=[acme, f"did:web:{HOST}:programs:example-programme"],
        ).sd_jwt,
    )
    _, endorsed = tenant.issue(
        tenant.prepare_member(
            acme,
            "member",
            [member.passkey, SoftAuthenticator()],
            sub=member.payload["sub"],
        ),
        *by(member),
        kind="endorsement",
    )
    credential_case(
        "endorsement",
        "Reissue that only adds a passkey, endorsed by the person's existing passkey.",
        endorsed,
    )

    # --- negative single approvals ------------------------------------------

    tampered = {**member.payload, "role": "admin"}
    credential_case(
        "tampered-payload",
        "Validly signed, but a claim changed after the approver signed the digest.",
        tenant.sign(
            {k: v for k, v in tampered.items() if k != "evidence"},
            [],
            member.payload["evidence"],
        ),
    )
    credential_case(
        "approver-not-admin",
        "Approved by a plain member.",
        person(acme, "member", by(member)).sd_jwt,
    )
    credential_case(
        "approver-wrong-organisation",
        "Approved by the admin of another organisation.",
        person(acme, "member", by(other_admin)).sd_jwt,
    )
    _, wrong_origin = tenant.issue(
        tenant.prepare_member(acme, "member", SoftAuthenticator()),
        *by(acme_admin),
        origin="https://evil.example",
    )
    credential_case(
        "origin-not-allowed",
        "Assertion made on an origin the trust anchor does not list.",
        wrong_origin,
    )
    _, no_uv = tenant.issue(
        tenant.prepare_member(acme, "member", SoftAuthenticator()),
        *by(acme_admin),
        flags=0x01,
    )
    credential_case(
        "user-not-verified",
        "Authenticator data without the user-verification flag.",
        no_uv,
    )
    credential_case(
        "legacy-typ",
        "Issuer JWT with typ vc+sd-jwt: evidence chains require dc+sd-jwt.",
        tenant.sign_raw(member.payload, typ="vc+sd-jwt"),
    )
    _, stranger = tenant.issue(
        tenant.prepare_organisation(acme, "Acme GmbH"), SoftAuthenticator(), by_ta
    )
    credential_case(
        "unknown-trust-anchor-passkey",
        "Signed by a passkey the trust anchor document does not list.",
        stranger,
    )

    # --- instructions ---------------------------------------------------------

    instruction = {
        "@context": INSTRUCTION_CONTEXT,
        "type": "haven:RevokeCredential",
        "tenant": "acme-tenant",
        "credential": member.payload["jti"],
        "entry": member.payload["credentialStatus"][0]["id"],
        "actor": acme_admin.payload["sub"],
        "issuedAt": NOW - DAY,
        "nonce": "n-0001",
    }
    [(_, _, revoke_evidence)] = tenant.approve_batch(
        [(instruction, [])], *by(acme_admin)
    )
    instruction_case(
        "revoke-instruction",
        "haven:RevokeCredential approved by the organisation admin.",
        instruction,
        revoke_evidence,
    )
    wrong_actor = {**instruction, "actor": member.payload["sub"]}
    [(_, _, wrong_actor_evidence)] = tenant.approve_batch(
        [(wrong_actor, [])], *by(acme_admin)
    )
    instruction_case(
        "revoke-instruction-wrong-actor",
        "Instruction whose actor is not the approver.",
        wrong_actor,
        wrong_actor_evidence,
    )

    # --- batches --------------------------------------------------------------

    # Three members, one tap by the organisation admin. Leaf 2 is promoted.
    members = [
        tenant.prepare_member(acme, "member", SoftAuthenticator()) for _ in range(3)
    ]
    approved = tenant.approve_batch(members, *by(acme_admin))
    for i, (p, d, e) in enumerate(approved):
        credential_case(
            f"batch-3-member-{i}",
            f"Member {i} of a batch of three approved with one organisation admin tap.",
            tenant.sign(p, d, [e]),
        )

    orgs = [
        tenant.prepare_organisation(f"did:web:{HOST}:participants:org-{i}", f"Org {i}")
        for i in range(5)
    ]
    for i, (p, d, e) in enumerate(tenant.approve_batch(orgs, ta_admin, by_ta)):
        credential_case(
            f"batch-5-organisation-{i}",
            f"Organisation credential {i} of a batch of five approved by a trust anchor admin.",
            tenant.sign(p, d, [e]),
        )

    # A mixed batch: a new member and a revocation of batch member 0, one tap.
    member0 = approved[0][0]
    batch_instruction = {
        **instruction,
        "credential": member0["jti"],
        "entry": member0["credentialStatus"][0]["id"],
        "issuedAt": NOW - 10 * DAY,
        "nonce": "n-batch-0001",
    }
    newcomer = tenant.prepare_member(acme, "member", SoftAuthenticator())
    mixed = tenant.approve_batch([newcomer, (batch_instruction, [])], *by(acme_admin))
    credential_case(
        "mixed-batch-credential",
        "A member credential approved in the same tap as a revocation instruction.",
        tenant.sign(mixed[0][0], mixed[0][1], [mixed[0][2]]),
    )
    instruction_case(
        "mixed-batch-instruction",
        "The revocation instruction of the mixed batch.",
        batch_instruction,
        mixed[1][2],
    )

    # --- negative batches -----------------------------------------------------

    payload1, disclosures1, evidence1 = approved[1]

    def batch_negative(name: str, description: str, evidence: dict) -> None:
        credential_case(
            name, description, tenant.sign(payload1, disclosures1, [evidence])
        )

    flipped = json.loads(json.dumps(evidence1))
    flipped["merklePath"][0]["position"] = (
        "right" if flipped["merklePath"][0]["position"] == "left" else "left"
    )
    batch_negative(
        "path-position-flipped",
        "The first path element's position is flipped.",
        flipped,
    )
    batch_negative(
        "path-of-another-member",
        "Member 1 carries member 0's path.",
        {**evidence1, "merklePath": approved[0][2]["merklePath"]},
    )
    batch_negative(
        "path-missing",
        "Batch evidence without its path, as a verifier without batch support reads it.",
        {k: v for k, v in evidence1.items() if k != "merklePath"},
    )
    short = json.loads(json.dumps(evidence1))
    short["merklePath"][0]["hash"] = b64url_encode(
        b64url_decode(short["merklePath"][0]["hash"])[:31]
    )
    batch_negative("path-hash-not-32-bytes", "A path hash of 31 bytes.", short)
    batch_negative(
        "path-too-long",
        "A path of 34 elements.",
        {**evidence1, "merklePath": evidence1["merklePath"] * 17},
    )
    bad_position = json.loads(json.dumps(evidence1))
    bad_position["merklePath"][0]["position"] = "up"
    batch_negative(
        "path-bad-position", "A path element with position 'up'.", bad_position
    )

    digests = [
        {"input": p, "digest": payload_digest(p)}
        for p in (
            {k: v for k, v in member.payload.items() if k != "evidence"},
            instruction,
        )
    ]

    return {
        "description": (
            "Passkey evidence vectors (docs/specs/passkey-evidence.md): chains, "
            "instructions and batch approvals. `expected` is the Python verifier's "
            "result; the TypeScript verifier must agree."
        ),
        "generator": "tests/fixtures/evidence/gen_evidence_vectors.py",
        "now": NOW,
        "trustAnchorDid": ta,
        "didDocuments": tenant.docs,
        "digests": digests,
        "cases": cases,
    }


def merkle_vectors() -> dict[str, Any]:
    """Deterministic known answers for the tree itself, batch sizes 1 to 9."""
    vectors = []
    for n in range(1, 10):
        payloads = [
            {"iss": "did:web:example.com", "n": i, "name": f"Payload {i}"}
            for i in range(n)
        ]
        batch = build_batch(payloads)
        vectors.append(
            {
                "name": f"batch-of-{n}",
                "payloads": payloads,
                "challenge": batch["challenge"],
                "paths": batch["paths"],
            }
        )
    return {
        "description": "Merkle batch known answers (docs/specs/passkey-evidence.md §5).",
        "generator": "tests/fixtures/evidence/gen_evidence_vectors.py",
        "vectors": vectors,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate passkey-evidence and Merkle test vectors.",
    )
    parser.add_argument("--output", type=Path, default=OUT, help=f"default: {OUT}")
    parser.add_argument(
        "--merkle-output", type=Path, default=MERKLE_OUT, help=f"default: {MERKLE_OUT}"
    )
    args = parser.parse_args()
    vectors = generate()
    args.output.write_text(json.dumps(vectors, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(vectors['cases'])} cases to {args.output}")
    args.merkle_output.write_text(
        json.dumps(merkle_vectors(), indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote Merkle vectors to {args.merkle_output}")


if __name__ == "__main__":
    main()
