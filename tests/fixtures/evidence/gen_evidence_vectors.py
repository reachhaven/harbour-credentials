"""Generate the passkey-evidence test vectors.

Builds a small tenant (trust anchor and organisation DID documents, software
passkeys, the trust anchor key log), issues credentials with
``HavenWebAuthnEvidence`` (``docs/specs/passkey-evidence.md``) and writes:

- ``evidence-vectors.json``: evidence chains (single approvals, endorsements,
  revocation instructions), batch approvals (§5), key log replay (§4.5) and
  negative cases, each with the Python verifier's result. The TypeScript suite
  verifies the same vectors and must agree.

The trust anchor DID signs with ``tests/fixtures/keys/trust-anchor.p256.json``
(so the TypeScript suite can append key log entries of its own); every other
DID shares one random tenant key.
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
import warnings
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from joserfc import jwk as jose_jwk
from joserfc import jws

from harbour._crypto import import_private_key
from harbour.evidence import (
    KEY_LOG_SERVICE_TYPE,
    RELYING_PARTY_SERVICE_TYPE,
    build_webauthn_evidence,
    key_log_entry_hash,
    passkey_vm_id,
    payload_digest,
    static_key_logs,
    static_resolver,
    verify_evidence_chain,
    verify_instruction_evidence,
)
from harbour.merkle import b64url_decode, b64url_encode, build_batch
from harbour.sd_jwt import build_sd_jwt_payload, sign_sd_jwt

OUT = Path(__file__).with_name("evidence-vectors.json")
MERKLE_OUT = Path(__file__).with_name("merkle-vectors.json")
TRUST_ANCHOR_KEY = (
    Path(__file__).resolve().parents[1] / "keys" / "trust-anchor.p256.json"
)

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
        client_data_extra: dict[str, Any] | None = None,
    ) -> dict[str, str]:
        """Assertion over *challenge* (base64url); ES256 signatures are DER.

        *client_data_extra* adds to or overrides clientDataJSON members
        (negative cases such as ``crossOrigin`` or a wrong ``type``).
        """
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": origin,
                **(client_data_extra or {}),
            },
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


def _trust_anchor_key() -> ec.EllipticCurvePrivateKey:
    jwk = json.loads(TRUST_ANCHOR_KEY.read_text(encoding="utf-8"))
    key = ec.derive_private_key(
        int.from_bytes(b64url_decode(jwk["d"]), "big"), ec.SECP256R1()
    )
    assert _jwk(key.public_key()) == {k: jwk[k] for k in ("kty", "crv", "x", "y")}
    return key


class Tenant:
    """One tenant: the trust anchor signs with the trust-anchor fixture key,
    every other DID document it serves shares one random signing key."""

    def __init__(self):
        self._signing_key = ec.generate_private_key(ec.SECP256R1())
        self._trust_anchor_key = _trust_anchor_key()
        self.signing_jwk = _jwk(self._signing_key.public_key())
        self.service = f"did:web:{HOST}"
        self.trust_anchor = f"did:web:{HOST}:participants:trust-anchor"
        self.docs: dict[str, dict] = {}
        self.key_logs: dict[str, list[dict]] = {self.trust_anchor: []}
        ta_doc = self.add_did(self.trust_anchor)
        ta_doc["authentication"] = []
        ta_doc["service"] = [
            {
                "id": f"{self.trust_anchor}#wallet",
                "type": RELYING_PARTY_SERVICE_TYPE,
                "serviceEndpoint": {"rpId": RP_ID, "origins": [ORIGIN]},
            },
            {
                "id": f"{self.trust_anchor}#key-log",
                "type": KEY_LOG_SERVICE_TYPE,
                "serviceEndpoint": f"https://{HOST}/participants/trust-anchor/key-log",
            },
        ]
        self.add_did(self.service)

    def _key(self, did: str) -> ec.EllipticCurvePrivateKey:
        return self._trust_anchor_key if did == self.trust_anchor else self._signing_key

    def kid(self, did: str) -> str:
        return f"{did}#key-{_thumbprint(_jwk(self._key(did).public_key()))}"

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
                        "publicKeyJwk": _jwk(self._key(did).public_key()),
                    }
                ],
                "assertionMethod": [kid],
            }
        return self.docs[did]

    def append_key_log(self, material: dict, at: int) -> dict:
        """Append one entry to the trust anchor key log (spec §4.5)."""
        log = self.key_logs[self.trust_anchor]
        assert not log or log[-1]["at"] <= at, (
            "key log entries must not go back in time"
        )
        unhashed = {
            "seq": len(log) + 1,
            "kind": material["kind"],
            "at": at,
            "prev": log[-1]["hash"] if log else None,
            "material": material,
        }
        entry = {**unhashed, "hash": key_log_entry_hash(unhashed)}
        log.append(entry)
        return entry

    def seat_trust_anchor_admin(
        self,
        passkeys: SoftAuthenticator | list[SoftAuthenticator],
        *,
        iat: int,
        at: int,
        by: tuple | None = None,
        sub: str | None = None,
        role: str = "admin",
    ) -> Person:
        """Issue a trust anchor member credential and log it at *at*.

        *by* is ``(passkey, approver)`` of an active trust anchor admin; without
        it the subject approves their own credential (the bootstrap rule).
        """
        passkeys = passkeys if isinstance(passkeys, list) else [passkeys]
        sub = sub or f"urn:uuid:{uuid.uuid4()}"
        prepared = self.prepare_member(
            self.trust_anchor, role, passkeys, sub=sub, iat=iat
        )
        key, approver = by or (
            passkeys[0],
            {"sub": sub, "memberOf": self.trust_anchor, "role": "admin"},
        )
        payload, sd_jwt = self.issue(prepared, key, approver)
        member = Person(payload, sd_jwt, passkeys[0])
        self.append_key_log({"kind": "credential", "jwt": member.credential}, at)
        if role == "admin":
            for passkey in passkeys:
                self.add_trust_anchor_passkey(passkey)
        return member

    @property
    def resolve_key_log(self):
        return static_key_logs(self.key_logs)

    def add_trust_anchor_passkey(self, passkey: SoftAuthenticator) -> None:
        """List *passkey* under ``authentication`` (informational only)."""
        doc = self.docs[self.trust_anchor]
        if any(
            vm["id"] == passkey_vm_id(self.trust_anchor, passkey.credential_id)
            for vm in doc["verificationMethod"]
        ):
            return
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

    def remove_trust_anchor_passkey(self, passkey: SoftAuthenticator) -> None:
        doc = self.docs[self.trust_anchor]
        vm_id = passkey_vm_id(self.trust_anchor, passkey.credential_id)
        doc["verificationMethod"] = [
            vm for vm in doc["verificationMethod"] if vm["id"] != vm_id
        ]
        doc["authentication"] = [a for a in doc["authentication"] if a != vm_id]

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
        self,
        sub: str,
        name: str,
        *,
        iat: int = NOW - 10 * DAY,
        iss: str | None = None,
    ) -> tuple[dict, list[str]]:
        claims = {
            **self._common(iss or self.trust_anchor, sub, ORGANISATION_VCT, iat),
            "name": name,
        }
        return build_sd_jwt_payload(claims, vct=claims.pop("vct"))

    def sign(self, payload: dict, disclosures: list[str], evidence: list) -> str:
        return sign_sd_jwt(
            {**payload, "evidence": evidence},
            disclosures,
            self._key(payload["iss"]),
            kid=self.kid(payload["iss"]),
        )

    def sign_raw(
        self,
        payload: dict,
        *,
        typ: str,
        kid: str | None = None,
        alg: str = "ES256",
    ) -> str:
        """Sign *payload* as is with an arbitrary header (negative cases).

        Any *alg* other than ES256 yields a forged token with a bogus
        signature: the verifier must reject the header before verifying.
        """
        header = {"alg": alg, "typ": typ, "kid": kid or self.kid(payload["iss"])}
        body = json.dumps(payload, ensure_ascii=False).encode()
        if alg != "ES256":
            return (
                b64url_encode(json.dumps(header).encode())
                + "."
                + b64url_encode(body)
                + "."
                + b64url_encode(b"\x00" * 64)
                + "~"
            )
        key = import_private_key(self._key(payload["iss"]), "ES256")
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
    keyed = f"did:web:{HOST}:participants:keyed"
    for did in (
        acme,
        other,
        keyed,
        *(f"did:web:{HOST}:participants:org-{i}" for i in range(5)),
    ):
        tenant.add_did(did)

    # --- the trust anchor key log (§4.5), appended in time order -------------
    #
    # genesis   NOW-30d  ta_admin approves their own admin credential (bootstrap)
    # demoted   NOW-25d  seated by ta_admin, demoted to member at NOW-6d
    # revoked   NOW-24d  seated by ta_admin, credential revoked at NOW-7d
    # dual      NOW-20d  seated by ta_admin, also an admin of acme
    # two_keys  NOW-15d  seated by ta_admin with two passkeys, one revoked at NOW-5d
    # late      NOW-3d   seated by ta_admin
    #
    # Each credential entry is logged a minute after its iat, as the issuer
    # signs after the approval.

    def seat(passkeys, days_ago: int, **kwargs) -> Person:
        iat = NOW - days_ago * DAY
        return tenant.seat_trust_anchor_admin(passkeys, iat=iat, at=iat + 60, **kwargs)

    ta_admin = SoftAuthenticator()
    genesis = seat(ta_admin, 30)
    by_ta = genesis.approver()
    by_genesis = (ta_admin, by_ta)
    demoted_key, revoked_key, dual_passkey = (SoftAuthenticator() for _ in range(3))
    kept_key, dropped_key, late_key = (SoftAuthenticator() for _ in range(3))
    demoted = seat(demoted_key, 25, by=by_genesis)
    revoked = seat(revoked_key, 24, by=by_genesis)
    dual_sub = f"urn:uuid:{uuid.uuid4()}"
    seat(dual_passkey, 20, by=by_genesis, sub=dual_sub)
    two_keys = seat([kept_key, dropped_key], 15, by=by_genesis)
    revocation = {
        "@context": INSTRUCTION_CONTEXT,
        "type": "haven:RevokeCredential",
        "tenant": "acme-tenant",
        "credential": revoked.payload["jti"],
        "entry": revoked.payload["credentialStatus"][0]["id"],
        "actor": by_ta["sub"],
        "issuedAt": NOW - 7 * DAY,
        "nonce": "n-key-log-0001",
    }
    [(_, _, revocation_evidence)] = tenant.approve_batch(
        [(revocation, [])], *by_genesis
    )
    tenant.append_key_log(
        {
            "kind": "revocation",
            "instruction": revocation,
            "evidence": revocation_evidence,
        },
        NOW - 7 * DAY,
    )
    tenant.remove_trust_anchor_passkey(revoked_key)
    seat(demoted_key, 6, by=by_genesis, sub=demoted.payload["sub"], role="member")
    tenant.remove_trust_anchor_passkey(demoted_key)
    tenant.append_key_log(
        {
            "kind": "passkey_revoked",
            "sub": two_keys.payload["sub"],
            "credentialId": dropped_key.credential_id,
        },
        NOW - 5 * DAY,
    )
    tenant.remove_trust_anchor_passkey(dropped_key)
    late = seat(late_key, 3, by=by_genesis)
    key_log = tenant.key_logs[ta]
    key_log_length = len(key_log)

    def person(
        org: str,
        role: str,
        approve: tuple,
        *,
        alg="ES256",
        passkey: SoftAuthenticator | None = None,
        **kwargs,
    ) -> Person:
        passkey = passkey or SoftAuthenticator(alg)
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

    def credential_case(
        name: str,
        description: str,
        sd_jwt: str,
        *,
        did_documents: dict[str, dict] | None = None,
        key_logs: dict[str, list] | None = None,
        max_depth: int | None = None,
    ) -> None:
        """*did_documents*, *key_logs* and *max_depth* replace the shared DID
        documents, the top-level ``keyLogs`` and the default depth limit for
        this case only."""
        docs = tenant.docs if did_documents is None else did_documents
        result = verify_evidence_chain(
            sd_jwt,
            resolve_did=static_resolver(docs),
            resolve_key_log=(
                tenant.resolve_key_log
                if key_logs is None
                else static_key_logs(key_logs)
            ),
            trust_anchor_did=ta,
            now=NOW,
            **({} if max_depth is None else {"max_depth": max_depth}),
        )
        case: dict[str, Any] = {
            "name": name,
            "description": description,
            "credential": sd_jwt,
            "expected": result.to_dict(),
        }
        if did_documents is not None:
            case["didDocuments"] = did_documents
        if key_logs is not None:
            case["keyLogs"] = key_logs
        if max_depth is not None:
            case["maxDepth"] = max_depth
        cases.append(case)

    def instruction_case(
        name: str, description: str, instruction: dict, evidence: dict
    ) -> None:
        result = verify_instruction_evidence(
            instruction,
            evidence,
            resolve_did=tenant.resolve_did,
            resolve_key_log=tenant.resolve_key_log,
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
    assert cases[-1]["expected"] == {
        "ok": True,
        "approvers": [{"sub": by_ta["sub"], "memberOf": ta, "via": "trust-anchor"}],
    }
    credential_case(
        "organisation-admin",
        "Admin credential of another organisation, approved by a trust anchor admin (seating its admin).",
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
    updated = {k: v for k, v in member.payload.items() if k != "evidence"}
    updated.update(
        authenticators=[
            member.passkey.authenticator,
            SoftAuthenticator().authenticator,
        ],
        iat=NOW - DAY,
        jti=f"urn:uuid:{uuid.uuid4()}",
    )
    _, endorsed = tenant.issue((updated, []), *by(member), kind="endorsement")
    credential_case(
        "endorsement",
        "Reissue preserving all claims except authenticators, iat, jti and evidence.",
        endorsed,
    )
    assert cases[-1]["expected"]["ok"]

    changes = {
        "vct": {**updated, "vct": ASCS_USER_VCT},
        "expiry": {**updated, "exp": updated["exp"] + DAY},
        "membership": {**updated, "memberOf": [acme, other]},
        "cnf": {**updated, "cnf": {"jwk": SoftAuthenticator().jwk}},
        "status": {**updated, "credentialStatus": []},
        "disclosures": {**updated, "_sd": []},
        "added-claim": {**updated, "privilege": "admin"},
        "proof": {**updated, "proof": {"type": "DataIntegrityProof"}},
        "removed-claim": {k: v for k, v in updated.items() if k != "credentialStatus"},
    }
    for name, payload in changes.items():
        _, token = tenant.issue((payload, []), *by(member), kind="endorsement")
        credential_case(
            f"endorsement-changed-{name}",
            "A self-endorsement cannot change protected claims.",
            token,
        )
        assert cases[-1]["expected"] == {
            "ok": False,
            "reason": "endorsement-payload-mismatch",
            "depth": 0,
        }

    # Sign directly so the signer does not reject deliberately invalid headers.
    for name, extension, accepted in [
        ("unknown-critical", {"crit": ["custom"], "custom": True}, False),
        ("empty-critical", {"crit": []}, False),
        ("malformed-critical", {"crit": "custom", "custom": True}, False),
        ("missing-critical", {"crit": ["custom"]}, False),
        ("noncritical", {"custom": True}, True),
    ]:
        header = {
            "alg": "ES256",
            "typ": "dc+sd-jwt",
            "kid": tenant.kid(acme),
            **extension,
        }
        signing_input = (
            b64url_encode(json.dumps(header).encode())
            + "."
            + b64url_encode(json.dumps(member.payload).encode())
        ).encode()
        signature = tenant._signing_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, sig_s = decode_dss_signature(signature)
        token = (
            signing_input.decode()
            + "."
            + b64url_encode(r.to_bytes(32, "big") + sig_s.to_bytes(32, "big"))
            + "~"
        )
        credential_case(
            f"jws-{name}",
            "Critical extensions must be understood; non-critical extensions may be ignored.",
            token,
        )
        assert cases[-1]["expected"]["ok"] is accepted, (name, cases[-1]["expected"])
        if not accepted:
            assert cases[-1]["expected"]["reason"] == "bad-issuer-signature"

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
    credential_case(
        "trust-anchor-approves-member-role",
        "A trust anchor admin approves a member-role credential of another organisation (step 7).",
        person(acme, "member", (ta_admin, by_ta)).sd_jwt,
    )
    assert cases[-1]["expected"]["reason"] == "approver-wrong-organisation"
    assert cases[-1]["expected"]["depth"] == 0

    # A trust anchor admin (seated in the key log) who is also an admin of acme,
    # with one passkey.
    dual = person(acme, "admin", by_genesis, passkey=dual_passkey, sub=dual_sub)
    by_dual_ta = {"sub": dual.payload["sub"], "memberOf": ta, "role": "admin"}
    credential_case(
        "dual-role-organisation-form",
        "A trust-anchor-listed passkey with approverCredential acts for that organisation (step 5.2).",
        person(acme, "member", by(dual)).sd_jwt,
    )
    assert cases[-1]["expected"]["ok"], cases[-1]["expected"]
    assert [a["via"] for a in cases[-1]["expected"]["approvers"]] == [
        "credential",
        "trust-anchor",
    ]
    credential_case(
        "dual-role-trust-anchor-form-member",
        "The same passkey without approverCredential is a trust anchor admin and cannot approve a member role.",
        person(acme, "member", (dual_passkey, by_dual_ta)).sd_jwt,
    )
    assert cases[-1]["expected"]["reason"] == "approver-wrong-organisation"
    credential_case(
        "dual-role-trust-anchor-form-organisation",
        "The same passkey without approverCredential approves an organisation credential (step 5.1).",
        tenant.issue(
            tenant.prepare_organisation(other, "Other GmbH"), dual_passkey, by_dual_ta
        )[1],
    )
    assert cases[-1]["expected"]["ok"], cases[-1]["expected"]
    credential_case(
        "dual-role-organisation-without-credential",
        "Claims to act for acme with a trust-anchor-listed passkey but no approverCredential.",
        person(acme, "member", (dual_passkey, dual.approver())).sd_jwt,
    )
    assert cases[-1]["expected"]["reason"] == "approver-mismatch"
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
        "Signed by a passkey that is in neither the key log nor the trust anchor document.",
        stranger,
    )
    assert cases[-1]["expected"]["reason"] == "approver-key-not-found"

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

    # --- one vector per remaining failure reason (§4.4) ------------------------

    def tampered(evidence: dict, **changes: Any) -> dict:
        return {**json.loads(json.dumps(evidence)), **changes}

    def flip_last_byte(b64: str) -> str:
        raw = bytearray(b64url_decode(b64))
        raw[-1] ^= 0x01
        return b64url_encode(bytes(raw))

    def with_evidence(prepared: tuple[dict, list[str]], evidence: dict) -> str:
        payload, disclosures = prepared
        return tenant.sign(payload, disclosures, [evidence])

    def approved(prepared: tuple[dict, list[str]], approve: tuple, **kw) -> dict:
        """The evidence object for *prepared*, approved by *approve*."""
        key, approver, *rest = approve
        [(_, _, evidence)] = tenant.approve_batch(
            [prepared], key, approver, *rest, **kw
        )
        return evidence

    def expect(reason: str, depth: int = 0) -> None:
        got = cases[-1]["expected"]
        assert (got.get("reason"), got.get("depth")) == (reason, depth), (
            cases[-1]["name"],
            got,
        )

    def expect_ok() -> None:
        assert cases[-1]["expected"]["ok"], (cases[-1]["name"], cases[-1]["expected"])

    def fresh() -> tuple[dict, list[str]]:
        return tenant.prepare_member(acme, "member", SoftAuthenticator())

    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "webauthn-signature-tampered",
        "ES256 assertion signature with one flipped bit.",
        with_evidence(p, tampered(e, signature=flip_last_byte(e["signature"]))),
    )
    expect("bad-webauthn-signature")
    p = fresh()
    e = approved(p, by(ed_admin))
    credential_case(
        "webauthn-signature-tampered-eddsa",
        "Ed25519 assertion signature with one flipped bit.",
        with_evidence(p, tampered(e, signature=flip_last_byte(e["signature"]))),
    )
    expect("bad-webauthn-signature")
    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "webauthn-signature-other-passkey",
        "credentialId names the admin's passkey, but another passkey signed.",
        with_evidence(
            p, tampered(e, signature=approved(p, by(other_admin))["signature"])
        ),
    )
    expect("bad-webauthn-signature")
    credential_case(
        "rp-id-hash-mismatch",
        "authenticatorData for a different RP ID.",
        tenant.issue(fresh(), *by(acme_admin), rp_id="evil.example")[1],
    )
    expect("rp-id-hash-mismatch")
    credential_case(
        "cross-origin",
        "clientDataJSON with crossOrigin: true.",
        tenant.issue(fresh(), *by(acme_admin), client_data_extra={"crossOrigin": True})[
            1
        ],
    )
    expect("cross-origin")
    credential_case(
        "user-not-present",
        "Flags byte without user presence.",
        tenant.issue(fresh(), *by(acme_admin), flags=0x04)[1],
    )
    expect("user-not-present")
    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "authenticator-data-short",
        "authenticatorData of 10 bytes.",
        with_evidence(p, tampered(e, authenticatorData=b64url_encode(b"\x00" * 10))),
    )
    expect("authenticator-data-invalid")
    credential_case(
        "client-data-wrong-type",
        "clientDataJSON type webauthn.create.",
        tenant.issue(
            fresh(), *by(acme_admin), client_data_extra={"type": "webauthn.create"}
        )[1],
    )
    expect("client-data-invalid")
    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "client-data-not-an-object",
        "clientDataJSON decodes to a JSON array.",
        with_evidence(p, tampered(e, clientDataJSON=b64url_encode(b"[]"))),
    )
    expect("client-data-invalid")
    p = fresh()
    credential_case(
        "client-data-challenge-padded",
        "The challenge carries base64 padding; the comparison is exact.",
        with_evidence(
            p,
            approved(
                p,
                by(acme_admin),
                client_data_extra={"challenge": payload_digest(p[0]) + "="},
            ),
        ),
    )
    expect("digest-mismatch")
    credential_case(
        "approver-credential-out-of-window",
        "P.iat lies before the approver credential's iat.",
        person(acme, "member", by(acme_admin), iat=NOW - 100 * DAY).sd_jwt,
    )
    expect("approver-credential-out-of-window")
    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "approver-key-not-found",
        "credentialId not among the approver credential's authenticators.",
        with_evidence(
            p, tampered(e, credentialId=b64url_encode(secrets.token_bytes(16)))
        ),
    )
    expect("approver-key-not-found")
    credential_case(
        "issuer-not-organisation",
        "Member credential issued by one organisation with memberOf another.",
        person(other, "member", by(acme_admin), member_of=acme).sd_jwt,
    )
    expect("issuer-not-organisation")
    credential_case(
        "issuer-not-trust-anchor",
        "Organisation credential issued by an organisation, not the trust anchor.",
        tenant.issue(
            tenant.prepare_organisation(other, "Other GmbH", iss=acme), ta_admin, by_ta
        )[1],
    )
    expect("issuer-not-trust-anchor")
    credential_case(
        "endorsement-by-admin",
        "kind endorsement, but the approver is the organisation admin, not the subject.",
        tenant.issue(fresh(), *by(acme_admin), kind="endorsement")[1],
    )
    expect("endorsement-subject-mismatch")
    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "evidence-count-two", "Two evidence objects.", tenant.sign(p[0], p[1], [e, e])
    )
    expect("evidence-count")
    credential_case(
        "evidence-count-zero",
        "A member credential with evidence: [].",
        tenant.sign(*fresh(), []),
    )
    expect("evidence-count")
    credential_case(
        "unknown-vct",
        "A vct outside the member and organisation lists.",
        person(acme, "member", by(acme_admin), vct="haven:UnknownCredential").sd_jwt,
    )
    expect("unknown-vct")
    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "approver-credential-not-member",
        "approverCredential is an organisation credential.",
        with_evidence(p, tampered(e, approverCredential=acme_org.split("~")[0] + "~")),
    )
    expect("approver-credential-not-member", 1)
    credential_case(
        "depth-exceeded",
        "A chain of two approver credentials verified with maxDepth 1.",
        person(acme, "member", by(person(acme, "admin", by(acme_admin)))).sd_jwt,
        max_depth=1,
    )
    expect("depth-exceeded", 2)
    credential_case(
        "issued-in-future",
        "P.iat one hour after the verification time.",
        person(acme, "member", by(acme_admin), iat=NOW + 3600).sd_jwt,
    )
    expect("issued-in-future")
    no_exp, no_exp_disclosures = fresh()
    del no_exp["exp"]
    credential_case(
        "malformed-credential-no-exp",
        "A member credential without exp.",
        tenant.issue((no_exp, no_exp_disclosures), *by(acme_admin))[1],
    )
    expect("malformed-credential")
    credential_case(
        "approver-not-trust-anchor-organisation",
        "Organisation credential approved by an organisation admin.",
        tenant.issue(tenant.prepare_organisation(other, "Other GmbH"), *by(acme_admin))[
            1
        ],
    )
    expect("approver-not-trust-anchor")
    credential_case(
        "approver-not-trust-anchor-staff",
        "Member credential of the trust anchor itself, approved by an organisation admin.",
        person(ta, "member", by(acme_admin)).sd_jwt,
    )
    expect("approver-not-trust-anchor")
    credential_case(
        "unsupported-alg",
        "Issuer JWT header alg RS256.",
        tenant.sign_raw(member.payload, typ="dc+sd-jwt", alg="RS256"),
    )
    expect("unsupported-alg")
    credential_case(
        "issuer-key-not-found",
        "kid names a key the issuer document does not list.",
        tenant.sign_raw(member.payload, typ="dc+sd-jwt", kid=f"{acme}#key-unknown"),
    )
    expect("issuer-key-not-found")
    credential_case(
        "issuer-key-of-other-did",
        "kid belongs to another DID than iss.",
        tenant.sign_raw(member.payload, typ="dc+sd-jwt", kid=tenant.kid(other)),
    )
    expect("issuer-key-not-found")
    credential_case(
        "issuer-kid-relative",
        "kid as a relative DID URL (#key-...), made absolute against iss.",
        tenant.sign_raw(
            member.payload, typ="dc+sd-jwt", kid="#" + tenant.kid(acme).split("#", 1)[1]
        ),
    )
    expect_ok()
    ghost = f"did:web:{HOST}:participants:ghost"
    ghost_admin, _ = tenant.prepare_member(ghost, "admin", SoftAuthenticator())
    ghost_token = tenant.sign_raw({**ghost_admin, "evidence": []}, typ="dc+sd-jwt")
    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "did-resolution-failed",
        "approverCredential issued by a DID that does not resolve.",
        with_evidence(
            p,
            tampered(
                e,
                approverCredential=ghost_token,
                approver={
                    "sub": ghost_admin["sub"],
                    "memberOf": ghost,
                    "role": "admin",
                },
            ),
        ),
    )
    expect("did-resolution-failed", 1)
    instruction_case(
        "malformed-instruction",
        "A revocation instruction without nonce.",
        {k: v for k, v in instruction.items() if k != "nonce"},
        revoke_evidence,
    )
    expect("malformed-instruction")

    # Cases that need their own DID documents.
    no_service = json.loads(json.dumps(tenant.docs))
    del no_service[ta]["service"]
    credential_case(
        "relying-party-missing",
        "Trust anchor document without the HavenWebAuthnRelyingParty service.",
        member.sd_jwt,
        did_documents=no_service,
    )
    expect("relying-party-missing")
    jwk_array = json.loads(json.dumps(tenant.docs))
    jwk_array[acme]["verificationMethod"][0]["publicKeyJwk"] = []
    credential_case(
        "issuer-public-key-jwk-array",
        "Issuer verification method whose publicKeyJwk is an array: not a key.",
        member.sd_jwt,
        did_documents=jwk_array,
    )
    expect("issuer-key-not-found")

    # Values that JSON parsers read differently must still give one result.
    ac_payload = json.loads(b64url_decode(acme_admin.credential.split(".")[1]))
    ac_jwk_array = tenant.sign_raw(
        {
            **ac_payload,
            "authenticators": [
                {"credentialId": acme_admin.passkey.credential_id, "jwk": []}
            ],
        },
        typ="dc+sd-jwt",
    )
    p = fresh()
    e = approved(p, by(acme_admin))
    credential_case(
        "approver-jwk-array",
        "An authenticators entry whose jwk is an array: not a key.",
        with_evidence(p, tampered(e, approverCredential=ac_jwk_array)),
    )
    expect("approver-key-not-found")
    credential_case(
        "payload-nan",
        "A payload containing NaN is not JSON (RFC 8259 §6) and has no JCS form.",
        tenant.sign_raw({**member.payload, "x": float("nan")}, typ="dc+sd-jwt"),
    )
    expect("malformed-credential")
    credential_case(
        "iat-integral-float",
        "iat written as 1799136000.0: the same JSON number, accepted by both runtimes.",
        tenant.sign_raw(
            {**member.payload, "iat": float(member.payload["iat"])}, typ="dc+sd-jwt"
        ),
    )
    expect_ok()
    credential_case(
        "iat-beyond-safe-integer",
        "iat above 2^53 - 1 is not read identically by every JSON parser.",
        tenant.sign_raw({**member.payload, "iat": 2**53 + 1}, typ="dc+sd-jwt"),
    )
    expect("malformed-credential")

    # An issuer signing with an Ed25519 key: EdDSA and the fully-specified
    # Ed25519 alg (RFC 9864) are both accepted.
    ed_org = f"did:web:{HOST}:participants:ed-org"
    ed_signing_key = Ed25519PrivateKey.generate()
    ed_jwk = _jwk(ed_signing_key.public_key())
    ed_kid = f"{ed_org}#key-{_thumbprint(ed_jwk)}"
    tenant.docs[ed_org] = {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": ed_org,
        "verificationMethod": [
            {
                "id": ed_kid,
                "type": "JsonWebKey",
                "controller": ed_org,
                "publicKeyJwk": ed_jwk,
            }
        ],
        "assertionMethod": [ed_kid],
    }
    ed_prepared = tenant.prepare_member(ed_org, "admin", SoftAuthenticator())
    ed_evidence = approved(ed_prepared, (ta_admin, by_ta))
    for alg in ("EdDSA", "Ed25519"):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # joserfc flags EdDSA as deprecated
            token = jws.serialize_compact(
                {"alg": alg, "typ": "dc+sd-jwt", "kid": ed_kid},
                json.dumps({**ed_prepared[0], "evidence": [ed_evidence]}).encode(),
                jose_jwk.import_key(ed_signing_key, "OKP"),
                algorithms=[alg],
            )
            credential_case(
                f"issuer-alg-{alg}",
                f"Issuer JWT signed by an Ed25519 key with alg {alg}.",
                token + "~",
            )
        expect_ok()

    # --- the trust anchor key log (§4.5) -------------------------------------

    def keyed_org(passkey: SoftAuthenticator, approver: dict, days_ago: int) -> str:
        prepared = tenant.prepare_organisation(
            keyed, "Keyed GmbH", iat=NOW - days_ago * DAY
        )
        return tenant.issue(prepared, passkey, approver)[1]

    def expect_result(result: dict) -> None:
        assert cases[-1]["expected"] == result, (
            cases[-1]["name"],
            cases[-1]["expected"],
        )

    def expect_ok_by(approver: Person) -> None:
        expect_result(
            {
                "ok": True,
                "approvers": [
                    {
                        "sub": approver.payload["sub"],
                        "memberOf": ta,
                        "via": "trust-anchor",
                    }
                ],
            }
        )

    def expect_key_not_found() -> None:
        assert cases[-1]["expected"]["ok"] is False
        assert (cases[-1]["expected"]["reason"], cases[-1]["expected"]["depth"]) == (
            "approver-key-not-found",
            0,
        ), (cases[-1]["name"], cases[-1]["expected"])

    credential_case(
        "key-log-genesis-bootstrap",
        "The first trust anchor admin approves their own admin credential: the "
        "log has no active key at its iat and the credential is its genesis entry.",
        genesis.sd_jwt,
    )
    expect_ok_by(genesis)
    credential_case(
        "key-log-replay",
        "Approved by an admin seated after the genesis, with every kind of entry replayed before iat.",
        keyed_org(kept_key, two_keys.approver(), 1),
    )
    expect_ok_by(two_keys)
    credential_case(
        "key-log-added-after-iat",
        "The approver key is in the log now, but was added after the payload's iat.",
        keyed_org(late_key, late.approver(), 10),
    )
    expect_key_not_found()
    credential_case(
        "key-log-passkey-revoked-after-iat",
        "The approver key was active at iat and removed since by passkey_revoked.",
        keyed_org(dropped_key, two_keys.approver(), 8),
    )
    expect_ok_by(two_keys)
    credential_case(
        "key-log-passkey-revoked-before-iat",
        "The approver key was removed by passkey_revoked before iat.",
        keyed_org(dropped_key, two_keys.approver(), 4),
    )
    expect_key_not_found()
    credential_case(
        "key-log-demoted-after-iat",
        "The approver was a trust anchor admin at iat and demoted to member since.",
        keyed_org(demoted_key, demoted.approver(), 8),
    )
    expect_ok_by(demoted)
    credential_case(
        "key-log-demoted-before-iat",
        "The approver was demoted (a successor credential with role member) before iat.",
        keyed_org(demoted_key, demoted.approver(), 4),
    )
    expect_key_not_found()
    credential_case(
        "key-log-revoked-after-iat",
        "The approver's admin credential was revoked by a logged instruction after iat.",
        keyed_org(revoked_key, revoked.approver(), 10),
    )
    expect_ok_by(revoked)
    credential_case(
        "key-log-revoked-before-iat",
        "The approver's admin credential was revoked by a logged instruction before iat.",
        keyed_org(revoked_key, revoked.approver(), 5),
    )
    expect_key_not_found()

    def self_approved(passkey: SoftAuthenticator, days_ago: int) -> str:
        prepared = tenant.prepare_member(ta, "admin", passkey, iat=NOW - days_ago * DAY)
        approver = {"sub": prepared[0]["sub"], "memberOf": ta, "role": "admin"}
        return tenant.issue(prepared, passkey, approver)[1]

    credential_case(
        "key-log-self-approval-while-admin-active",
        "A trust anchor admin credential approved by its own subject while other admin keys are active.",
        self_approved(SoftAuthenticator(), 2),
    )
    expect_key_not_found()
    credential_case(
        "key-log-self-approval-not-logged",
        "A self-approved trust anchor admin credential dated before the genesis "
        "(no active key) whose jti is not in the log.",
        self_approved(SoftAuthenticator(), 40),
    )
    expect_key_not_found()
    credential_case(
        "key-log-approver-sub-mismatch",
        "A trust anchor admin key whose evidence names another subject.",
        keyed_org(ta_admin, {**by_ta, "sub": f"urn:uuid:{uuid.uuid4()}"}, 1),
    )
    assert cases[-1]["expected"]["reason"] == "approver-mismatch"
    document_only = SoftAuthenticator()
    tenant.add_trust_anchor_passkey(document_only)
    credential_case(
        "key-log-document-only-passkey",
        "A passkey listed under authentication in the trust anchor document but not in the key log.",
        keyed_org(
            document_only,
            {"sub": f"urn:uuid:{uuid.uuid4()}", "memberOf": ta, "role": "admin"},
            1,
        ),
    )
    expect_key_not_found()

    def broken(change) -> dict[str, list]:
        entries = json.loads(json.dumps(key_log))
        change(entries)
        return {ta: entries}

    def rechain(entries: list[dict], start: int) -> None:
        for i in range(start, len(entries)):
            entries[i]["prev"] = entries[i - 1]["hash"] if i else None
            entries[i]["hash"] = key_log_entry_hash(entries[i])

    def broken_prev(entries: list[dict]) -> None:
        entries[2]["prev"] = entries[0]["hash"]
        entries[2]["hash"] = key_log_entry_hash(entries[2])
        rechain(entries, 3)

    def seq_gap(entries: list[dict]) -> None:
        for entry in entries[3:]:
            entry["seq"] += 1
        rechain(entries, 3)

    def stale_hash(entries: list[dict]) -> None:
        entries[1]["at"] -= 1

    def foreign_credential(entries: list[dict]) -> None:
        entries[1]["material"]["jwt"] = acme_admin.credential
        rechain(entries, 1)

    def at_decreases(entries: list[dict]) -> None:
        entries[2]["at"] = entries[0]["at"] - 1
        rechain(entries, 2)

    for name, description, change in [
        (
            "broken-prev",
            "Entry 3's prev names entry 1 (hashes recomputed).",
            broken_prev,
        ),
        ("seq-gap", "seq jumps from 3 to 5 (hashes recomputed).", seq_gap),
        (
            "stale-hash",
            "Entry 2's at changed without recomputing its hash.",
            stale_hash,
        ),
        (
            "foreign-credential",
            "Entry 2 holds an acme admin credential, not a trust anchor member credential.",
            foreign_credential,
        ),
        ("at-decreases", "Entry 3 is dated before entry 1.", at_decreases),
    ]:
        credential_case(
            f"key-log-{name}",
            f"{description} Any chain violation fails the verification.",
            acme_org,
            key_logs=broken(change),
        )
        assert cases[-1]["expected"]["reason"] == "key-log-invalid", cases[-1]
        assert cases[-1]["expected"]["depth"] == 0
    credential_case(
        "key-log-unavailable",
        "The key log of the trust anchor cannot be fetched.",
        acme_org,
        key_logs={},
    )
    assert cases[-1]["expected"]["reason"] == "key-log-unavailable"
    assert len(key_log) == key_log_length, "every case must replay the same log"

    digests = [
        {"input": obj, "digest": payload_digest(obj)}
        for obj in (
            {k: v for k, v in member.payload.items() if k != "evidence"},
            instruction,
        )
    ]

    return {
        "description": (
            "Passkey evidence vectors (docs/specs/passkey-evidence.md): chains, "
            "instructions, batch approvals and trust anchor key log replay. "
            "`keyLogs` maps the trust anchor DID to its key log; a case with its "
            "own `keyLogs` uses that map instead. `expected` is the Python "
            "verifier's result; the TypeScript verifier must agree."
        ),
        "generator": "tests/fixtures/evidence/gen_evidence_vectors.py",
        "now": NOW,
        "trustAnchorDid": ta,
        "didDocuments": tenant.docs,
        "keyLogs": tenant.key_logs,
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
