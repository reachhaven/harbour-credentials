"""Passkey evidence: verify who approved a credential, up to the trust anchor.

Implements ``docs/specs/passkey-evidence.md``: every member and organisation
credential carries one ``HavenWebAuthnEvidence`` object, a WebAuthn assertion
by the approving person's passkey over the digest of the credential payload.
The approver's passkey is trusted through the ``authenticators`` claim of the
approver's own member credential (embedded as ``approverCredential``), whose
evidence is checked the same way, until a passkey listed in the trust anchor's
DID document ends the chain.

One assertion may approve a whole batch: its challenge is then the Merkle root
over the payload digests, and each credential carries its ``merklePath``
(:mod:`harbour.merkle`). A batch of one is ordinary single-payload evidence.

Both runtimes run the same checks in the same order and report the same
``reason`` for the same input. DID resolution is injected: pass any
``resolve_did(did) -> dict``.

CLI Usage:
    python -m harbour.evidence --help
    python -m harbour.evidence digest --payload payload.json
    python -m harbour.evidence verify --credential cred.jwt --did-documents docs.json \\
        --trust-anchor did:web:example.com:participants:ta
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import sys
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from joserfc import jwk as jose_jwk
from joserfc import jws as jose_jws

from harbour.digest_sri import canonical_json
from harbour.merkle import (
    MerklePathError,
    b64url_decode,
    b64url_encode,
    fold_path,
    payload_digest_bytes,
)

__all__ = [
    "CREDENTIAL_JWT_TYP",
    "EVIDENCE_TYPE",
    "RELYING_PARTY_SERVICE_TYPE",
    "INSTRUCTION_CONTEXT",
    "MEMBER_VCTS",
    "ORGANISATION_VCTS",
    "DEFAULT_MAX_EVIDENCE_DEPTH",
    "Approver",
    "EvidenceChainResult",
    "payload_digest",
    "evidence_challenge",
    "passkey_vm_id",
    "build_webauthn_evidence",
    "static_resolver",
    "verify_did_signed_jwt",
    "verify_evidence_chain",
    "verify_evidence_for_payload",
    "verify_instruction_evidence",
]

CREDENTIAL_JWT_TYP = "dc+sd-jwt"
EVIDENCE_TYPE = "HavenWebAuthnEvidence"
RELYING_PARTY_SERVICE_TYPE = "HavenWebAuthnRelyingParty"
INSTRUCTION_CONTEXT = "https://schema.reachhaven.com/instructions/v1"
INSTRUCTION_TYPES = ("haven:RevokeCredential",)
DEFAULT_MAX_EVIDENCE_DEPTH = 8

# Credentials held by a person that carry memberOf, role and authenticators.
MEMBER_VCTS = (
    "haven:MemberCredential",
    "simpulseid:UserCredential",
    "simpulseid:AdministratorCredential",
)
# Organisation-level credentials: issued by the trust anchor, published.
ORGANISATION_VCTS = (
    "haven:OrganisationCredential",
    "simpulseid:ParticipantCredential",
    "simpulseid:AscsBaseMembershipCredential",
    "simpulseid:AscsEnvitedMembershipCredential",
)

_CLOCK_SKEW_SECONDS = 60
_FLAG_UP = 0x01
_FLAG_UV = 0x04
_SUPPORTED_JWS_ALGS = ("ES256", "EdDSA", "Ed25519")
_B64URL_NONEMPTY = re.compile(r"^[A-Za-z0-9_-]+$")
_URN_UUID = re.compile(
    r"^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CRSET_ENTRY_ID = re.compile(r"^0x[0-9a-f]{64}$")

ResolveDid = Callable[[str], dict]


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Approver:
    """One level of a verified chain. ``via`` is ``"trust-anchor"`` when the key
    is listed in the trust anchor document, ``"credential"`` otherwise."""

    sub: str
    member_of: str
    via: str

    def to_dict(self) -> dict[str, str]:
        return {"sub": self.sub, "memberOf": self.member_of, "via": self.via}


@dataclass
class EvidenceChainResult:
    """``ok`` with the approvers nearest first, or the first failing check.

    ``depth`` is 0 for the credential itself and *n* for the *n*-th approver
    credential down the chain.
    """

    ok: bool
    approvers: list[Approver] = field(default_factory=list)
    reason: str | None = None
    depth: int | None = None
    detail: str | None = None

    def __bool__(self) -> bool:
        return self.ok

    def to_dict(self) -> dict[str, Any]:
        if self.ok:
            return {"ok": True, "approvers": [a.to_dict() for a in self.approvers]}
        out: dict[str, Any] = {"ok": False, "reason": self.reason, "depth": self.depth}
        if self.detail is not None:
            out["detail"] = self.detail
        return out


class _Fail(Exception):
    """Internal: carries a failure up to the public entry points."""

    def __init__(self, reason: str, depth: int, detail: str | None = None):
        super().__init__(reason)
        self.result = EvidenceChainResult(
            ok=False, reason=reason, depth=depth, detail=detail
        )


@dataclass
class _Ctx:
    resolve_did: ResolveDid
    ta: str
    ta_doc: dict
    now: int
    max_depth: int
    member_vcts: tuple[str, ...]
    organisation_vcts: tuple[str, ...]


# ---------------------------------------------------------------------------
# Digests, identifiers, DID documents
# ---------------------------------------------------------------------------


def payload_digest(payload: dict[str, Any]) -> str:
    """``base64url(SHA-256(UTF-8(JCS(payload without evidence/proof))))``.

    For a credential, *payload* is the issuer JWT payload exactly as signed
    (with ``_sd`` digests); disclosures do not enter it. For an instruction it
    is the instruction object.
    """
    return b64url_encode(payload_digest_bytes(payload))


def evidence_challenge(payload: dict[str, Any], merkle_path: Any = None) -> str:
    """The WebAuthn challenge that evidence for *payload* must carry: the payload
    digest folded up *merkle_path* (the digest itself when there is no path)."""
    return b64url_encode(fold_path(payload_digest_bytes(payload), merkle_path))


def passkey_vm_id(trust_anchor_did: str, credential_id: str) -> str:
    """``<ta>#passkey-<b64url(SHA-256(rawId))>``: a trust anchor admin passkey."""
    raw = b64url_decode(credential_id)
    return f"{trust_anchor_did}#passkey-{b64url_encode(hashlib.sha256(raw).digest())}"


def build_webauthn_evidence(
    assertion: dict[str, str],
    *,
    approver: dict[str, str],
    kind: str = "approval",
    approver_credential: str | None = None,
    merkle_path: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Wrap the four raw WebAuthn values (``credentialId``, ``authenticatorData``,
    ``clientDataJSON``, ``signature``, base64url) as a ``HavenWebAuthnEvidence``.

    ``merkle_path`` is omitted for single-payload evidence (and for a batch of
    one, whose path is empty).
    """
    evidence: dict[str, Any] = {
        "type": EVIDENCE_TYPE,
        "version": 1,
        "kind": kind,
        "credentialId": assertion["credentialId"],
        "authenticatorData": assertion["authenticatorData"],
        "clientDataJSON": assertion["clientDataJSON"],
        "signature": assertion["signature"],
        "approver": dict(approver),
    }
    if approver_credential is not None:
        evidence["approverCredential"] = approver_credential
    if merkle_path:
        evidence["merklePath"] = merkle_path
    return evidence


def static_resolver(documents: dict[str, dict] | Iterable[dict]) -> ResolveDid:
    """A resolver over a fixed set of DID documents (keyed by DID, or a list)."""
    docs = (
        dict(documents)
        if isinstance(documents, dict)
        else {d["id"]: d for d in documents}
    )

    def resolve(did: str) -> dict:
        if did not in docs:
            raise LookupError(f"unknown DID {did}")
        return json.loads(json.dumps(docs[did]))

    return resolve


def _did_of(did_url: str) -> str:
    return did_url.split("#")[0]


def _absolute(doc: dict, vm_id: str) -> str:
    return f"{doc.get('id')}{vm_id}" if vm_id.startswith("#") else vm_id


def _find_verification_method(doc: dict, vm_id: str, relationship: str) -> dict | None:
    """The method *vm_id* if *doc* references it from *relationship* (by id or
    embedded). Only methods with a ``publicKeyJwk`` count."""
    wanted = _absolute(doc, vm_id)
    for ref in doc.get(relationship) or []:
        if isinstance(ref, str):
            if _absolute(doc, ref) != wanted:
                continue
            for vm in doc.get("verificationMethod") or []:
                if (
                    isinstance(vm, dict)
                    and isinstance(vm.get("id"), str)
                    and _absolute(doc, vm["id"]) == wanted
                    and isinstance(vm.get("publicKeyJwk"), dict)
                ):
                    return vm
        elif (
            isinstance(ref, dict)
            and isinstance(ref.get("id"), str)
            and _absolute(doc, ref["id"]) == wanted
            and isinstance(ref.get("publicKeyJwk"), dict)
        ):
            return ref
    return None


def _resolve_exact(resolve_did: ResolveDid, did: str) -> dict:
    doc = resolve_did(did)
    if not isinstance(doc, dict) or doc.get("id") != did:
        raise LookupError(f"resolved document id does not match {did}")
    return doc


def _read_relying_party(ta_doc: dict) -> tuple[str, list[str]] | None:
    for service in ta_doc.get("service") or []:
        if (
            isinstance(service, dict)
            and service.get("type") == RELYING_PARTY_SERVICE_TYPE
        ):
            endpoint = service.get("serviceEndpoint")
            if not isinstance(endpoint, dict):
                return None
            rp_id, origins = endpoint.get("rpId"), endpoint.get("origins")
            if not isinstance(rp_id, str) or not rp_id:
                return None
            if not isinstance(origins, list) or not all(
                isinstance(o, str) for o in origins
            ):
                return None
            return rp_id, origins
    return None


# ---------------------------------------------------------------------------
# Keys and signatures
# ---------------------------------------------------------------------------


def _public_key(jwk: dict):
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x = int.from_bytes(b64url_decode(jwk["x"]), "big")
        y = int.from_bytes(b64url_decode(jwk["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        return Ed25519PublicKey.from_public_bytes(b64url_decode(jwk["x"]))
    raise ValueError("unsupported key")


def _jws_alg_fits(alg: str, jwk: dict) -> bool:
    if alg == "ES256":
        return jwk.get("kty") == "EC" and jwk.get("crv") == "P-256"
    if alg in ("EdDSA", "Ed25519"):
        return jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519"
    return False


def _der_to_raw(der: bytes, size: int = 32) -> tuple[int, int]:
    """ASN.1 DER ``SEQUENCE { INTEGER r, INTEGER s }`` → ``(r, s)``.

    Tolerates redundant leading zeros (some authenticators pad oddly; ECDSA
    verification decides whether the values are valid) and rejects trailing
    bytes.
    """

    def length(at: int) -> tuple[int, int]:
        if at >= len(der):
            raise ValueError("truncated DER")
        first = der[at]
        if first < 0x80:
            return first, at + 1
        if first != 0x81 or at + 1 >= len(der) or der[at + 1] < 0x80:
            raise ValueError("unsupported DER length")
        return der[at + 1], at + 2

    def integer(at: int) -> tuple[int, int]:
        if at >= len(der) or der[at] != 0x02:
            raise ValueError("expected DER INTEGER")
        n, start = length(at + 1)
        end = start + n
        if n == 0 or end > len(der):
            raise ValueError("truncated DER INTEGER")
        value = der[start:end].lstrip(b"\x00") or b"\x00"
        if len(value) > size:
            raise ValueError("DER INTEGER too large")
        return int.from_bytes(value, "big"), end

    if not der or der[0] != 0x30:
        raise ValueError("expected DER SEQUENCE")
    n, start = length(1)
    if start + n != len(der):
        raise ValueError("DER SEQUENCE length mismatch")
    r, after_r = integer(start)
    s, after_s = integer(after_r)
    if after_s != len(der):
        raise ValueError("trailing bytes after DER signature")
    return r, s


def verify_did_signed_jwt(
    token: str, *, resolve_did: ResolveDid, typ: str = CREDENTIAL_JWT_TYP
) -> tuple[dict, dict]:
    """Verify a compact JWS (or the issuer JWT of an SD-JWT) against the key its
    ``kid`` names under ``assertionMethod`` in the ``iss`` DID document.

    Returns ``(header, payload)``. Raises :class:`ValueError` whose first
    argument is the failure reason (``malformed-credential``,
    ``unexpected-typ``, ``unsupported-alg``, ``did-resolution-failed``,
    ``issuer-key-not-found``, ``bad-issuer-signature``) and the second an
    optional detail.
    """
    jws = token.split("~")[0] if isinstance(token, str) else ""
    parts = jws.split(".")
    try:
        if len(parts) != 3:
            raise ValueError
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError
    except ValueError as e:
        raise ValueError("malformed-credential", "not a compact JWS") from e
    if header.get("typ") != typ:
        raise ValueError("unexpected-typ", str(header.get("typ")))
    alg = header.get("alg")
    if not isinstance(alg, str) or alg not in _SUPPORTED_JWS_ALGS:
        raise ValueError("unsupported-alg", str(alg))
    iss = payload.get("iss")
    if not isinstance(iss, str) or not iss.startswith("did:"):
        raise ValueError("malformed-credential", None)
    kid = header.get("kid")
    kid = (
        (f"{iss}{kid}" if kid.startswith("#") else kid) if isinstance(kid, str) else ""
    )
    if not kid or _did_of(kid) != iss:
        raise ValueError("issuer-key-not-found", "kid is not a key of iss")
    try:
        doc = _resolve_exact(resolve_did, iss)
    except Exception as e:  # any resolver failure
        raise ValueError("did-resolution-failed", str(e)) from e
    vm = _find_verification_method(doc, kid, "assertionMethod")
    if vm is None:
        raise ValueError("issuer-key-not-found", kid)
    jwk = vm["publicKeyJwk"]
    if not _jws_alg_fits(alg, jwk):
        raise ValueError("unsupported-alg", alg)
    try:
        # joserfc permits an empty crit array; RFC 7515 §4.1.11 forbids it.
        if "crit" in header and (
            not isinstance(header["crit"], list)
            or not header["crit"]
            or any(not isinstance(name, str) or not name for name in header["crit"])
        ):
            raise ValueError("crit must be a non-empty array of header names")
        # Keep non-critical extension headers interoperable with jose, while
        # requiring every critical extension to be understood by the registry.
        registry = jose_jws.JWSRegistry(algorithms=[alg], strict_check_header=False)
        registry.max_header_length = max(8192, len(parts[0]))
        registry.max_payload_length = max(65536, len(parts[1]))
        jose_jws.deserialize_compact(
            jws, jose_jwk.import_key(jwk), algorithms=[alg], registry=registry
        )
    except Exception as e:
        raise ValueError("bad-issuer-signature", str(e) or None) from e
    return {**header, "kid": kid}, payload


# ---------------------------------------------------------------------------
# WebAuthn assertion checks (spec §4 steps 2, 3, 4, 6)
# ---------------------------------------------------------------------------


def _check_client_data(e: dict, challenge: str, origins: list[str], depth: int) -> None:
    try:
        cd = json.loads(b64url_decode(e["clientDataJSON"]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as err:
        raise _Fail("client-data-invalid", depth, "clientDataJSON is not JSON") from err
    if not isinstance(cd, dict):
        raise _Fail("client-data-invalid", depth)
    if cd.get("type") != "webauthn.get":
        raise _Fail("client-data-invalid", depth, f"type {cd.get('type')}")
    if not isinstance(cd.get("challenge"), str) or not hmac.compare_digest(
        cd["challenge"].encode("utf-8"), challenge.encode("utf-8")
    ):
        raise _Fail("digest-mismatch", depth)
    if cd.get("crossOrigin") is True:
        raise _Fail("cross-origin", depth)
    if not isinstance(cd.get("origin"), str) or cd["origin"] not in origins:
        raise _Fail("origin-not-allowed", depth, str(cd.get("origin")))


def _check_authenticator_data(e: dict, rp_id: str, depth: int) -> None:
    try:
        ad = b64url_decode(e["authenticatorData"])
    except ValueError as err:
        raise _Fail("authenticator-data-invalid", depth) from err
    if len(ad) < 37:
        raise _Fail("authenticator-data-invalid", depth, "shorter than 37 bytes")
    if not hmac.compare_digest(ad[:32], hashlib.sha256(rp_id.encode("utf-8")).digest()):
        raise _Fail("rp-id-hash-mismatch", depth)
    if not ad[32] & _FLAG_UP:
        raise _Fail("user-not-present", depth)
    if not ad[32] & _FLAG_UV:
        raise _Fail("user-not-verified", depth)


def _verify_assertion_signature(e: dict, jwk: dict, depth: int) -> None:
    try:
        data = (
            b64url_decode(e["authenticatorData"])
            + hashlib.sha256(b64url_decode(e["clientDataJSON"])).digest()
        )
        signature = b64url_decode(e["signature"])
    except ValueError as err:
        raise _Fail("malformed-evidence", depth) from err
    alg = jwk.get("alg")
    try:
        if (
            jwk.get("kty") == "EC"
            and jwk.get("crv") == "P-256"
            and alg in (None, "ES256")
        ):
            try:
                r, s = _der_to_raw(signature, 32)
            except ValueError as err:
                raise _Fail("bad-webauthn-signature", depth, str(err)) from err
            _public_key(jwk).verify(
                encode_dss_signature(r, s), data, ec.ECDSA(hashes.SHA256())
            )
            return
        if (
            jwk.get("kty") == "OKP"
            and jwk.get("crv") == "Ed25519"
            and alg in (None, "EdDSA")
        ):
            _public_key(jwk).verify(signature, data)
            return
    except _Fail:
        raise
    except Exception as err:
        raise _Fail("bad-webauthn-signature", depth, str(err) or None) from err
    raise _Fail(
        "unsupported-alg", depth, f"{jwk.get('kty')}/{jwk.get('crv')}/{jwk.get('alg')}"
    )


# ---------------------------------------------------------------------------
# The chain (spec §4)
# ---------------------------------------------------------------------------


def _is_str(v: Any) -> bool:
    return isinstance(v, str) and len(v) > 0


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _parse_evidence(e: Any, depth: int) -> dict:
    """Shape check of ``HavenWebAuthnEvidence``; unknown members are ignored."""
    ok = (
        isinstance(e, dict)
        and e.get("type") == EVIDENCE_TYPE
        and _is_int(e.get("version"))
        and e["version"] == 1
        and e.get("kind") in ("approval", "endorsement")
        and all(
            isinstance(e.get(k), str) and _B64URL_NONEMPTY.match(e[k])
            for k in (
                "credentialId",
                "authenticatorData",
                "clientDataJSON",
                "signature",
            )
        )
        and isinstance(e.get("approver"), dict)
        and _is_str(e["approver"].get("sub"))
        and _is_str(e["approver"].get("memberOf"))
        and e["approver"].get("role") in ("admin", "member")
        and ("approverCredential" not in e or _is_str(e["approverCredential"]))
    )
    if not ok:
        raise _Fail("malformed-evidence", depth)
    return e


def _parse_instruction(instruction: Any) -> dict:
    ok = (
        isinstance(instruction, dict)
        and instruction.get("@context") == INSTRUCTION_CONTEXT
        and instruction.get("type") in INSTRUCTION_TYPES
        and _is_str(instruction.get("tenant"))
        and isinstance(instruction.get("credential"), str)
        and _URN_UUID.match(instruction["credential"])
        and isinstance(instruction.get("entry"), str)
        and _CRSET_ENTRY_ID.match(instruction["entry"])
        and _is_str(instruction.get("actor"))
        and _is_int(instruction.get("issuedAt"))
        and _is_str(instruction.get("nonce"))
    )
    if not ok:
        raise _Fail("malformed-instruction", 0)
    return instruction


def _member_fields(p: dict) -> tuple[str, str] | None:
    member_of, role = p.get("memberOf"), p.get("role")
    valid = _is_str(member_of) or (
        isinstance(member_of, list)
        and len(member_of) > 0
        and all(_is_str(m) for m in member_of)
    )
    if not valid or role not in ("admin", "member"):
        return None
    return (member_of if isinstance(member_of, str) else member_of[0]), role


def _challenge(payload: dict, e: dict, depth: int) -> str:
    try:
        return evidence_challenge(payload, e.get("merklePath"))
    except MerklePathError as err:
        raise _Fail("malformed-evidence", depth, str(err)) from err


def _verify_assertion(
    e: dict, challenge: str, anchor_time: int, ctx: _Ctx, depth: int
) -> tuple[dict, dict | None]:
    """Steps 2–6. Returns ``(approver, approver_credential_payload | None)``;
    the approver dict has ``sub``, ``memberOf``, ``role`` and ``via``."""
    rp = _read_relying_party(ctx.ta_doc)
    if rp is None:
        raise _Fail("relying-party-missing", depth)
    rp_id, origins = rp
    _check_client_data(e, challenge, origins, depth)
    _check_authenticator_data(e, rp_id, depth)

    key: dict | None = None
    approver: dict | None = None
    approver_credential: dict | None = None

    # 5.1 An endorsement must prove who the subject is, so it always goes
    # through the approver credential, even for a trust anchor passkey.
    if e["kind"] == "approval":
        try:
            vm_id = passkey_vm_id(ctx.ta, e["credentialId"])
        except ValueError as err:
            raise _Fail("malformed-evidence", depth, "credentialId") from err
        vm = _find_verification_method(ctx.ta_doc, vm_id, "authentication")
        if vm is not None:
            if e["approver"]["memberOf"] != ctx.ta or e["approver"]["role"] != "admin":
                raise _Fail("approver-mismatch", depth, "key is a trust anchor passkey")
            key = vm["publicKeyJwk"]
            approver = {
                "sub": e["approver"]["sub"],
                "memberOf": ctx.ta,
                "role": "admin",
                "via": "trust-anchor",
            }

    # 5.2
    if key is None:
        if not e.get("approverCredential"):
            raise _Fail("approver-credential-missing", depth)
        if depth + 1 > ctx.max_depth:
            raise _Fail("depth-exceeded", depth + 1)
        try:
            _, ac = verify_did_signed_jwt(
                e["approverCredential"], resolve_did=ctx.resolve_did
            )
        except ValueError as err:
            reason, detail = (err.args + (None,))[:2]
            raise _Fail(reason, depth + 1, detail) from err
        if ac.get("vct") not in ctx.member_vcts:
            raise _Fail("approver-credential-not-member", depth + 1, str(ac.get("vct")))
        fields = _member_fields(ac)
        if (
            fields is None
            or not _is_str(ac.get("sub"))
            or not _is_int(ac.get("iat"))
            or not _is_int(ac.get("exp"))
            or not isinstance(ac.get("authenticators"), list)
        ):
            raise _Fail("malformed-credential", depth + 1)
        if not ac["iat"] <= anchor_time <= ac["exp"]:
            raise _Fail("approver-credential-out-of-window", depth)
        match = next(
            (
                a
                for a in ac["authenticators"]
                if isinstance(a, dict) and a.get("credentialId") == e["credentialId"]
            ),
            None,
        )
        if match is None or not isinstance(match.get("jwk"), dict):
            raise _Fail("approver-key-not-found", depth)
        org, role = fields
        approver = {
            "sub": ac["sub"],
            "memberOf": org,
            "role": role,
            "via": "credential",
        }
        if (
            e["approver"]["sub"] != approver["sub"]
            or e["approver"]["memberOf"] != approver["memberOf"]
            or e["approver"]["role"] != approver["role"]
        ):
            raise _Fail("approver-mismatch", depth)
        key = match["jwk"]
        approver_credential = ac

    _verify_assertion_signature(e, key, depth)
    return approver, approver_credential


def _check_authority(p: dict, e: dict, approver: dict, ctx: _Ctx, depth: int) -> None:
    """Step 7: may this approver authorise this credential?"""
    is_ta_admin = approver["role"] == "admin" and (
        approver["via"] == "trust-anchor" or approver["memberOf"] == ctx.ta
    )
    if p.get("vct") in ctx.organisation_vcts:
        if p.get("iss") != ctx.ta:
            raise _Fail("issuer-not-trust-anchor", depth)
        if e["kind"] == "endorsement":
            raise _Fail(
                "endorsement-subject-mismatch", depth, "organisation-level credential"
            )
        if approver["role"] != "admin":
            raise _Fail("approver-not-admin", depth)
        if not is_ta_admin:
            raise _Fail("approver-not-trust-anchor", depth)
        return

    fields = _member_fields(p)
    if fields is None:
        raise _Fail("malformed-credential", depth)
    org, role = fields
    if p.get("iss") != org:
        raise _Fail("issuer-not-organisation", depth)

    if e["kind"] == "endorsement":
        if (
            approver["via"] != "credential"
            or approver["sub"] != p.get("sub")
            or approver["memberOf"] != org
        ):
            raise _Fail("endorsement-subject-mismatch", depth)
        if approver["role"] != role:
            raise _Fail("endorsement-subject-mismatch", depth, "role differs")
        return

    if approver["role"] != "admin":
        raise _Fail("approver-not-admin", depth)
    if is_ta_admin:
        return
    if org == ctx.ta:
        raise _Fail("approver-not-trust-anchor", depth)
    if approver["memberOf"] != org:
        raise _Fail("approver-wrong-organisation", depth)


def _verify_payload_chain(p: dict, ctx: _Ctx, depth: int) -> list[Approver]:
    """Steps 1b–8 for an already signature-checked payload at *depth*."""
    if depth > ctx.max_depth:
        raise _Fail("depth-exceeded", depth)
    if (
        not _is_str(p.get("iss"))
        or not _is_str(p.get("sub"))
        or not _is_int(p.get("iat"))
        or not _is_int(p.get("exp"))
        or not isinstance(p.get("evidence"), list)
    ):
        raise _Fail("malformed-credential", depth)
    if p["iat"] > ctx.now + _CLOCK_SKEW_SECONDS:
        raise _Fail("issued-in-future", depth)
    vct = p.get("vct")
    if vct not in ctx.member_vcts and vct not in ctx.organisation_vcts:
        raise _Fail("unknown-vct", depth, str(vct))

    # The trust anchor's own organisation credential is the root.
    if (
        len(p["evidence"]) == 0
        and p["iss"] == ctx.ta
        and p["sub"] == ctx.ta
        and vct in ctx.organisation_vcts
    ):
        return []
    if len(p["evidence"]) != 1:
        raise _Fail("evidence-count", depth)

    e = _parse_evidence(p["evidence"][0], depth)
    approver, approver_credential = _verify_assertion(
        e, _challenge(p, e, depth), p["iat"], ctx, depth
    )
    _check_authority(p, e, approver, ctx, depth)
    if e["kind"] == "endorsement":
        # §4 step 7: a self-endorsement only updates passkeys and reissue metadata.
        mutable = {"authenticators", "iat", "jti", "evidence"}
        old = {k: v for k, v in approver_credential.items() if k not in mutable}
        new = {k: v for k, v in p.items() if k not in mutable}
        if canonical_json(old) != canonical_json(new):
            raise _Fail("endorsement-payload-mismatch", depth)

    approvers = [Approver(approver["sub"], approver["memberOf"], approver["via"])]
    if approver_credential is not None:
        approvers += _verify_payload_chain(approver_credential, ctx, depth + 1)
    return approvers


def _context(
    resolve_did: ResolveDid,
    trust_anchor_did: str,
    now: int | None,
    max_depth: int,
    member_vcts: Iterable[str] | None,
    organisation_vcts: Iterable[str] | None,
) -> _Ctx:
    try:
        ta_doc = _resolve_exact(resolve_did, trust_anchor_did)
    except Exception as err:
        raise _Fail("did-resolution-failed", 0, str(err)) from err
    return _Ctx(
        resolve_did=resolve_did,
        ta=trust_anchor_did,
        ta_doc=ta_doc,
        now=int(time.time()) if now is None else now,
        max_depth=max_depth,
        member_vcts=tuple(MEMBER_VCTS if member_vcts is None else member_vcts),
        organisation_vcts=tuple(
            ORGANISATION_VCTS if organisation_vcts is None else organisation_vcts
        ),
    )


def verify_evidence_chain(
    issuer_jwt: str,
    *,
    resolve_did: ResolveDid,
    trust_anchor_did: str,
    now: int | None = None,
    max_depth: int = DEFAULT_MAX_EVIDENCE_DEPTH,
    member_vcts: Iterable[str] | None = None,
    organisation_vcts: Iterable[str] | None = None,
) -> EvidenceChainResult:
    """Verify a credential's evidence chain up to the trust anchor.

    *issuer_jwt* is the issuer JWT or the whole SD-JWT (disclosures are not
    needed). Checks issuer signatures, WebAuthn assertions (single or batched)
    and authority. It does not check the expiry or revocation of the credential
    or of any approver credential.
    """
    try:
        ctx = _context(
            resolve_did,
            trust_anchor_did,
            now,
            max_depth,
            member_vcts,
            organisation_vcts,
        )
        try:
            _, payload = verify_did_signed_jwt(issuer_jwt, resolve_did=resolve_did)
        except ValueError as err:
            reason, detail = (err.args + (None,))[:2]
            raise _Fail(reason, 0, detail) from err
        return EvidenceChainResult(
            ok=True, approvers=_verify_payload_chain(payload, ctx, 0)
        )
    except _Fail as f:
        return f.result


def verify_evidence_for_payload(
    payload: dict[str, Any],
    evidence: Any,
    *,
    resolve_did: ResolveDid,
    trust_anchor_did: str,
    now: int | None = None,
    max_depth: int = DEFAULT_MAX_EVIDENCE_DEPTH,
    member_vcts: Iterable[str] | None = None,
    organisation_vcts: Iterable[str] | None = None,
) -> EvidenceChainResult:
    """The issuer's check before it signs: *evidence* against the unsigned
    *payload* (without an ``evidence`` member), with the approver credential's
    own chain verified. Same result as :func:`verify_evidence_chain` once the
    payload is signed with ``evidence: [evidence]``."""
    if "evidence" in payload:
        return EvidenceChainResult(
            ok=False,
            reason="malformed-credential",
            depth=0,
            detail="the payload already carries evidence",
        )
    try:
        ctx = _context(
            resolve_did,
            trust_anchor_did,
            now,
            max_depth,
            member_vcts,
            organisation_vcts,
        )
        approvers = _verify_payload_chain({**payload, "evidence": [evidence]}, ctx, 0)
        return EvidenceChainResult(ok=True, approvers=approvers)
    except _Fail as f:
        return f.result


def verify_instruction_evidence(
    instruction: Any,
    evidence: Any,
    *,
    resolve_did: ResolveDid,
    trust_anchor_did: str,
    now: int | None = None,
    max_depth: int = DEFAULT_MAX_EVIDENCE_DEPTH,
    member_vcts: Iterable[str] | None = None,
    organisation_vcts: Iterable[str] | None = None,
) -> EvidenceChainResult:
    """Evidence for an action that is not an issuance (``haven:RevokeCredential``).

    Steps 2–6 against the digest of the instruction as received, the approver
    must be the instruction's ``actor``, and the approver credential's chain is
    verified up to the trust anchor. Who may revoke what is the caller's policy.
    """
    try:
        instr = _parse_instruction(instruction)
        e = _parse_evidence(evidence, 0)
        if e["kind"] != "approval":
            raise _Fail("malformed-evidence", 0, "instructions take approval evidence")
        if e["approver"]["sub"] != instr["actor"]:
            raise _Fail("approver-mismatch", 0, "approver is not the actor")
        ctx = _context(
            resolve_did,
            trust_anchor_did,
            now,
            max_depth,
            member_vcts,
            organisation_vcts,
        )
        approver, approver_credential = _verify_assertion(
            e, _challenge(instruction, e, 0), instr["issuedAt"], ctx, 0
        )
        approvers = [Approver(approver["sub"], approver["memberOf"], approver["via"])]
        if approver_credential is not None:
            approvers += _verify_payload_chain(approver_credential, ctx, 1)
        return EvidenceChainResult(ok=True, approvers=approvers)
    except _Fail as f:
        return f.result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _load_documents(path: Path) -> ResolveDid:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "didDocuments" in data:
        data = data["didDocuments"]
    return static_resolver(data)


def main() -> None:
    """CLI entry point for passkey evidence operations."""
    parser = argparse.ArgumentParser(
        prog="harbour.evidence",
        description=(
            "Compute payload digests and verify HavenWebAuthnEvidence chains "
            "(docs/specs/passkey-evidence.md)."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # The WebAuthn challenge an approver signs for one payload
  python -m harbour.evidence digest --payload payload.json

  # Verify a credential's evidence chain against a set of DID documents
  python -m harbour.evidence verify --credential cred.jwt \\
      --did-documents docs.json --trust-anchor did:web:example.com:participants:ta
        """,
    )
    sub = parser.add_subparsers(dest="command", help="Available commands")

    digest_p = sub.add_parser("digest", help="Print the payload digest (challenge)")
    digest_p.add_argument(
        "--payload", required=True, help="JSON payload or instruction"
    )

    verify_p = sub.add_parser("verify", help="Verify a credential's evidence chain")
    verify_p.add_argument(
        "--credential", required=True, help="Issuer JWT or SD-JWT file"
    )
    verify_p.add_argument(
        "--did-documents",
        required=True,
        help="JSON file: a list of DID documents, a DID→document map, or an "
        "object with a didDocuments member",
    )
    verify_p.add_argument(
        "--trust-anchor", required=True, help="Trusted trust anchor DID"
    )
    verify_p.add_argument("--now", type=int, help="Verification time (epoch seconds)")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "digest":
        print(
            payload_digest(json.loads(Path(args.payload).read_text(encoding="utf-8")))
        )
    elif args.command == "verify":
        result = verify_evidence_chain(
            Path(args.credential).read_text(encoding="utf-8").strip(),
            resolve_did=_load_documents(Path(args.did_documents)),
            trust_anchor_did=args.trust_anchor,
            now=args.now,
        )
        print(json.dumps(result.to_dict(), indent=2))
        if not result.ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
