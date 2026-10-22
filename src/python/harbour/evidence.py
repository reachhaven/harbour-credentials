"""Passkey evidence: verify who approved a credential, up to the trust anchor.

Implements ``docs/specs/passkey-evidence.md``: every member and organisation
credential carries one ``HavenWebAuthnEvidence`` object, a WebAuthn assertion
by the approving person's passkey over the digest of the credential payload.
The approver's passkey is trusted through the ``authenticators`` claim of the
approver's own member credential (embedded as ``approverCredential``), whose
evidence is checked the same way, until a trust anchor admin passkey ends the
chain. Trust anchor admin passkeys come from the trust anchor key log, replayed
as of the approved payload's ``iat`` (:func:`replay_trust_anchor_key_log`). The
log is self-certifying: every entry that seats or unseats an admin carries an
approval by a passkey the entries before it seated.

One assertion may approve a whole batch: its challenge is then the Merkle root
over the payload digests, and each credential carries its ``merklePath``
(:mod:`harbour.merkle`). A batch of one is ordinary single-payload evidence.

Both runtimes run the same checks in the same order and report the same
``reason`` for the same input. DID and key log resolution are injected: pass
any ``resolve_did(did) -> dict`` and ``resolve_key_log(did) -> list``.

CLI Usage:
    python -m harbour.evidence --help
    python -m harbour.evidence digest --payload payload.json
    python -m harbour.evidence verify --credential cred.jwt --did-documents docs.json \\
        --key-logs key-logs.json --trust-anchor did:web:example.com:participants:ta
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
    "KEY_LOG_SERVICE_TYPE",
    "INSTRUCTION_CONTEXT",
    "MEMBER_VCTS",
    "ORGANISATION_VCTS",
    "DEFAULT_MAX_EVIDENCE_DEPTH",
    "Approver",
    "EvidenceChainResult",
    "TrustAnchorKeys",
    "payload_digest",
    "evidence_challenge",
    "passkey_vm_id",
    "build_webauthn_evidence",
    "static_resolver",
    "static_key_logs",
    "key_log_entry_hash",
    "replay_trust_anchor_key_log",
    "verify_did_signed_jwt",
    "verify_evidence_chain",
    "verify_evidence_for_payload",
    "verify_instruction_evidence",
]

CREDENTIAL_JWT_TYP = "dc+sd-jwt"
EVIDENCE_TYPE = "HavenWebAuthnEvidence"
RELYING_PARTY_SERVICE_TYPE = "HavenWebAuthnRelyingParty"
KEY_LOG_SERVICE_TYPE = "HavenTrustAnchorKeyLog"
KEY_LOG_KINDS = ("credential", "revocation", "passkey_revoked")
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
# Returns the key log of a trust anchor DID, genesis first; raises when it
# cannot be fetched.
ResolveKeyLog = Callable[[str], list]


# ---------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Approver:
    """One level of a verified chain. ``via`` is ``"trust-anchor"`` when a
    trust anchor admin passkey from the key log approved without an approver
    credential (step 5.1), ``"credential"`` otherwise."""

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


@dataclass(frozen=True)
class TrustAnchorKeys:
    """A replayed trust anchor key log (spec §4.5).

    ``credential_jtis`` holds the ``jti`` of every ``credential`` entry,
    ``bootstrap_jtis`` those the replay accepted under the bootstrap rule (no
    admin key was active when they were appended); :meth:`keys_at` gives the
    admin passkeys active at an instant.
    """

    ops: tuple[tuple[int, str, dict], ...]
    credential_jtis: frozenset[str]
    bootstrap_jtis: frozenset[str] = frozenset()

    def keys_at(self, t: int) -> dict[str, dict[str, Any]]:
        """``credentialId -> {"sub", "jwk"}`` for every admin passkey active at
        *t*: entries with ``at <= t`` applied in order, then admins whose
        credential does not cover *t* (``iat <= t <= exp``) dropped."""
        admins: dict[str, dict[str, Any]] = {}
        for at, kind, data in self.ops:
            if at > t:
                break
            if kind == "credential":
                admins.pop(data["sub"], None)
                if data["role"] == "admin":
                    admins[data["sub"]] = {
                        "jti": data["jti"],
                        "iat": data["iat"],
                        "exp": data["exp"],
                        "authenticators": dict(data["authenticators"]),
                    }
            elif kind == "revocation":
                for sub in [
                    s for s, r in admins.items() if r["jti"] == data["credential"]
                ]:
                    del admins[sub]
            else:
                record = admins.get(data["sub"])
                if record is not None:
                    record["authenticators"].pop(data["credentialId"], None)
        keys: dict[str, dict[str, Any]] = {}
        for sub, record in admins.items():
            if record["iat"] <= t <= record["exp"]:
                for credential_id, jwk in record["authenticators"].items():
                    # The admin whose credential entry came later wins.
                    keys.pop(credential_id, None)
                    keys[credential_id] = {"sub": sub, "jwk": jwk}
        return keys


@dataclass
class _Ctx:
    resolve_did: ResolveDid
    ta: str
    ta_doc: dict
    keys: TrustAnchorKeys
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


def static_key_logs(logs: dict[str, list]) -> ResolveKeyLog:
    """A key log resolver over a fixed ``{trust anchor DID: entries}`` map."""
    logs = dict(logs)

    def resolve(did: str) -> list:
        if did not in logs:
            raise LookupError(f"no key log for {did}")
        return json.loads(json.dumps(logs[did]))

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
        header = json.loads(b64url_decode(parts[0]), parse_constant=_reject_constant)
        payload = json.loads(b64url_decode(parts[1]), parse_constant=_reject_constant)
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
        cd = json.loads(
            b64url_decode(e["clientDataJSON"]).decode("utf-8"),
            parse_constant=_reject_constant,
        )
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


# A JSON integer: an integral number inside the IEEE 754 safe range, so that
# both runtimes accept the same values. JSON.parse cannot tell 1 from 1.0 and
# loses precision beyond 2^53; JCS serialises both forms identically.
_MAX_SAFE_INTEGER = 2**53 - 1


def _is_int(v: Any) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return False
    if isinstance(v, float) and not v.is_integer():
        return False
    return abs(v) <= _MAX_SAFE_INTEGER


def _reject_constant(name: str) -> Any:
    """``json.loads`` hook: ``NaN`` and ``Infinity`` are not JSON (RFC 8259 §6)
    and have no JCS form. ``JSON.parse`` rejects them, so this side must too."""
    raise ValueError(f"non-finite JSON constant {name}")


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


# ---------------------------------------------------------------------------
# The trust anchor key log (spec §4.5)
# ---------------------------------------------------------------------------


def key_log_entry_hash(entry: dict[str, Any]) -> str:
    """``b64url(SHA-256(JCS({ seq, kind, at, prev, material })))``."""
    return payload_digest(
        {k: entry.get(k) for k in ("seq", "kind", "at", "prev", "material")}
    )


def _key_log_credential(
    material: dict, ta: str, resolve_did: ResolveDid, member_vcts: tuple[str, ...]
) -> tuple[dict[str, Any], dict] | str:
    """``(fields, payload)`` of a ``credential`` entry, or why it is invalid."""
    jwt = material.get("jwt")
    if not isinstance(jwt, str) or not jwt.endswith("~") or jwt.count("~") != 1:
        return "credential jwt is not an issuer JWT with a trailing ~"
    try:
        _, p = verify_did_signed_jwt(jwt, resolve_did=resolve_did)
    except ValueError as err:
        return f"credential {err.args[0]}"
    fields = _member_fields(p)
    if (
        p.get("iss") != ta
        or p.get("vct") not in member_vcts
        or fields is None
        or fields[0] != ta
        or not _is_str(p.get("sub"))
        or not _is_str(p.get("jti"))
        or not _is_int(p.get("iat"))
        or not _is_int(p.get("exp"))
        or not isinstance(p.get("authenticators"), list)
    ):
        return "credential is not a trust anchor member credential"
    authenticators: dict[str, dict] = {}
    for a in p["authenticators"]:
        if (
            not isinstance(a, dict)
            or not _is_str(a.get("credentialId"))
            or not isinstance(a.get("jwk"), dict)
        ):
            return "credential has a malformed authenticator"
        authenticators[a["credentialId"]] = a["jwk"]
    return {
        "sub": p["sub"],
        "role": fields[1],
        "jti": p["jti"],
        "iat": p["iat"],
        "exp": p["exp"],
        "authenticators": authenticators,
    }, p


def _verify_logged_assertion(
    e: dict,
    payload: dict,
    anchor_time: int,
    *,
    keys: TrustAnchorKeys,
    rp: tuple[str, list[str]],
    ta: str,
    member_vcts: tuple[str, ...],
    subject: dict | None,
    entry_at: int,
) -> tuple[str, bool]:
    """Steps 2–6 for the evidence of a key log entry, against the admins the
    entries before it seated. Returns ``(approver sub, bootstrapped)``; raises
    :class:`_Fail` with the §4.4 reason of the first failing check.

    *subject* is the logged credential payload for a ``credential`` entry and
    ``None`` for a ``revocation``; only a credential may bootstrap itself, and
    only while no admin key is active at its ``iat`` nor at the entry's ``at``.
    """
    if e["kind"] != "approval" or e.get("approverCredential"):
        raise _Fail(
            "malformed-evidence",
            0,
            "a key log entry takes a trust anchor approval without approverCredential",
        )
    challenge = _challenge(payload, e, 0)
    rp_id, origins = rp
    _check_client_data(e, challenge, origins, 0)
    _check_authenticator_data(e, rp_id, 0)
    active = keys.keys_at(anchor_time)
    found = active.get(e["credentialId"])
    bootstrapped = False
    if found is not None:
        sub, key = found["sub"], found["jwk"]
    else:
        key = None
        if subject is not None and not active and not keys.keys_at(entry_at):
            key = _own_passkey(e, subject, ta, member_vcts)
        if key is None:
            raise _Fail(
                "approver-key-not-found", 0, "not a trust anchor admin passkey at iat"
            )
        sub, bootstrapped = subject["sub"], True
    if (
        e["approver"]["sub"] != sub
        or e["approver"]["memberOf"] != ta
        or e["approver"]["role"] != "admin"
    ):
        raise _Fail("approver-mismatch", 0, "key is a trust anchor passkey")
    _verify_assertion_signature(e, key, 0)
    return sub, bootstrapped


def replay_trust_anchor_key_log(
    entries: Any,
    *,
    trust_anchor_did: str,
    resolve_did: ResolveDid,
    member_vcts: Iterable[str] | None = None,
    trust_anchor_document: dict | None = None,
) -> TrustAnchorKeys:
    """Check the chain of a trust anchor key log and replay it.

    Every entry must hash and link correctly, and every entry that changes the
    admin set must be approved by a passkey that the entries before it seated
    (spec §4.5): a ``credential`` entry carries the trust anchor admin approval
    of the logged credential, or, while no admin key is active, the subject's
    own approval (the bootstrap); a ``revocation`` entry carries an instruction
    approved by an active trust anchor admin. The log is therefore
    self-certifying back to its genesis: the trust anchor signing key alone
    cannot seat an admin. A ``jti`` may be logged once and a ``credentialId``
    belongs to one admin.

    *trust_anchor_document* is the resolved trust anchor DID document; it is
    resolved through *resolve_did* when absent and is the only document the
    replay consults.

    Raises ``ValueError("key-log-invalid", detail)`` on the first violation.
    """
    vcts = tuple(MEMBER_VCTS if member_vcts is None else member_vcts)
    ta = trust_anchor_did
    ta_doc = (
        _resolve_exact(resolve_did, ta)
        if trust_anchor_document is None
        else trust_anchor_document
    )
    rp = _read_relying_party(ta_doc)
    if rp is None:
        raise ValueError(
            "key-log-invalid", "trust anchor document has no relying party service"
        )

    def resolve(did: str) -> dict:
        # Every logged credential is issued by the trust anchor: one document.
        return json.loads(json.dumps(ta_doc)) if did == ta else resolve_did(did)

    if not isinstance(entries, list):
        raise ValueError("key-log-invalid", "the key log is not an array")
    ops: list[tuple[int, str, dict]] = []
    jtis: set[str] = set()
    bootstrap_jtis: set[str] = set()
    owner: dict[str, str] = {}  # credentialId -> sub, over all credential entries
    prev_hash: str | None = None
    prev_at: int | None = None
    for i, entry in enumerate(entries):

        def invalid(detail: str, i: int = i) -> ValueError:
            return ValueError("key-log-invalid", f"entry {i + 1}: {detail}")

        if (
            not isinstance(entry, dict)
            or not _is_int(entry.get("seq"))
            or entry.get("kind") not in KEY_LOG_KINDS
            or not _is_int(entry.get("at"))
            or "prev" not in entry
            or not (entry["prev"] is None or _is_str(entry["prev"]))
            or not _is_str(entry.get("hash"))
            or not isinstance(entry.get("material"), dict)
            or entry["material"].get("kind") != entry["kind"]
        ):
            raise invalid("malformed entry")
        if entry["seq"] != i + 1:
            raise invalid(f"seq {entry['seq']}")
        if entry["prev"] != prev_hash:
            raise invalid("prev is not the hash of the previous entry")
        try:
            computed = key_log_entry_hash(entry)
        except ValueError as err:
            raise invalid(f"hash cannot be computed: {err}") from err
        if computed != entry["hash"]:
            raise invalid("hash does not match")
        if prev_at is not None and entry["at"] < prev_at:
            raise invalid("at decreases")
        at = entry["at"]
        material = entry["material"]
        # The admins seated by the entries before this one decide who may
        # have approved it.
        so_far = TrustAnchorKeys(
            ops=tuple(ops),
            credential_jtis=frozenset(jtis),
            bootstrap_jtis=frozenset(bootstrap_jtis),
        )
        if entry["kind"] == "credential":
            checked = _key_log_credential(material, ta, resolve, vcts)
            if isinstance(checked, str):
                raise invalid(checked)
            data, payload = checked
            if data["jti"] in jtis:
                raise invalid("credential jti already logged")
            for credential_id in data["authenticators"]:
                if owner.get(credential_id, data["sub"]) != data["sub"]:
                    raise invalid("credentialId already belongs to another admin")
            if data["iat"] > at:
                raise invalid("credential logged before its iat")
            evidence = payload.get("evidence")
            if not isinstance(evidence, list) or len(evidence) != 1:
                raise invalid("credential must carry exactly one evidence object")
            try:
                e = _parse_evidence(evidence[0], 0)
                _, bootstrapped = _verify_logged_assertion(
                    e,
                    payload,
                    data["iat"],
                    keys=so_far,
                    rp=rp,
                    ta=ta,
                    member_vcts=vcts,
                    subject=payload,
                    entry_at=at,
                )
            except _Fail as err:
                raise invalid(f"credential evidence: {err.result.reason}") from err
            if bootstrapped:
                bootstrap_jtis.add(data["jti"])
            jtis.add(data["jti"])
            for credential_id in data["authenticators"]:
                owner[credential_id] = data["sub"]
        elif entry["kind"] == "revocation":
            try:
                instr = _parse_instruction(material.get("instruction"))
                e = _parse_evidence(material.get("evidence"), 0)
                if e["approver"]["sub"] != instr["actor"]:
                    raise _Fail("approver-mismatch", 0, "approver is not the actor")
                _verify_logged_assertion(
                    e,
                    instr,
                    instr["issuedAt"],
                    keys=so_far,
                    rp=rp,
                    ta=ta,
                    member_vcts=vcts,
                    subject=None,
                    entry_at=at,
                )
            except _Fail as err:
                raise invalid(f"revocation evidence: {err.result.reason}") from err
            if instr["issuedAt"] > at:
                raise invalid("revocation logged before its issuedAt")
            data = {"credential": instr["credential"]}
        else:
            # Operator-asserted (spec §4.5): removes a key, carries no evidence.
            if not _is_str(material.get("sub")) or not _is_str(
                material.get("credentialId")
            ):
                raise invalid("malformed passkey_revoked")
            data = {"sub": material["sub"], "credentialId": material["credentialId"]}
        ops.append((at, entry["kind"], data))
        prev_hash, prev_at = entry["hash"], at
    return TrustAnchorKeys(
        ops=tuple(ops),
        credential_jtis=frozenset(jtis),
        bootstrap_jtis=frozenset(bootstrap_jtis),
    )


def _own_passkey(
    e: dict, p: dict, ta: str, member_vcts: tuple[str, ...]
) -> dict | None:
    """The passkey of *p* itself that *e* names, when *p* is a trust anchor
    admin member credential approving itself; ``None`` otherwise."""
    if (
        p.get("iss") != ta
        or p.get("vct") not in member_vcts
        or _member_fields(p) != (ta, "admin")
        or e["approver"]["sub"] != p.get("sub")
        or not isinstance(p.get("authenticators"), list)
    ):
        return None
    match = next(
        (
            a
            for a in p["authenticators"]
            if isinstance(a, dict) and a.get("credentialId") == e["credentialId"]
        ),
        None,
    )
    if match is None or not isinstance(match.get("jwk"), dict):
        return None
    return match["jwk"]


def _bootstrap_key(
    e: dict, p: dict | None, keys: dict, ctx: _Ctx, unsigned: bool
) -> dict | None:
    """The bootstrap rule of step 5.1 for the credential being verified: a
    trust anchor admin member credential approved by its own subject's passkey
    while no admin key is active.

    A signed credential must be a bootstrap entry of the log (the replay
    accepted it while no admin key was active). The issuer's pre-signing check
    has no entry yet; it requires no admin key to be active now either, which
    is what the entry it is about to append will have to satisfy.
    """
    if p is None or keys:
        return None
    if unsigned:
        if ctx.keys.keys_at(ctx.now):
            return None
    elif p.get("jti") not in ctx.keys.bootstrap_jtis:
        return None
    return _own_passkey(e, p, ctx.ta, ctx.member_vcts)


def _challenge(payload: dict, e: dict, depth: int) -> str:
    try:
        return evidence_challenge(payload, e.get("merklePath"))
    except MerklePathError as err:
        raise _Fail("malformed-evidence", depth, str(err)) from err
    except ValueError as err:  # a payload value with no JCS form
        raise _Fail("malformed-credential", depth, str(err)) from err


def _verify_assertion(
    e: dict,
    challenge: str,
    anchor_time: int,
    ctx: _Ctx,
    depth: int,
    subject: dict | None = None,
    unsigned: bool = False,
) -> tuple[dict, dict | None]:
    """Steps 2–6. Returns ``(approver, approver_credential_payload | None)``;
    the approver dict has ``sub``, ``memberOf``, ``role`` and ``via``.

    *subject* is the credential payload being approved (``None`` for an
    instruction); *unsigned* marks the issuer's pre-signing check."""
    rp = _read_relying_party(ctx.ta_doc)
    if rp is None:
        raise _Fail("relying-party-missing", depth)
    rp_id, origins = rp
    _check_client_data(e, challenge, origins, depth)
    _check_authenticator_data(e, rp_id, depth)

    key: dict | None = None
    approver: dict | None = None
    approver_credential: dict | None = None

    # 5.1 only for an approval without an approver credential. An endorsement
    # must prove who the subject is, and an approver who carries a member
    # credential acts for that credential's organisation, even when the passkey
    # is also a trust anchor admin passkey. The key comes from the key log as
    # of the anchor time, never from the trust anchor document.
    if e["kind"] == "approval" and not e.get("approverCredential"):
        active = ctx.keys.keys_at(anchor_time)
        found = active.get(e["credentialId"])
        if found is not None:
            sub, key = found["sub"], found["jwk"]
        else:
            key = _bootstrap_key(e, subject, active, ctx, unsigned)
            if key is None:
                raise _Fail(
                    "approver-key-not-found",
                    depth,
                    "not a trust anchor admin passkey at iat",
                )
            sub = subject["sub"]
        if (
            e["approver"]["sub"] != sub
            or e["approver"]["memberOf"] != ctx.ta
            or e["approver"]["role"] != "admin"
        ):
            raise _Fail("approver-mismatch", depth, "key is a trust anchor passkey")
        approver = {
            "sub": sub,
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
    if org == ctx.ta:
        if not is_ta_admin:
            raise _Fail("approver-not-trust-anchor", depth)
        return
    if approver["memberOf"] == org:
        return
    # A trust anchor admin seats an organisation's admins, never its members.
    if is_ta_admin and role == "admin":
        return
    raise _Fail(
        "approver-wrong-organisation",
        depth,
        "trust anchor admin approving a member role" if is_ta_admin else None,
    )


def _verify_payload_chain(
    p: dict, ctx: _Ctx, depth: int, unsigned: bool = False
) -> list[Approver]:
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
        e, _challenge(p, e, depth), p["iat"], ctx, depth, p, unsigned
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
    resolve_key_log: ResolveKeyLog,
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
    if _read_relying_party(ta_doc) is None:
        raise _Fail("relying-party-missing", 0)
    vcts = tuple(MEMBER_VCTS if member_vcts is None else member_vcts)
    try:
        entries = resolve_key_log(trust_anchor_did)
    except Exception as err:
        raise _Fail("key-log-unavailable", 0, str(err)) from err
    try:
        keys = replay_trust_anchor_key_log(
            entries,
            trust_anchor_did=trust_anchor_did,
            resolve_did=resolve_did,
            member_vcts=vcts,
            trust_anchor_document=ta_doc,
        )
    except Exception as err:  # the log is untrusted input: never crash on it
        detail = (
            err.args[1]
            if isinstance(err, ValueError)
            and len(err.args) == 2
            and err.args[0] == "key-log-invalid"
            else f"{type(err).__name__}: {err}"
        )
        raise _Fail("key-log-invalid", 0, detail) from err
    return _Ctx(
        resolve_did=resolve_did,
        ta=trust_anchor_did,
        ta_doc=ta_doc,
        keys=keys,
        now=int(time.time()) if now is None else now,
        max_depth=max_depth,
        member_vcts=vcts,
        organisation_vcts=tuple(
            ORGANISATION_VCTS if organisation_vcts is None else organisation_vcts
        ),
    )


def verify_evidence_chain(
    issuer_jwt: str,
    *,
    resolve_did: ResolveDid,
    resolve_key_log: ResolveKeyLog,
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
            resolve_key_log,
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
    resolve_key_log: ResolveKeyLog,
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
            resolve_key_log,
            trust_anchor_did,
            now,
            max_depth,
            member_vcts,
            organisation_vcts,
        )
        approvers = _verify_payload_chain(
            {**payload, "evidence": [evidence]}, ctx, 0, unsigned=True
        )
        return EvidenceChainResult(ok=True, approvers=approvers)
    except _Fail as f:
        return f.result


def verify_instruction_evidence(
    instruction: Any,
    evidence: Any,
    *,
    resolve_did: ResolveDid,
    resolve_key_log: ResolveKeyLog,
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
            resolve_key_log,
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


def _load_key_logs(path: Path) -> ResolveKeyLog:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "keyLogs" in data:
        data = data["keyLogs"]
    return static_key_logs(data)


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
      --did-documents docs.json --key-logs key-logs.json \\
      --trust-anchor did:web:example.com:participants:ta
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
        "--key-logs",
        required=True,
        help="JSON file: a trust anchor DID→key log map, or an object with a "
        "keyLogs member",
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
            resolve_key_log=_load_key_logs(Path(args.key_logs)),
            trust_anchor_did=args.trust_anchor,
            now=args.now,
        )
        print(json.dumps(result.to_dict(), indent=2))
        if not result.ok:
            sys.exit(1)


if __name__ == "__main__":
    main()
