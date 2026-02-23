"""Cross-runtime interop tests: Python signs → Node.js verifies (and vice versa)."""

import json
import subprocess
from pathlib import Path

import pytest
from harbour.sd_jwt import issue_sd_jwt_vc, verify_sd_jwt_vc
from harbour.signer import sign_vc_jose, sign_vp_jose
from harbour.verifier import verify_vc_jose, verify_vp_jose

FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"
KEYS_DIR = FIXTURES_DIR / "keys"
TS_DIR = Path(__file__).resolve().parents[2] / "src" / "typescript" / "harbour"


def _can_run_node_jose() -> bool:
    """Check whether yarn-managed Node can import jose in the TS workspace."""
    result = subprocess.run(
        ["yarn", "node", "--input-type=module", "-e", 'import "jose";'],
        capture_output=True,
        text=True,
        cwd=str(TS_DIR),
        timeout=30,
    )
    return result.returncode == 0


# Skip if TypeScript runtime dependencies are unavailable
pytestmark = pytest.mark.skipif(
    not _can_run_node_jose(),
    reason="TypeScript runtime dependencies unavailable (run 'make ts-bootstrap').",
)


def _run_node(script: str) -> str:
    """Run a Node.js script and return its stdout."""
    result = subprocess.run(
        ["yarn", "node", "--input-type=module", "-e", script],
        capture_output=True,
        text=True,
        cwd=str(TS_DIR),
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Node.js error:\n{result.stderr}")
    return result.stdout.strip()


class TestPythonSignNodeVerify:
    """Python signs a VC/VP → Node.js verifies it."""

    def test_vc_jose(self, sample_vc, p256_private_key, p256_public_key):
        token = sign_vc_jose(sample_vc, p256_private_key)
        fixture = json.loads((KEYS_DIR / "test-keypair-p256.json").read_text())
        pub_jwk = {
            "kty": fixture["kty"],
            "crv": fixture["crv"],
            "x": fixture["x"],
            "y": fixture["y"],
        }

        script = f"""
import {{ compactVerify, importJWK }} from "jose";
const pubJwk = {json.dumps(pub_jwk)};
const key = await importJWK(pubJwk, "ES256");
const result = await compactVerify("{token}", key);
const payload = JSON.parse(new TextDecoder().decode(result.payload));
console.log(JSON.stringify(payload));
"""
        output = _run_node(script)
        verified_vc = json.loads(output)
        assert verified_vc == sample_vc

    def test_vp_jose(self, sample_vp, p256_private_key):
        token = sign_vp_jose(
            sample_vp,
            p256_private_key,
            nonce="interop-nonce",
            audience="did:web:verifier.test",
        )
        fixture = json.loads((KEYS_DIR / "test-keypair-p256.json").read_text())
        pub_jwk = {
            "kty": fixture["kty"],
            "crv": fixture["crv"],
            "x": fixture["x"],
            "y": fixture["y"],
        }

        script = f"""
import {{ compactVerify, importJWK }} from "jose";
const key = await importJWK({json.dumps(pub_jwk)}, "ES256");
const result = await compactVerify("{token}", key);
const payload = JSON.parse(new TextDecoder().decode(result.payload));
if (payload.nonce !== "interop-nonce") throw new Error("nonce mismatch");
if (payload.aud !== "did:web:verifier.test") throw new Error("aud mismatch");
console.log("OK");
"""
        assert _run_node(script) == "OK"


class TestNodeSignPythonVerify:
    """Node.js signs a VC/VP → Python verifies it."""

    def test_vc_jose(self, p256_public_key):
        fixture = json.loads((KEYS_DIR / "test-keypair-p256.json").read_text())
        sample_vc = json.loads((FIXTURES_DIR / "sample-vc.json").read_text())

        script = f"""
import {{ CompactSign, importJWK }} from "jose";
const jwk = {json.dumps(fixture)};
const key = await importJWK(jwk, "ES256");
const payload = new TextEncoder().encode(JSON.stringify({json.dumps(sample_vc)}));
const signer = new CompactSign(payload);
signer.setProtectedHeader({{ alg: "ES256", typ: "vc+ld+jwt" }});
const token = await signer.sign(key);
console.log(token);
"""
        token = _run_node(script)
        result = verify_vc_jose(token, p256_public_key)
        assert result == sample_vc

    def test_vp_jose(self, p256_public_key):
        fixture = json.loads((KEYS_DIR / "test-keypair-p256.json").read_text())

        vp = {
            "@context": ["https://www.w3.org/ns/credentials/v2"],
            "type": ["VerifiablePresentation"],
            "verifiableCredential": [],
            "nonce": "cross-nonce",
            "aud": "did:web:verifier.test",
        }

        script = f"""
import {{ CompactSign, importJWK }} from "jose";
const jwk = {json.dumps(fixture)};
const key = await importJWK(jwk, "ES256");
const payload = new TextEncoder().encode(JSON.stringify({json.dumps(vp)}));
const signer = new CompactSign(payload);
signer.setProtectedHeader({{ alg: "ES256", typ: "vp+ld+jwt" }});
const token = await signer.sign(key);
console.log(token);
"""
        token = _run_node(script)
        result = verify_vp_jose(
            token,
            p256_public_key,
            expected_nonce="cross-nonce",
            expected_audience="did:web:verifier.test",
        )
        assert result["type"] == ["VerifiablePresentation"]


class TestPythonSDJWTNodeVerify:
    """Python issues SD-JWT-VC → Node.js verifies the issuer JWT signature."""

    def test_sd_jwt_signature_interop(self, p256_private_key):
        """Python-issued SD-JWT-VC can be signature-verified by Node.js."""
        claims = {"iss": "did:web:test", "name": "Test"}
        sd_jwt = issue_sd_jwt_vc(
            claims,
            p256_private_key,
            vct="https://example.com/vc",
            disclosable=["name"],
        )
        # Extract issuer JWT (first part before ~)
        issuer_jwt = sd_jwt.split("~")[0]
        fixture = json.loads((KEYS_DIR / "test-keypair-p256.json").read_text())
        pub_jwk = {
            "kty": fixture["kty"],
            "crv": fixture["crv"],
            "x": fixture["x"],
            "y": fixture["y"],
        }

        script = f"""
import {{ compactVerify, importJWK }} from "jose";
const key = await importJWK({json.dumps(pub_jwk)}, "ES256");
const result = await compactVerify("{issuer_jwt}", key);
const header = JSON.parse(Buffer.from("{issuer_jwt}".split(".")[0], "base64url").toString());
if (header.typ !== "vc+sd-jwt") throw new Error("wrong typ: " + header.typ);
const payload = JSON.parse(new TextDecoder().decode(result.payload));
if (payload.vct !== "https://example.com/vc") throw new Error("wrong vct");
console.log("OK");
"""
        assert _run_node(script) == "OK"


class TestNodeSDJWTPythonVerify:
    """Node.js issues SD-JWT-VC → Python verifies it."""

    def test_sd_jwt_from_node(self, p256_public_key):
        """Node-issued SD-JWT-VC can be verified by Python."""
        fixture = json.loads((KEYS_DIR / "test-keypair-p256.json").read_text())

        script = f"""
import {{ CompactSign, importJWK }} from "jose";
const jwk = {json.dumps(fixture)};
const key = await importJWK(jwk, "ES256");
const payload = new TextEncoder().encode(JSON.stringify({{
  vct: "https://example.com/vc",
  iss: "did:web:node-issuer",
  name: "NodeTest"
}}));
const signer = new CompactSign(payload);
signer.setProtectedHeader({{ alg: "ES256", typ: "vc+sd-jwt" }});
const token = await signer.sign(key);
// Output as SD-JWT (issuer-jwt with trailing ~)
console.log(token + "~");
"""
        sd_jwt = _run_node(script)
        result = verify_sd_jwt_vc(sd_jwt, p256_public_key)
        assert result["iss"] == "did:web:node-issuer"
        assert result["vct"] == "https://example.com/vc"
