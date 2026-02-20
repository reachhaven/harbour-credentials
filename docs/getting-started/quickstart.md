# Quick Start

This guide gets you signing and verifying credentials in minutes.

## 1. Generate a Keypair

=== "Python"

    ```python
    from harbour.keys import generate_p256_keypair, p256_public_key_to_did_key

    private_key, public_key = generate_p256_keypair()
    did = p256_public_key_to_did_key(public_key)
    print(f"DID: {did}")
    ```

=== "TypeScript"

    ```typescript
    import { generateP256Keypair, p256PublicKeyToDid } from '@reachhaven/harbour-credentials';

    const { privateKey, publicKey } = await generateP256Keypair();
    const did = await p256PublicKeyToDid(publicKey);
    console.log(`DID: ${did}`);
    ```

=== "CLI"

    ```bash
    python -m harbour.keys generate --curve p256 --output keypair.json
    ```

## 2. Sign a Credential

=== "Python"

    ```python
    from harbour.signer import sign_vc_jose

    credential = {
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential"],
        "issuer": did,
        "credentialSubject": {
            "id": "did:example:subject",
            "name": "Alice"
        }
    }

    jwt = sign_vc_jose(credential, private_key, kid=f"{did}#{did.split(':')[-1]}")
    print(jwt)
    ```

=== "TypeScript"

    ```typescript
    import { signJwt } from '@reachhaven/harbour-credentials';

    const credential = {
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        type: ['VerifiableCredential'],
        issuer: did,
        credentialSubject: {
            id: 'did:example:subject',
            name: 'Alice'
        }
    };

    const jwt = await signJwt(credential, privateKey);
    console.log(jwt);
    ```

## 3. Verify a Credential

=== "Python"

    ```python
    from harbour.verifier import verify_vc_jose

    result = verify_vc_jose(jwt, public_key)
    print(f"Verified: {result['credentialSubject']['name']}")
    ```

=== "TypeScript"

    ```typescript
    import { verifyJwt } from '@reachhaven/harbour-credentials';

    const result = await verifyJwt(jwt, publicKey);
    console.log(`Verified: ${result.credentialSubject.name}`);
    ```

## 4. Selective Disclosure (SD-JWT)

=== "Python"

    ```python
    from harbour.sd_jwt import issue_sd_jwt_vc, verify_sd_jwt_vc

    # Issue with selective disclosure
    sd_jwt = issue_sd_jwt_vc(
        credential,
        private_key,
        disclosable_claims=["name", "email"]
    )

    # Verify
    result = verify_sd_jwt_vc(sd_jwt, public_key)
    ```

=== "TypeScript"

    ```typescript
    import { issueSdJwt, verifySdJwt } from '@reachhaven/harbour-credentials';

    const sdJwt = await issueSdJwt(credential, privateKey, {
        disclosableClaims: ['name', 'email']
    });

    const result = await verifySdJwt(sdJwt, publicKey);
    ```

## Next Steps

- [Key Management](../guide/keys.md) — Advanced key operations
- [SD-JWT Guide](../guide/sd-jwt.md) — Selective disclosure in depth
- [CLI Reference](../cli/index.md) — Command-line tools
