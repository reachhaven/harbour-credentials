# TypeScript API Reference

This section documents the TypeScript API for Harbour Credentials.

## Installation

```bash
npm install @reachhaven/harbour-credentials
```

## Quick Import Reference

```typescript
import {
  // Key management
  generateP256Keypair,
  generateEd25519Keypair,
  p256PublicKeyToDid,
  ed25519PublicKeyToDid,
  privateKeyToJwk,
  publicKeyToJwk,
  
  // Signing
  signJwt,
  signVp,
  
  // Verification
  verifyJwt,
  verifyVp,
  
  // SD-JWT
  issueSdJwt,
  verifySdJwt,
  
  // KB-JWT
  createKbJwt,
  verifyKbJwt,
  
  // X.509
  generateSelfSignedCert,
  certToX5c,
  x5cToCert,
} from '@reachhaven/harbour-credentials';
```

## Type Definitions

```typescript
interface Keypair {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}

interface VerifiableCredential {
  '@context': string[];
  type: string[];
  issuer: string;
  credentialSubject: Record<string, unknown>;
  [key: string]: unknown;
}

interface SdJwtOptions {
  disclosableClaims?: string[];
  hashAlgorithm?: 'sha-256';
}

interface KbJwtOptions {
  nonce: string;
  audience: string;
  issuedAt?: number;
}
```

## Generated Documentation

Full TypeScript API documentation is generated with TypeDoc and available at:

- [TypeDoc API Reference](./typedoc/index.html)
