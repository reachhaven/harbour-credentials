/**
 * Key generation, DID-key encoding, and JWK export for P-256 and Ed25519.
 */

import * as jose from "jose";

// Multicodec prefixes (varint-encoded)
const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]); // p256-pub 0x1200
const ED25519_MULTICODEC_PREFIX = new Uint8Array([0xed, 0x01]); // ed25519-pub 0xed

// Base58btc alphabet (Bitcoin)
const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export interface JWK {
  kty: string;
  crv: string;
  x: string;
  y?: string;
  d?: string;
}

// ---------------------------------------------------------------------------
// P-256 (ES256) keys
// ---------------------------------------------------------------------------

export async function generateP256Keypair(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
}

export async function p256KeypairToJwk(privateKey: CryptoKey): Promise<JWK> {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return {
    kty: jwk.kty!,
    crv: jwk.crv!,
    x: jwk.x!,
    y: jwk.y!,
    d: jwk.d!,
  };
}

export async function p256PublicKeyToJwk(publicKey: CryptoKey): Promise<JWK> {
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  return {
    kty: jwk.kty!,
    crv: jwk.crv!,
    x: jwk.x!,
    y: jwk.y!,
  };
}

export async function p256PublicKeyToDidKey(
  publicKey: CryptoKey,
): Promise<string> {
  const mb = await p256PublicKeyToMultibase(publicKey);
  return `did:key:${mb}`;
}

export async function p256PublicKeyToMultibase(
  publicKey: CryptoKey,
): Promise<string> {
  // Export as raw (uncompressed SEC1: 04 || x || y, 65 bytes)
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", publicKey),
  );
  // Compress: 02/03 prefix + x coordinate (33 bytes)
  const compressed = compressP256(raw);
  const prefixed = new Uint8Array(
    P256_MULTICODEC_PREFIX.length + compressed.length,
  );
  prefixed.set(P256_MULTICODEC_PREFIX);
  prefixed.set(compressed, P256_MULTICODEC_PREFIX.length);
  return "z" + base58btcEncode(prefixed);
}

// ---------------------------------------------------------------------------
// Ed25519 keys
// ---------------------------------------------------------------------------

export async function generateEd25519Keypair(): Promise<{
  privateKey: CryptoKey;
  publicKey: CryptoKey;
}> {
  const keyPair = await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ]);
  return { privateKey: keyPair.privateKey, publicKey: keyPair.publicKey };
}

export async function ed25519KeypairToJwk(
  privateKey: CryptoKey,
): Promise<JWK> {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return {
    kty: jwk.kty!,
    crv: jwk.crv!,
    x: jwk.x!,
    d: jwk.d!,
  };
}

export async function ed25519PublicKeyToJwk(
  publicKey: CryptoKey,
): Promise<JWK> {
  const jwk = await crypto.subtle.exportKey("jwk", publicKey);
  return { kty: jwk.kty!, crv: jwk.crv!, x: jwk.x! };
}

export async function ed25519PublicKeyToDidKey(
  publicKey: CryptoKey,
): Promise<string> {
  const mb = await ed25519PublicKeyToMultibase(publicKey);
  return `did:key:${mb}`;
}

export async function ed25519PublicKeyToMultibase(
  publicKey: CryptoKey,
): Promise<string> {
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", publicKey),
  );
  const prefixed = new Uint8Array(
    ED25519_MULTICODEC_PREFIX.length + raw.length,
  );
  prefixed.set(ED25519_MULTICODEC_PREFIX);
  prefixed.set(raw, ED25519_MULTICODEC_PREFIX.length);
  return "z" + base58btcEncode(prefixed);
}

// ---------------------------------------------------------------------------
// JWK import helpers (for loading test fixtures)
// ---------------------------------------------------------------------------

export async function importP256PrivateKey(jwk: JWK): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { ...jwk, key_ops: ["sign"] },
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign"],
  );
}

export async function importP256PublicKey(jwk: JWK): Promise<CryptoKey> {
  const { d, ...publicJwk } = jwk;
  return crypto.subtle.importKey(
    "jwk",
    { ...publicJwk, key_ops: ["verify"] },
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"],
  );
}

export async function importEd25519PrivateKey(jwk: JWK): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "jwk",
    { ...jwk, key_ops: ["sign"] },
    "Ed25519",
    true,
    ["sign"],
  );
}

export async function importEd25519PublicKey(jwk: JWK): Promise<CryptoKey> {
  const { d, ...publicJwk } = jwk;
  return crypto.subtle.importKey(
    "jwk",
    { ...publicJwk, key_ops: ["verify"] },
    "Ed25519",
    true,
    ["verify"],
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compressP256(uncompressed: Uint8Array): Uint8Array {
  // Uncompressed format: 04 || x (32 bytes) || y (32 bytes)
  if (uncompressed[0] !== 0x04 || uncompressed.length !== 65) {
    throw new Error("Expected uncompressed P-256 key (65 bytes, 04 prefix)");
  }
  const x = uncompressed.slice(1, 33);
  const yLastByte = uncompressed[64];
  const prefix = yLastByte % 2 === 0 ? 0x02 : 0x03;
  const compressed = new Uint8Array(33);
  compressed[0] = prefix;
  compressed.set(x, 1);
  return compressed;
}

function base58btcEncode(bytes: Uint8Array): string {
  // Count leading zeros
  let zeros = 0;
  for (const b of bytes) {
    if (b === 0) zeros++;
    else break;
  }

  // Convert to base58
  const result: number[] = [];
  let num = BigInt("0x" + Buffer.from(bytes).toString("hex"));
  const base = BigInt(58);
  while (num > 0n) {
    const [div, mod] = [num / base, num % base];
    result.unshift(Number(mod));
    num = div;
  }

  return (
    BASE58_ALPHABET[0].repeat(zeros) +
    result.map((i) => BASE58_ALPHABET[i]).join("")
  );
}
