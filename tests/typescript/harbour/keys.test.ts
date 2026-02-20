import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  generateP256Keypair,
  generateEd25519Keypair,
  p256KeypairToJwk,
  p256PublicKeyToJwk,
  p256PublicKeyToMultibase,
  p256PublicKeyToDidKey,
  ed25519KeypairToJwk,
  ed25519PublicKeyToJwk,
  ed25519PublicKeyToMultibase,
  ed25519PublicKeyToDidKey,
  importP256PrivateKey,
  importP256PublicKey,
} from "../../../src/typescript/harbour/keys.js";

const FIXTURES_DIR = resolve(__dirname, "../../fixtures");

describe("P-256 keys", () => {
  it("generates a keypair", async () => {
    const { privateKey, publicKey } = await generateP256Keypair();
    expect(privateKey.algorithm.name).toBe("ECDSA");
    expect(publicKey.algorithm.name).toBe("ECDSA");
  });

  it("exports private JWK with correct fields", async () => {
    const { privateKey } = await generateP256Keypair();
    const jwk = await p256KeypairToJwk(privateKey);
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    expect(jwk.x).toBeTruthy();
    expect(jwk.y).toBeTruthy();
    expect(jwk.d).toBeTruthy();
  });

  it("exports public JWK without d", async () => {
    const { publicKey } = await generateP256Keypair();
    const jwk = await p256PublicKeyToJwk(publicKey);
    expect(jwk.kty).toBe("EC");
    expect(jwk.crv).toBe("P-256");
    expect(jwk.d).toBeUndefined();
  });

  it("produces multibase starting with zDn", async () => {
    const { publicKey } = await generateP256Keypair();
    const mb = await p256PublicKeyToMultibase(publicKey);
    expect(mb).toMatch(/^zDn/);
    expect(mb.length).toBeGreaterThan(40);
  });

  it("produces deterministic multibase", async () => {
    const { publicKey } = await generateP256Keypair();
    const mb1 = await p256PublicKeyToMultibase(publicKey);
    const mb2 = await p256PublicKeyToMultibase(publicKey);
    expect(mb1).toBe(mb2);
  });

  it("produces did:key:zDn...", async () => {
    const { publicKey } = await generateP256Keypair();
    const did = await p256PublicKeyToDidKey(publicKey);
    expect(did).toMatch(/^did:key:zDn/);
  });

  it("roundtrips JWK from test fixture", async () => {
    const fixture = JSON.parse(
      readFileSync(resolve(FIXTURES_DIR, "test-keypair-p256.json"), "utf-8"),
    );
    const privateKey = await importP256PrivateKey(fixture);
    const publicKey = await importP256PublicKey(fixture);
    const jwk = await p256KeypairToJwk(privateKey);
    expect(jwk.x).toBe(fixture.x);
    expect(jwk.y).toBe(fixture.y);
    const pubJwk = await p256PublicKeyToJwk(publicKey);
    expect(pubJwk.x).toBe(fixture.x);
    expect(pubJwk.y).toBe(fixture.y);
  });
});

describe("Ed25519 keys", () => {
  it("generates a keypair", async () => {
    const { privateKey, publicKey } = await generateEd25519Keypair();
    expect(privateKey.algorithm.name).toBe("Ed25519");
    expect(publicKey.algorithm.name).toBe("Ed25519");
  });

  it("exports private JWK with correct fields", async () => {
    const { privateKey } = await generateEd25519Keypair();
    const jwk = await ed25519KeypairToJwk(privateKey);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.x).toBeTruthy();
    expect(jwk.d).toBeTruthy();
  });

  it("exports public JWK without d", async () => {
    const { publicKey } = await generateEd25519Keypair();
    const jwk = await ed25519PublicKeyToJwk(publicKey);
    expect(jwk.kty).toBe("OKP");
    expect(jwk.crv).toBe("Ed25519");
    expect(jwk.d).toBeUndefined();
  });

  it("produces multibase starting with z6Mk", async () => {
    const { publicKey } = await generateEd25519Keypair();
    const mb = await ed25519PublicKeyToMultibase(publicKey);
    expect(mb).toMatch(/^z6Mk/);
    expect(mb.length).toBeGreaterThan(40);
  });

  it("produces did:key:z6Mk...", async () => {
    const { publicKey } = await generateEd25519Keypair();
    const did = await ed25519PublicKeyToDidKey(publicKey);
    expect(did).toMatch(/^did:key:z6Mk/);
  });
});
