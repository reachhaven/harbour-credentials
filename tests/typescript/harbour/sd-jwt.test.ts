import { describe, it, expect, beforeAll } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { CompactSign } from "jose";
import {
  buildSdJwtPayload,
  issueSdJwtVc,
  NON_DISCLOSABLE_CLAIMS,
  signSdJwt,
  verifySdJwtVc,
} from "../../../src/typescript/harbour/sd-jwt.js";
import { VerificationError } from "../../../src/typescript/harbour/verifier.js";
import {
  importP256PrivateKey,
  importP256PublicKey,
  generateP256Keypair,
  p256PublicKeyToJwk,
} from "../../../src/typescript/harbour/keys.js";

const FIXTURES_DIR = resolve(__dirname, "../../fixtures");
const VCT =
  "https://w3id.org/reachhaven/harbour/core/v1/LegalPersonCredential";

const SAMPLE_CLAIMS = {
  iss: "did:ethr:0x14a34:0x212025b9751231b17ead53fdcaad8ddeffa0106c",
  iat: 1723972522,
  legalName: "Example Corporation GmbH",
  legalForm: "GmbH",
  countryCode: "DE",
  email: "info@example.com",
};

let privateKey: CryptoKey;
let publicKey: CryptoKey;

function joseHeader(sdJwt: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(sdJwt.split(".")[0], "base64url").toString());
}

/** Mint an SD-JWT with an arbitrary typ header (no disclosures). */
async function signWithTyp(typ: string): Promise<string> {
  const payload = new TextEncoder().encode(
    JSON.stringify({ ...SAMPLE_CLAIMS, vct: VCT }),
  );
  const signer = new CompactSign(payload);
  signer.setProtectedHeader({ alg: "ES256", typ });
  return (await signer.sign(privateKey)) + "~";
}

beforeAll(async () => {
  const fixture = JSON.parse(
    readFileSync(resolve(FIXTURES_DIR, "keys", "test-keypair-p256.json"), "utf-8"),
  );
  privateKey = await importP256PrivateKey(fixture);
  publicKey = await importP256PublicKey(fixture);
});

describe("SD-JWT-VC issuance", () => {
  it("produces ~-delimited format", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    const parts = sdJwt.split("~");
    expect(parts.length).toBeGreaterThanOrEqual(2);
    expect(parts[parts.length - 1]).toBe(""); // trailing ~
    expect(parts[0].split(".")).toHaveLength(3); // issuer JWT
  });

  it("uses the dc+sd-jwt typ header", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    expect(joseHeader(sdJwt).typ).toBe("dc+sd-jwt");
  });

  it("creates disclosures for disclosable claims", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: ["email", "countryCode"],
    });
    const parts = sdJwt.split("~");
    // issuer-jwt + 2 disclosures + trailing empty = 4 parts
    expect(parts).toHaveLength(4);
  });
});

describe("SD-JWT-VC verification", () => {
  it("returns all claims when no selective disclosure", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.vct).toBe(VCT);
    expect(result.legalName).toBe("Example Corporation GmbH");
  });

  it("returns disclosed claims with selective disclosure", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: ["email", "countryCode"],
    });
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.email).toBe("info@example.com");
    expect(result.countryCode).toBe("DE");
    expect(result.legalName).toBe("Example Corporation GmbH");
  });

  it("throws on wrong key", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    const { publicKey: wrongKey } = await generateP256Keypair();
    await expect(verifySdJwtVc(sdJwt, wrongKey)).rejects.toThrow(
      VerificationError,
    );
  });

  it("accepts the legacy vc+sd-jwt typ during transition", async () => {
    const legacy = await signWithTyp("vc+sd-jwt");
    const result = await verifySdJwtVc(legacy, publicKey);
    expect(result.vct).toBe(VCT);
  });

  it("throws on an unknown typ", async () => {
    const token = await signWithTyp("JWT");
    await expect(verifySdJwtVc(token, publicKey)).rejects.toThrow(
      /Unexpected typ/,
    );
  });

  it("throws on VCT mismatch", async () => {
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    await expect(
      verifySdJwtVc(sdJwt, publicKey, { expectedVct: "https://wrong.example.com" }),
    ).rejects.toThrow(VerificationError);
  });

  it("includes cnf when provided", async () => {
    const pubJwk = await p256PublicKeyToJwk(publicKey);
    const sdJwt = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, {
      vct: VCT,
      cnf: { jwk: pubJwk },
    });
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.cnf).toBeDefined();
    expect((result.cnf as any).jwk.crv).toBe("P-256");
  });
});

const NESTED_CLAIMS = {
  iss: "did:web:harbour.example:participants:acme",
  credentialSubject: {
    id: "urn:uuid:5f1c2c6e-3d7a-4c39-9a52-1e0f6b1d2a11",
    email: "alice@example.com",
    "harbour.gx:labelLevel": "BL",
    address: { "gx:countryCode": "DE", "gx:postalCode": "80331" },
  },
};

function rawPayload(sdJwt: string): Record<string, any> {
  return JSON.parse(
    Buffer.from(sdJwt.split("~")[0].split(".")[1], "base64url").toString(),
  );
}

describe("SD-JWT-VC structured disclosure", () => {
  it("places _sd digests at the nested level and restores them", async () => {
    const sdJwt = await issueSdJwtVc(NESTED_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: [
        "credentialSubject.email",
        "credentialSubject.address.gx:postalCode",
      ],
    });
    const raw = rawPayload(sdJwt);
    expect(raw.credentialSubject.email).toBeUndefined();
    expect(raw.credentialSubject._sd).toHaveLength(1);
    expect(raw.credentialSubject.address._sd).toHaveLength(1);
    expect(raw._sd_alg).toBe("sha-256");
    expect(raw.credentialSubject._sd_alg).toBeUndefined();

    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result).toEqual({ ...NESTED_CLAIMS, vct: VCT });
  });

  it("omits withheld nested disclosures", async () => {
    const sdJwt = await issueSdJwtVc(NESTED_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: ["credentialSubject.email"],
    });
    const [jwt] = sdJwt.split("~");
    const result = await verifySdJwtVc(`${jwt}~`, publicKey);
    expect((result.credentialSubject as any).email).toBeUndefined();
    expect((result.credentialSubject as any).id).toBe(NESTED_CLAIMS.credentialSubject.id);
  });

  it("handles keys containing dots with segment-list paths", async () => {
    const sdJwt = await issueSdJwtVc(NESTED_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: [["credentialSubject", "harbour.gx:labelLevel"]],
    });
    expect(rawPayload(sdJwt).credentialSubject["harbour.gx:labelLevel"]).toBeUndefined();
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect((result.credentialSubject as any)["harbour.gx:labelLevel"]).toBe("BL");
  });

  it("throws on a declared path that does not resolve", async () => {
    await expect(
      issueSdJwtVc(NESTED_CLAIMS, privateKey, {
        vct: VCT,
        disclosable: ["credentialSubject.nonexistent"],
      }),
    ).rejects.toThrow(/disclosable path not found/);
  });

  it("rejects a disclosure whose digest is not in the payload", async () => {
    const a = await issueSdJwtVc(NESTED_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: ["credentialSubject.email"],
    });
    const b = await issueSdJwtVc(NESTED_CLAIMS, privateKey, {
      vct: VCT,
      disclosable: ["credentialSubject.email"],
    });
    const forged = `${a.split("~")[0]}~${b.split("~")[1]}~`;
    await expect(verifySdJwtVc(forged, publicKey)).rejects.toThrow(VerificationError);
  });
});

describe("SD-JWT-VC reserved claims", () => {
  for (const claim of [...NON_DISCLOSABLE_CLAIMS].filter((c) => c !== "_sd")) {
    it(`rejects making '${claim}' selectively disclosable`, async () => {
      await expect(
        issueSdJwtVc({ ...SAMPLE_CLAIMS, [claim]: "x" }, privateKey, {
          vct: VCT,
          disclosable: [claim],
        }),
      ).rejects.toThrow(/must not be selectively disclosable/);
    });
  }

  it("allows a reserved name below the top level", async () => {
    const sdJwt = await issueSdJwtVc({ address: { status: "verified" } }, privateKey, {
      vct: VCT,
      disclosable: ["address.status"],
    });
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.address).toEqual({ status: "verified" });
  });
});

describe("SD-JWT-VC disclosable path validation", () => {
  for (const path of ["status.status_list", "cnf.jwk"]) {
    it(`rejects disclosing '${path}' under a reserved claim`, () => {
      const claims = {
        status: { status_list: { idx: 0, uri: "https://example.com/sl" } },
        cnf: { jwk: { kty: "EC" } },
      };
      expect(() => buildSdJwtPayload(claims, { vct: VCT, disclosable: [path] })).toThrow(
        /must not be selectively disclosable, nor any of its members/,
      );
    });
  }

  for (const path of ["__proto__.isPrototypeOf", "constructor.prototype.isPrototypeOf", "toString"]) {
    it(`does not follow inherited properties ('${path}')`, () => {
      expect(() =>
        buildSdJwtPayload({ a: 1 }, { vct: VCT, disclosable: [path] }),
      ).toThrow(/disclosable path not found/);
      expect(Object.hasOwn(Object.prototype, "_sd")).toBe(false);
      expect(Object.hasOwn(Object.prototype, "isPrototypeOf")).toBe(true);
    });
  }

  for (const path of ["roles.0", "addresses.0.city"]) {
    it(`rejects array paths ('${path}')`, () => {
      const claims = { roles: ["admin"], addresses: [{ city: "Munich" }] };
      expect(() => buildSdJwtPayload(claims, { vct: VCT, disclosable: [path] })).toThrow(
        /traverses an array/,
      );
    });
  }

  for (const disclosable of [
    ["address.city", "address"],
    ["address", "address.city"],
    ["address.city", "address.city"],
  ]) {
    it(`rejects overlapping paths ${JSON.stringify(disclosable)}`, () => {
      expect(() =>
        buildSdJwtPayload({ address: { city: "Munich" } }, { vct: VCT, disclosable }),
      ).toThrow(/overlapping disclosable paths/);
    });
  }

  it("allows sibling paths sharing a parent", async () => {
    const sdJwt = await issueSdJwtVc(
      { address: { city: "Munich", zip: "80331" } },
      privateKey,
      { vct: VCT, disclosable: ["address.city", "address.zip"] },
    );
    const result = await verifySdJwtVc(sdJwt, publicKey);
    expect(result.address).toEqual({ city: "Munich", zip: "80331" });
  });
});

describe("SD-JWT-VC build and sign", () => {
  it("signs exactly the built payload", async () => {
    const { payload, disclosures } = buildSdJwtPayload(SAMPLE_CLAIMS, {
      vct: VCT,
      disclosable: ["email"],
    });
    const sdJwt = await signSdJwt(payload, disclosures, privateKey);
    expect(rawPayload(sdJwt)).toEqual(payload);
    expect(sdJwt.split("~").slice(1, -1)).toEqual(disclosures);
  });

  it("does not mutate the input claims", () => {
    const claims = { address: { city: "Munich" } };
    buildSdJwtPayload(claims, { vct: VCT, disclosable: ["address.city"] });
    expect(claims).toEqual({ address: { city: "Munich" } });
  });

  it("sets kid only when given", async () => {
    const kid = "did:web:harbour.example:participants:acme#key-1";
    const withKid = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT, kid });
    expect(joseHeader(withKid).kid).toBe(kid);
    const without = await issueSdJwtVc(SAMPLE_CLAIMS, privateKey, { vct: VCT });
    expect(joseHeader(without).kid).toBeUndefined();
  });
});
