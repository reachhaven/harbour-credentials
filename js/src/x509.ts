/**
 * X.509 certificate utilities for EUDI-compliant VC signing.
 *
 * Provides helpers for encoding/decoding x5c certificate chains in JOSE headers.
 * Note: Full X.509 certificate generation requires Node.js crypto or external
 * libraries. This module focuses on the x5c encoding/decoding needed for
 * SD-JWT-VC and VC-JOSE-COSE interoperability.
 */

/**
 * Encode DER certificate bytes as x5c header value (base64, NOT base64url).
 */
export function derToX5c(derCerts: Uint8Array[]): string[] {
  return derCerts.map((der) => Buffer.from(der).toString("base64"));
}

/**
 * Decode an x5c header value back to DER certificate bytes.
 */
export function x5cToDer(x5c: string[]): Uint8Array[] {
  return x5c.map((b64) => new Uint8Array(Buffer.from(b64, "base64")));
}

/**
 * Extract the SubjectPublicKeyInfo from the first (leaf) certificate in an x5c chain.
 *
 * This parses enough of the DER/ASN.1 to find the SubjectPublicKeyInfo structure,
 * which can then be imported as a CryptoKey via WebCrypto.
 *
 * For P-256 keys, the SPKI contains the algorithm OID and the public key point.
 */
export async function importPublicKeyFromX5c(
  x5c: string[],
  algorithm: AlgorithmIdentifier | EcKeyImportParams = {
    name: "ECDSA",
    namedCurve: "P-256",
  },
): Promise<CryptoKey> {
  if (x5c.length === 0) {
    throw new Error("Empty x5c chain");
  }

  const der = Buffer.from(x5c[0], "base64");

  // Extract SPKI from X.509 certificate DER
  const spki = extractSpkiFromCert(der);

  return crypto.subtle.importKey("spki", spki, algorithm, true, ["verify"]);
}

/**
 * Extract SubjectPublicKeyInfo from an X.509 certificate DER encoding.
 *
 * X.509 Certificate structure (simplified):
 *   SEQUENCE {
 *     SEQUENCE {  -- TBSCertificate
 *       [0] version
 *       INTEGER serialNumber
 *       SEQUENCE signature algorithm
 *       SEQUENCE issuer
 *       SEQUENCE validity
 *       SEQUENCE subject
 *       SEQUENCE subjectPublicKeyInfo  <-- we want this
 *       ...
 *     }
 *     ...
 *   }
 */
function extractSpkiFromCert(der: Buffer): ArrayBuffer {
  let offset = 0;

  // Parse outer SEQUENCE
  const outer = parseTag(der, offset);
  offset = outer.contentOffset;

  // Parse TBSCertificate SEQUENCE
  const tbs = parseTag(der, offset);
  let tbsOffset = tbs.contentOffset;

  // [0] version (optional, context-specific tag 0xa0)
  if (der[tbsOffset] === 0xa0) {
    const version = parseTag(der, tbsOffset);
    tbsOffset = version.contentOffset + version.contentLength;
  }

  // serialNumber (INTEGER)
  const serial = parseTag(der, tbsOffset);
  tbsOffset = serial.contentOffset + serial.contentLength;

  // signature algorithm (SEQUENCE)
  const sigAlg = parseTag(der, tbsOffset);
  tbsOffset = sigAlg.contentOffset + sigAlg.contentLength;

  // issuer (SEQUENCE)
  const issuer = parseTag(der, tbsOffset);
  tbsOffset = issuer.contentOffset + issuer.contentLength;

  // validity (SEQUENCE)
  const validity = parseTag(der, tbsOffset);
  tbsOffset = validity.contentOffset + validity.contentLength;

  // subject (SEQUENCE)
  const subject = parseTag(der, tbsOffset);
  tbsOffset = subject.contentOffset + subject.contentLength;

  // subjectPublicKeyInfo (SEQUENCE) - this is what we want
  const spki = parseTag(der, tbsOffset);
  const spkiStart = tbsOffset;
  const spkiEnd = spki.contentOffset + spki.contentLength;

  return der.buffer.slice(
    der.byteOffset + spkiStart,
    der.byteOffset + spkiEnd,
  );
}

interface ParsedTag {
  tag: number;
  contentOffset: number;
  contentLength: number;
}

function parseTag(der: Buffer, offset: number): ParsedTag {
  const tag = der[offset];
  let lenOffset = offset + 1;
  let contentLength: number;

  if (der[lenOffset] < 0x80) {
    contentLength = der[lenOffset];
    lenOffset += 1;
  } else {
    const numLenBytes = der[lenOffset] & 0x7f;
    contentLength = 0;
    for (let i = 0; i < numLenBytes; i++) {
      contentLength = (contentLength << 8) | der[lenOffset + 1 + i];
    }
    lenOffset += 1 + numLenBytes;
  }

  return { tag, contentOffset: lenOffset, contentLength };
}
