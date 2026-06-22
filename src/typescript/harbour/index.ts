export {
  // P-256 keys
  generateP256Keypair,
  p256KeypairToJwk,
  p256PublicKeyToJwk,
  p256PublicKeyToDidKey,
  p256PublicKeyToMultibase,
  importP256PrivateKey,
  importP256PublicKey,
  // Ed25519 keys
  generateEd25519Keypair,
  ed25519KeypairToJwk,
  ed25519PublicKeyToJwk,
  ed25519PublicKeyToDidKey,
  ed25519PublicKeyToMultibase,
  importEd25519PrivateKey,
  importEd25519PublicKey,
  // Types
  type JWK,
} from "./keys.js";

export { signVcJose, signVpJose, type SignOptions, type VpSignOptions } from "./signer.js";

export {
  verifyVcJose,
  verifyVpJose,
  VerificationError,
  type VpVerifyOptions,
} from "./verifier.js";

export {
  issueSdJwtVc,
  verifySdJwtVc,
  buildSdJwtPayload,
  signSdJwt,
} from "./sd-jwt.js";

export {
  computeLeaf,
  hashNode,
  merkleRoot,
  merkleRootB64url,
  inclusionProof,
  verifyInclusion,
  buildBatch,
  b64urlEncode,
  b64urlDecode,
  type MerkleProofStep,
} from "./merkle.js";

export {
  AUTHORIZATION_JWT_TYP,
  EVIDENCE_TYPE,
  signAuthorization,
  verifyAuthorization,
  buildBatchEvidence,
  verifyBatchEvidence,
  type BatchEvidence,
  type AuthorizationOptions,
} from "./batch-evidence.js";

export { derToX5c, x5cToDer, importPublicKeyFromX5c } from "./x509.js";

export {
  createKbJwt,
  verifyKbJwt,
  KbJwtVerificationError,
  type KbJwtOptions,
  type KbJwtPayload,
  type KbJwtVerifyOptions,
} from "./kb-jwt.js";

export {
  ACTION_TYPE,
  TYPE_PREFIX,
  ACTION_LABELS,
  ChallengeError,
  getAction,
  toCanonicalJson,
  computeTransactionHash,
  createDelegationChallenge,
  parseDelegationChallenge,
  verifyChallenge,
  createTransactionData,
  renderTransactionDisplay,
  validateTransactionData,
  type TransactionData,
} from "./delegation.js";

export {
  issueSdJwtVp,
  verifySdJwtVp,
  type IssueSdJwtVpOptions,
  type VerifySdJwtVpOptions,
  type SdJwtVpResult,
} from "./sd-jwt-vp.js";

export {
  canonicalJson,
  computeDigestSri,
  parseDigestSri,
  verifyDigestSri,
  DigestSriError,
  type SriAlgorithm,
} from "./digest-sri.js";
