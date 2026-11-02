import { SDJwtVcInstance, type SDJWTVCConfig } from '@sd-jwt/sd-jwt-vc';
import {
  b64uDecode,
  b64uEncode,
  jwkThumbprint,
  randomToken,
  sha256,
  utf8,
  verifyEs256,
  type Jwk,
  type JwsSigner,
} from './jose.js';

// Shared SD-JWT VC plumbing. The OpenWallet Foundation library does the format
// work; we only supply WebCrypto-backed hasher, salts and ES256 callbacks.

export const SD_JWT_VC_FORMAT = 'dc+sd-jwt';
export const SD_JWT_VC_TYP = 'dc+sd-jwt';

export async function hasher(data: string | ArrayBuffer, alg: string): Promise<Uint8Array> {
  if (alg.toLowerCase() !== 'sha-256') throw new Error(`unsupported hash ${alg}`);
  return sha256(typeof data === 'string' ? utf8(data) : new Uint8Array(data));
}

export const saltGenerator = (length: number): string => randomToken(length);

export function sdSigner(signer: JwsSigner): (data: string) => Promise<string> {
  return async (data) => b64uEncode(await signer.sign(utf8(data)));
}

export function sdVerifier(publicJwk: Jwk): (data: string, sig: string) => Promise<boolean> {
  return (data, sig) => verifyEs256(publicJwk, utf8(data), b64uDecode(sig));
}

export function sdJwtVc(config: SDJWTVCConfig = {}): SDJwtVcInstance {
  return new SDJwtVcInstance({
    hasher,
    saltGenerator,
    hashAlg: 'sha-256',
    signAlg: 'ES256',
    kbSignAlg: 'ES256',
    ...config,
  });
}

/** Issuer-signed part of a compact SD-JWT (everything before the first '~'). */
export function issuerJwtOf(compact: string): string {
  return compact.split('~')[0]!;
}

/**
 * Per-site subject identifier (FFN v1 doc, "Per-site identifiers").
 *
 * Derived from the holder key and the site's client_id, so a site can recompute
 * and trust it, and two sites see different values. v1 uses one holder key for
 * all sites, so this is no stronger than the key itself; batch issuance (one key
 * per site) makes it properly pairwise with no change to this function.
 */
export async function subjectIdFor(holderJwk: Jwk, clientId: string): Promise<string> {
  const thumb = await jwkThumbprint(holderJwk);
  return b64uEncode(await sha256(`ffn-subject-v1|${thumb}|${clientId}`));
}
