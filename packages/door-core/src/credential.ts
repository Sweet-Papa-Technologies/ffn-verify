import type { DidResolver } from './did-web.js';
import {
  b64uDecode,
  b64uEncode,
  decodeJwt,
  jwkThumbprint,
  sha256,
  utf8,
  verifyEs256,
  type Jwk,
  type JwsSigner,
} from './jose.js';
import { issuerJwtOf, sdJwtVc, sdSigner, sdVerifier } from './sdjwt.js';

// Signing and verifying SD-JWT VCs outside the OpenID4VC flows: a business
// signing its own profile in the wallet, SPT signing an attestation for the
// registry, an agent presenting a delegation over plain HTTP. Same format and
// keys as the person path; no wallet or trust registry needed to check one.

export interface SignCredentialInput {
  signer: JwsSigner;
  /** Payload claims; iss, vct and cnf are required. */
  payload: Record<string, unknown> & { iss: string; vct: string; cnf: { jwk: Jwk } };
  /** SD-JWT disclosure frame. Omit to disclose everything (business facts are public). */
  frame?: Record<string, unknown>;
}

export async function signCredential(input: SignCredentialInput): Promise<string> {
  const { kty, crv, x, y } = input.payload.cnf.jwk;
  const sdjwt = sdJwtVc({ signer: sdSigner(input.signer) });
  return sdjwt.issue({ ...input.payload, cnf: { jwk: { kty, crv, x, y } } }, input.frame as never, {
    header: { kid: input.signer.kid },
  });
}

export class CredentialError extends Error {
  constructor(
    message: string,
    readonly code: string = 'invalid_credential',
  ) {
    super(message);
    this.name = 'CredentialError';
  }
}

export interface VerifiedSdJwt {
  header: Record<string, unknown>;
  /** Issuer-signed payload with every presented disclosure applied. */
  claims: Record<string, unknown>;
  iss: string;
  vct: string;
  cnfJwk: Jwk;
  /** The key that signed it, as resolved from the issuer DID. */
  issuerKey: Jwk;
  kb?: { aud: string; nonce: string; iat: number };
}

export interface VerifyCredentialOptions {
  resolver: DidResolver;
  /** Seconds since epoch (default now). */
  now?: number;
  skewSeconds?: number;
  /** Require a key-binding JWT over this nonce and audience. */
  keyBinding?: { nonce: string; audience: string; maxAgeSeconds?: number };
}

/** Base64url SHA-256 of the issuer-signed JWT: how a child delegation names its parent. */
export async function credentialHash(compact: string): Promise<string> {
  return b64uEncode(await sha256(issuerJwtOf(compact)));
}

/**
 * Verify the issuer signature (key from the issuer's DID document), every
 * disclosure, the time claims and, when asked, the holder's key binding.
 * Status is separate (see StatusChecker) because callers treat an unreachable
 * status list differently.
 */
export async function verifyCredential(
  compact: string,
  options: VerifyCredentialOptions,
): Promise<VerifiedSdJwt> {
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    ({ header, payload } = decodeJwt<Record<string, unknown>>(issuerJwtOf(compact)));
  } catch {
    throw new CredentialError('malformed credential');
  }
  const iss = payload.iss;
  const vct = payload.vct;
  if (typeof iss !== 'string' || typeof vct !== 'string')
    throw new CredentialError('credential has no issuer or type');
  if (header.alg !== 'ES256') throw new CredentialError('unsupported alg');
  const cnfJwk = (payload.cnf as { jwk?: Jwk } | undefined)?.jwk;
  if (!cnfJwk) throw new CredentialError('credential is not key-bound');

  let issuerKey: Jwk;
  try {
    issuerKey = await options.resolver.assertionKey(iss, header.kid as string | undefined);
  } catch (err) {
    throw new CredentialError(
      `issuer key not found: ${(err as Error).message}`,
      'untrusted_issuer',
    );
  }

  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.skewSeconds ?? 60;
  const sdjwt = sdJwtVc({
    verifier: sdVerifier(issuerKey),
    kbVerifier: (data, sig) => verifyEs256(cnfJwk, utf8(data), b64uDecode(sig)),
  });
  let verified;
  try {
    verified = await sdjwt.verify(compact, {
      ...(options.keyBinding
        ? {
            keyBindingNonce: options.keyBinding.nonce,
            expectedKeyBindingAudience: options.keyBinding.audience,
            keyBindingMaxAgeSeconds: options.keyBinding.maxAgeSeconds ?? 300,
          }
        : {}),
      currentDate: now,
      skewSeconds: skew,
      allowedIssuerAlgorithms: ['ES256'],
      allowedKeyBindingAlgorithms: ['ES256'],
      disableStatusVerification: true,
    } as never);
  } catch (err) {
    const message = (err as Error).message;
    throw new CredentialError(
      `credential failed verification: ${message}`,
      /\bis expired\b/.test(message) ? 'expired' : 'invalid_credential',
    );
  }
  // Belt and braces on time: the library's checks are option-dependent.
  if (typeof payload.exp === 'number' && now - skew > payload.exp)
    throw new CredentialError('credential expired', 'expired');
  if (typeof payload.nbf === 'number' && now + skew < payload.nbf)
    throw new CredentialError('credential not yet valid');

  let kb: VerifiedSdJwt['kb'];
  if (options.keyBinding) {
    const kbPayload = verified.kb?.payload as
      | { aud?: string; nonce?: string; iat?: number }
      | undefined;
    if (!kbPayload) throw new CredentialError('key binding missing');
    if (kbPayload.aud !== options.keyBinding.audience)
      throw new CredentialError('key binding audience mismatch');
    if (kbPayload.nonce !== options.keyBinding.nonce)
      throw new CredentialError('key binding nonce mismatch');
    const age = now - (kbPayload.iat ?? 0);
    if (age > (options.keyBinding.maxAgeSeconds ?? 300) + skew || age < -skew)
      throw new CredentialError('key binding is stale');
    kb = { aud: kbPayload.aud, nonce: kbPayload.nonce, iat: kbPayload.iat! };
  }
  const claims = (await sdjwt.getClaims(compact)) as Record<string, unknown>;
  return { header, claims, iss, vct, cnfJwk, issuerKey, ...(kb ? { kb } : {}) };
}

/** Same key? Thumbprints, so member order and extra members don't matter. */
export async function sameKey(a: Jwk, b: Jwk): Promise<boolean> {
  return (await jwkThumbprint(a)) === (await jwkThumbprint(b));
}
