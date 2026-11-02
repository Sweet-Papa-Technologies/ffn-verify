// Minimal ES256 JOSE over WebCrypto. Runs unchanged in Node 22, Cloud Run and
// the browser wallet, so issuer, verifier and holder share one implementation.
//
// ES256 only: it is the HAIP / EUDI baseline and what Cloud KMS signs natively
// (EC_SIGN_P256_SHA256). WebCrypto ECDSA already emits the JOSE r||s format.

export type Jwk = JsonWebKey & { kid?: string; alg?: string; use?: string };

const subtle = () => globalThis.crypto.subtle;

export function b64uEncode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function b64uDecode(value: string): Uint8Array<ArrayBuffer> {
  const pad = value.length % 4 === 0 ? '' : '='.repeat(4 - (value.length % 4));
  const bin = atob(value.replace(/-/g, '+').replace(/_/g, '/') + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export const utf8 = (s: string): Uint8Array<ArrayBuffer> => new TextEncoder().encode(s);
export const b64uJson = (v: unknown): string => b64uEncode(utf8(JSON.stringify(v)));

export function b64uDecodeJson<T>(value: string): T {
  return JSON.parse(new TextDecoder().decode(b64uDecode(value))) as T;
}

export async function sha256(data: Uint8Array | string): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? utf8(data) : data;
  return new Uint8Array(await subtle().digest('SHA-256', bytes as Uint8Array<ArrayBuffer>));
}

export function randomToken(bytes = 32): string {
  return b64uEncode(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
}

/** Anything that can produce an ES256 signature: a WebCrypto key, Cloud KMS, an HSM. */
export interface JwsSigner {
  readonly alg: 'ES256';
  /** Full key id as it appears in the JWS header, e.g. did:web:pass.fofo.network#issuer-1 */
  readonly kid: string;
  readonly publicJwk: Jwk;
  /** Returns the raw 64-byte r||s signature over `data`. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export async function generateEs256KeyPair(): Promise<{ privateJwk: Jwk; publicJwk: Jwk }> {
  const pair = await subtle().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ]);
  const privateJwk = (await subtle().exportKey('jwk', pair.privateKey)) as Jwk;
  return { privateJwk, publicJwk: publicPart(privateJwk) };
}

/** Strip private and WebCrypto bookkeeping members, leaving a publishable JWK. */
export function publicPart(jwk: Jwk): Jwk {
  const { kty, crv, x, y } = jwk;
  return { kty, crv, x, y };
}

export async function localSigner(privateJwk: Jwk, kid: string): Promise<JwsSigner> {
  const key = await subtle().importKey(
    'jwk',
    privateJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  );
  return {
    alg: 'ES256',
    kid,
    publicJwk: publicPart(privateJwk),
    async sign(data) {
      const sig = await subtle().sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        key,
        data as Uint8Array<ArrayBuffer>,
      );
      return new Uint8Array(sig);
    },
  };
}

export async function verifyEs256(
  publicJwk: Jwk,
  data: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  if (publicJwk.kty !== 'EC' || publicJwk.crv !== 'P-256') return false;
  if (signature.length !== 64) return false;
  const key = await subtle().importKey(
    'jwk',
    publicPart(publicJwk),
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  );
  return subtle().verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    signature as Uint8Array<ArrayBuffer>,
    data as Uint8Array<ArrayBuffer>,
  );
}

/** RFC 7638 JWK thumbprint (EC keys), base64url. */
export async function jwkThumbprint(jwk: Jwk): Promise<string> {
  if (jwk.kty !== 'EC') throw new Error('only EC keys are supported');
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
  return b64uEncode(await sha256(canonical));
}

export interface DecodedJwt<P = Record<string, unknown>> {
  header: Record<string, unknown>;
  payload: P;
  signingInput: string;
  signature: Uint8Array;
}

export function decodeJwt<P = Record<string, unknown>>(jwt: string): DecodedJwt<P> {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new JoseError('malformed JWT');
  const [h, p, s] = parts as [string, string, string];
  try {
    return {
      header: b64uDecodeJson(h),
      payload: b64uDecodeJson<P>(p),
      signingInput: `${h}.${p}`,
      signature: b64uDecode(s),
    };
  } catch {
    throw new JoseError('malformed JWT');
  }
}

export async function signJwt(
  signer: JwsSigner,
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
): Promise<string> {
  // Holder keys have no kid (they travel as a `jwk` header instead).
  const protectedHeader = {
    alg: signer.alg,
    ...(signer.kid ? { kid: signer.kid } : {}),
    ...header,
  };
  const signingInput = `${b64uJson(protectedHeader)}.${b64uJson(payload)}`;
  return `${signingInput}.${b64uEncode(await signer.sign(utf8(signingInput)))}`;
}

export interface VerifyJwtOptions {
  /** Required `typ` header value. */
  typ?: string;
  /** Seconds since epoch; defaults to now. */
  now?: number;
  /** Clock tolerance in seconds (default 60). */
  skew?: number;
  audience?: string;
}

/** Verify signature and the standard time claims. Throws JoseError on any failure. */
export async function verifyJwt<P extends Record<string, unknown>>(
  jwt: string,
  publicJwk: Jwk,
  options: VerifyJwtOptions = {},
): Promise<DecodedJwt<P>> {
  const decoded = decodeJwt<P>(jwt);
  if (decoded.header.alg !== 'ES256') throw new JoseError('unsupported alg');
  if (options.typ && decoded.header.typ !== options.typ)
    throw new JoseError(`expected typ ${options.typ}`);
  if (!(await verifyEs256(publicJwk, utf8(decoded.signingInput), decoded.signature))) {
    throw new JoseError('bad signature');
  }
  const now = options.now ?? Math.floor(Date.now() / 1000);
  const skew = options.skew ?? 60;
  const { exp, nbf, aud } = decoded.payload as {
    exp?: number;
    nbf?: number;
    aud?: string | string[];
  };
  if (typeof exp === 'number' && now - skew > exp) throw new JoseError('expired');
  if (typeof nbf === 'number' && now + skew < nbf) throw new JoseError('not yet valid');
  if (options.audience !== undefined) {
    const auds = Array.isArray(aud) ? aud : [aud];
    if (!auds.includes(options.audience)) throw new JoseError('wrong audience');
  }
  return decoded;
}

export class JoseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JoseError';
  }
}
