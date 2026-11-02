import { StatusList, createHeaderAndPayload } from '@owf/token-status-list';
import {
  DidResolver,
  buildDidDocument,
  generateEs256KeyPair,
  localSigner,
  signJwt,
  type DidDocument,
  type Fetch,
  type Jwk,
  type JwsSigner,
} from '../src/index.js';

export interface Party {
  did: string;
  signer: JwsSigner;
  privateJwk: Jwk;
  publicJwk: Jwk;
}

export async function party(did: string, kid = 'key-1'): Promise<Party> {
  const { privateJwk, publicJwk } = await generateEs256KeyPair();
  return { did, signer: await localSigner(privateJwk, `${did}#${kid}`), privateJwk, publicJwk };
}

/** A tiny web: URL → body, so DID documents and status lists resolve without a network. */
export class FakeWeb {
  readonly pages = new Map<string, { body: string; type: string }>();

  publishDid(doc: DidDocument) {
    const [host, ...path] = doc.id.slice('did:web:'.length).split(':');
    const url = path.length
      ? `https://${host}/${path.join('/')}/did.json`
      : `https://${host}/.well-known/did.json`;
    this.pages.set(url, { body: JSON.stringify(doc), type: 'application/did+json' });
  }

  publishParty(p: Party) {
    this.publishDid(buildDidDocument(p.did, [{ kid: p.signer.kid, publicJwk: p.publicJwk }]));
  }

  fetch: Fetch = async (input) => {
    const hit = this.pages.get(String(input));
    return hit
      ? new Response(hit.body, { status: 200, headers: { 'content-type': hit.type } })
      : new Response('not found', { status: 404 });
  };

  resolver() {
    return new DidResolver({ fetch: this.fetch, ttlSeconds: 0 });
  }
}

/** Sign and publish a status list with the given entries set. */
export async function publishStatusList(
  web: FakeWeb,
  signer: JwsSigner,
  iss: string,
  uri: string,
  set: Record<number, number> = {},
  bits: 1 | 2 | 4 | 8 = 2,
) {
  const statuses = Array.from({ length: 64 }, (_, i) => set[i] ?? 0);
  const now = Math.floor(Date.now() / 1000);
  const { payload } = createHeaderAndPayload(
    new StatusList(statuses, bits),
    { iss, sub: uri, iat: now, exp: now + 86_400, ttl: 3600 },
    { alg: 'ES256', typ: 'statuslist+jwt', kid: signer.kid },
  );
  const jwt = await signJwt(signer, payload as Record<string, unknown>, { typ: 'statuslist+jwt' });
  web.pages.set(uri, { body: jwt, type: 'application/statuslist+jwt' });
}
