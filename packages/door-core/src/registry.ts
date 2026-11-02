import { CredentialKinds, type CredentialKind } from './catalog.js';
import type { Fetch } from './did-web.js';
import { decodeJwt, signJwt, verifyJwt, type Jwk, type JwsSigner } from './jose.js';
import { BusinessRegistryPaths, type FfnNetwork } from './networks.js';
import type {
  RegistryDocument,
  RegistryIssuer,
  RegistryVerifier,
  SignedRegistry,
} from './types.js';

// The trust registry is a signed JSON file at a well-known address (Flow 8).
// Anyone holding the registry key can verify FFN credentials without our SDK.

export const REGISTRY_JWT_TYP = 'ffn-registry+jwt';

/** Sites and issuers besides FFN itself, as kept in ffn-pass/trust/<network>.json. */
export interface TrustFile {
  issuers: Array<Omit<RegistryIssuer, 'credentialTypes'> & { credentialTypes: CredentialKind[] }>;
  verifiers: RegistryVerifier[];
}

/**
 * A network's trust registry document. FFN's own issuer and the business
 * registry come from the network (so a host move flows through), everything
 * else from its trust file.
 */
export function trustRegistryDocument(
  network: Required<FfnNetwork>,
  file: TrustFile,
  version = Math.floor(Date.now() / 1000),
): RegistryDocument {
  const registry = network.businessRegistry;
  return {
    version,
    issuers: [
      {
        id: network.ffnIssuer,
        name: network.name === 'production' ? 'FoFo Network' : `FoFo Network (${network.name})`,
        url: network.walletOrigin,
        credentialTypes: [CredentialKinds.identity, CredentialKinds.link],
        status: 'active',
      },
      ...file.issuers.map((i) => ({
        ...i,
        credentialTypes: i.credentialTypes.map((k) => CredentialKinds[k]),
      })),
    ],
    verifiers: [
      {
        clientId: new URL(registry.origin).host,
        name: 'FFN Verified Business',
        responseUris: Object.values(BusinessRegistryPaths).map((p) => `${registry.origin}${p}`),
        status: 'active',
      },
      ...file.verifiers,
    ],
  };
}

export async function signRegistry(
  doc: RegistryDocument,
  signer: JwsSigner,
  options: { iss: string; validForDays?: number; now?: number },
): Promise<string> {
  const iat = options.now ?? Math.floor(Date.now() / 1000);
  const exp = iat + (options.validForDays ?? 90) * 86_400;
  return signJwt(signer, { ...doc, iss: options.iss, iat, exp }, { typ: REGISTRY_JWT_TYP });
}

/** Verify against any of the trusted keys. Throws if none verifies. */
export async function verifyRegistry(
  jwt: string,
  trustedKeys: Jwk[],
  now?: number,
): Promise<SignedRegistry> {
  const { header } = decodeJwt(jwt);
  const keys = trustedKeys.filter(
    (k) => header.kid === undefined || k.kid === undefined || k.kid === header.kid,
  );
  for (const key of keys.length > 0 ? keys : trustedKeys) {
    try {
      const { payload } = await verifyJwt<SignedRegistry & Record<string, unknown>>(jwt, key, {
        typ: REGISTRY_JWT_TYP,
        ...(now === undefined ? {} : { now }),
      });
      if (!Array.isArray(payload.issuers) || !Array.isArray(payload.verifiers))
        throw new Error('malformed registry');
      return payload;
    } catch {
      // try the next trusted key
    }
  }
  throw new Error('registry signature not trusted');
}

export class Registry {
  constructor(readonly doc: SignedRegistry | (RegistryDocument & { iss?: string })) {}

  issuer(id: string): RegistryIssuer | undefined {
    return this.doc.issuers.find((i) => i.id === id && i.status === 'active');
  }

  verifier(clientId: string): RegistryVerifier | undefined {
    return this.doc.verifiers.find((v) => v.clientId === clientId && v.status === 'active');
  }

  /** May `issuerId` issue credentials of type `vct`? */
  allows(issuerId: string, vct: string): boolean {
    return this.issuer(issuerId)?.credentialTypes.includes(vct) ?? false;
  }

  /** Active issuers allowed to issue `vct`. */
  issuersFor(vct: string): RegistryIssuer[] {
    return this.doc.issuers.filter((i) => i.status === 'active' && i.credentialTypes.includes(vct));
  }
}

export interface RegistryClientOptions {
  url: string;
  trustedKeys: Jwk[];
  fetch?: Fetch;
  ttlSeconds?: number;
}

/**
 * Fetches and caches the signed registry. When the fetch fails it keeps serving
 * the last verified copy, so an FFN outage never blocks a site (principle 1).
 */
export class RegistryClient {
  private cached?: { registry: Registry; until: number };
  private readonly fetchFn: Fetch;

  constructor(private readonly options: RegistryClientOptions) {
    this.fetchFn = options.fetch ?? ((input, init) => globalThis.fetch(input, init));
  }

  static fixed(doc: RegistryDocument): { get(): Promise<Registry> } {
    const registry = new Registry(doc);
    return { get: async () => registry };
  }

  async get(): Promise<Registry> {
    if (this.cached && this.cached.until > Date.now()) return this.cached.registry;
    try {
      const res = await this.fetchFn(this.options.url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const registry = new Registry(
        await verifyRegistry((await res.text()).trim(), this.options.trustedKeys),
      );
      this.cached = { registry, until: Date.now() + (this.options.ttlSeconds ?? 3600) * 1000 };
      return registry;
    } catch (err) {
      if (this.cached) return this.cached.registry;
      throw new Error(`FFN registry unavailable: ${(err as Error).message}`);
    }
  }
}
