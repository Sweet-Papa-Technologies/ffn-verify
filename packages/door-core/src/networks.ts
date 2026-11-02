import type { Jwk } from './jose.js';

// Where an FFN network lives. A site picks one by name; everything else
// (registry location and key, wallet URL, FFN's issuer DID, the business
// registry) follows from it.
//
// Hosts live here and nowhere else in code. Moving a service is an edit to
// this table, or a deploy-time override (networkFromEnv), plus the DNS
// records listed in docs/DOMAINS.md, which are added by hand at the registrar.
//
// One host is special: the wallet origin is the passkey RP ID. Passkeys made
// on one wallet host don't work on another, so settle it before people enroll.

export interface FfnNetwork {
  name: string;
  /** Hosted wallet origin; also the passkey RP ID host and the person issuer's host. */
  walletOrigin: string;
  /** FFN Issuer DID. */
  ffnIssuer: string;
  /** The signed trust registry of issuers and sites. */
  registryUrl: string;
  /** Pinned registry signing keys (trust anchors). Rotation = add the new key, then drop the old. */
  registryKeys: Jwk[];
  /** FFN Verified Business: the registry agents query, and who runs it. */
  businessRegistry?: BusinessRegistryAnchor;
}

export interface BusinessRegistryAnchor {
  origin: string;
  did: string;
  name: string;
  /**
   * The registry keys a verifier accepts: RFC 7638 SHA-256 thumbprints
   * (base64url) of the signing key and its standby. A record, attestation or
   * status list signed by any other key fails, even if the registry's
   * did.json lists that key. Absent: whatever did.json lists (devnet-style
   * setups and tests that bring their own registry).
   */
  keyThumbprints?: string[];
}

const network = (
  name: string,
  walletHost: string,
  registryHost: string,
  keyThumbprints: string[],
): Required<FfnNetwork> => ({
  name,
  walletOrigin: `https://${walletHost}`,
  ffnIssuer: `did:web:${walletHost}`,
  registryUrl: `https://${walletHost}/.well-known/ffn-registry.jwt`,
  registryKeys: [],
  businessRegistry: {
    origin: `https://${registryHost}`,
    did: `did:web:${registryHost}`,
    name: 'Sweet Papa Technologies LLC',
    keyThumbprints,
  },
});

// Business registry key pins. Rotation keeps deployed verifiers working only
// if the next key is pinned before it signs anything: publish it as the
// standby (#records-2, KMS registry-signer-2), pin its thumbprint here and in
// python/ffn_verify/networks.py, ship, and only then promote it. Print the
// thumbprints with `pnpm --filter @fofonet/registry cli key-thumbprints`.
const PRODUCTION_REGISTRY_KEYS = [
  // KMS fofo-network-mainet ffn-pass-mainet/registry-signer (HSM), version 1: #records-1, signing.
  'ha2yRH_LpeVyIJR5KvD_3m10ZQCbe1ppRqo5Swo7B6k',
  // KMS fofo-network-mainet ffn-pass-mainet/registry-signer-2 (HSM), version 1: #records-2, standby.
  'tWuq-FfqJwjb_oqiMHELPG18U1bfCCOvNRs1s5zjroU',
];
const DEVNET_REGISTRY_KEYS = [
  // KMS fofo-network-devnet ffn-pass-devnet/registry-signer, version 1: #records-1, signing.
  'Updj4FcLyO2SpdZw57NjEKEKG2SFnnoq8UBm5Pk-lZI',
  // KMS fofo-network-devnet ffn-pass-devnet/registry-signer-2, version 1: #records-2, standby.
  'X3go29ByGoAuStS_9wK7uInL-W_tIh_L4-djymN7iks',
];

export const Networks = {
  production: {
    ...network(
      'production',
      'pass.fofo.network',
      'registry.fofo.network',
      PRODUCTION_REGISTRY_KEYS,
    ),
    // KMS ffn-pass-mainet/trust-registry (HSM), version 1.
    registryKeys: [
      {
        kty: 'EC',
        crv: 'P-256',
        x: 'SSu0fUSb6K1IX7U7Fbd5MlO9c6mePqk5iQWJetRcYVE',
        y: 'CQIVrkB-xLsOp3AYsKI6duSADPgrhZxmsKkQkO8hX1A',
        kid: 'did:web:pass.fofo.network#registry-1',
        alg: 'ES256',
      },
    ],
  },
  // Firebase Hosting default domains: devnet works with no DNS records at all.
  devnet: {
    ...network(
      'devnet',
      'fofo-pass-devnet.web.app',
      'fofo-registry-devnet.web.app',
      DEVNET_REGISTRY_KEYS,
    ),
    // KMS ffn-pass-devnet/trust-registry, version 1.
    registryKeys: [
      {
        kty: 'EC',
        crv: 'P-256',
        x: '1a7cfUriDPF3FkwbiYFsNxzNNrHSgCTTwp2iKFW9lac',
        y: 'oRULyfN0qTCAszKeY10aHXpf7-F9NYFM95d1oqUsmzQ',
        kid: 'did:web:fofo-pass-devnet.web.app#registry-1',
        alg: 'ES256',
      },
    ],
  },
} satisfies Record<string, Required<FfnNetwork>>;

export type NetworkName = keyof typeof Networks;

/**
 * The key pins of a known FFN business registry DID (mainnet or devnet), or
 * undefined for any other DID. Every DID resolver applies these, whatever the
 * caller configured: a known registry's DID never resolves to a key it doesn't pin.
 */
export function knownRegistryPins(did: string): readonly string[] | undefined {
  for (const net of Object.values(Networks))
    if (net.businessRegistry.did === did) return net.businessRegistry.keyThumbprints;
  return undefined;
}

/**
 * The business registry's routes the FFN wallet posts to. The registry builds
 * its requests from these and the trust registry lists them, so the two can't
 * drift apart (a URI the trust registry lacks makes the wallet refuse).
 */
export const BusinessRegistryPaths = {
  /** A person's pass, signing in to the portal. */
  passResponse: '/portal/pass/response',
  /** What the business key signed in the wallet. */
  signingResponse: '/portal/signing-response',
} as const;

/**
 * The named network with deploy-time overrides, so a host can move without a
 * code change:
 *   PASS_NETWORK              devnet | production
 *   PASS_WALLET_ORIGIN        e.g. https://pass.example.com (issuer DID and trust registry URL follow)
 *   PASS_TRUST_REGISTRY_KEYS  JSON array of the trust registry's public JWKs
 *   BUSINESS_REGISTRY_ORIGIN  e.g. https://registry.example.com
 *   BUSINESS_REGISTRY_KEY_THUMBPRINTS  comma-separated key pins for that registry
 *
 * The network's own key pins stay only while the business registry is the
 * network's own: a registry moved to another origin has other keys, so it
 * runs unpinned unless BUSINESS_REGISTRY_KEY_THUMBPRINTS names them.
 */
export function networkFromEnv(env: Record<string, string | undefined>): Required<FfnNetwork> {
  const base = Networks[(env.PASS_NETWORK as NetworkName) ?? 'devnet'] ?? Networks.devnet;
  const wallet = env.PASS_WALLET_ORIGIN ? new URL(env.PASS_WALLET_ORIGIN) : undefined;
  const registry = env.BUSINESS_REGISTRY_ORIGIN ? new URL(env.BUSINESS_REGISTRY_ORIGIN) : undefined;
  const { keyThumbprints: basePins, ...baseRegistry } = base.businessRegistry;
  const ownRegistry = !registry || registry.origin === baseRegistry.origin;
  const pins = env.BUSINESS_REGISTRY_KEY_THUMBPRINTS
    ? env.BUSINESS_REGISTRY_KEY_THUMBPRINTS.split(',')
        .map((s) => s.trim())
        .filter(Boolean)
    : ownRegistry
      ? basePins
      : undefined;
  return {
    ...base,
    ...(wallet
      ? {
          walletOrigin: wallet.origin,
          ffnIssuer: `did:web:${encodeURIComponent(wallet.host)}`,
          registryUrl: `${wallet.origin}/.well-known/ffn-registry.jwt`,
        }
      : {}),
    ...(env.PASS_TRUST_REGISTRY_KEYS
      ? { registryKeys: JSON.parse(env.PASS_TRUST_REGISTRY_KEYS) as Jwk[] }
      : {}),
    businessRegistry: {
      ...baseRegistry,
      ...(registry
        ? { origin: registry.origin, did: `did:web:${encodeURIComponent(registry.host)}` }
        : {}),
      ...(pins ? { keyThumbprints: pins } : {}),
    },
  };
}
