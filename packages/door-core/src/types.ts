import type { AccountType, CredentialKind, IdentityClaim, SiteKind } from './catalog.js';

// ---------------------------------------------------------------------------
// Evidence (FFN v1 doc, "The evidence record")
// ---------------------------------------------------------------------------

export type Assurance = 'high' | 'substantial' | 'moderate' | 'low' | 'none';

/** Ordered weakest → strongest, for minimum-assurance checks. */
export const AssuranceOrder: readonly Assurance[] = [
  'none',
  'low',
  'moderate',
  'substantial',
  'high',
];

export function meetsAssurance(actual: Assurance, minimum: Assurance): boolean {
  return AssuranceOrder.indexOf(actual) >= AssuranceOrder.indexOf(minimum);
}

// Design principle: a non-biometric route to verification always exists. No
// flow may require a face match. Identity methods below are document- or
// chip-based; a face match is only ever an opt-in add-on to a vendor check.
export type EvidenceMethod =
  // Identity (Flow 1)
  | 'mdl-wallet' // Path A: state-signed mDL from the phone wallet, Digital Credentials API
  | 'vendor-document' // Path B: ID vendor reads the document (no selfie unless opted in)
  | 'vendor-nfc' // Path B: ID vendor reads the document's chip
  | 'organizer-video' // Path C: organizer saw the ID on a video call (site attestation only)
  // A value computed from another observed fact, e.g. issuingState from the
  // license address rather than read from a dedicated field.
  | 'derived'
  // Links (Flow 2)
  | 'oauth'
  | 'email-code'
  | 'phone-code'
  // Site attestations (Flows 4 and 5)
  | 'organizer-references'
  | 'organizer-confirmation'
  | 'peer-vouch'
  // Devnet only. Never enabled where real people verify.
  | 'sandbox';

/** One evidence entry. Travels inside the credential next to the claim it supports. */
export interface Evidence {
  method: EvidenceMethod;
  /** Who observed it, e.g. "Didit (document check)" or "adventure.fofo.dev". */
  source: string;
  /** ISO 8601. */
  checkedAt: string;
  assurance: Assurance;
}

export type HolderBinding = 'passkey-prf' | 'custodial';

/** Always-disclosed summary on an FFN Identity credential. */
export interface AssuranceSummary {
  level: Assurance;
  method: EvidenceMethod;
  holderBinding: HolderBinding;
}

export type NameMatch = 'match' | 'partial' | 'no-match' | 'not-checked';

export interface LegalName {
  givenName: string;
  familyName: string;
}

// ---------------------------------------------------------------------------
// Credential payloads (the claims each kind carries before SD packing)
// ---------------------------------------------------------------------------

export interface IdentityClaimValues {
  personVerified?: boolean;
  ageOver18?: boolean;
  ageOver21?: boolean;
  /** YYYY-MM-DD */
  birthDate?: string;
  legalName?: LegalName;
  holdsValidLicense?: boolean;
  /** Two-letter US state or subdivision code. */
  issuingState?: string;
}

export interface IdentityCredentialClaims extends IdentityClaimValues {
  evidence: Partial<Record<IdentityClaim, Evidence>>;
  notChecked: string[];
  assurance: AssuranceSummary;
}

export interface LinkCredentialClaims {
  accountType: AccountType;
  handle: string;
  /** YYYY-MM-DD, only when the provider shares it. */
  accountCreated?: string;
  nameMatchesVerifiedName: NameMatch;
  evidence: { handle: Evidence; accountCreated?: Evidence; nameMatchesVerifiedName?: Evidence };
}

export interface SiteAttestationClaims {
  /** Free-form context the site attaches, e.g. the trip name. */
  context?: string;
  evidence: Evidence;
  [claim: string]: unknown;
}

// ---------------------------------------------------------------------------
// Requests (Flow 3 step 1)
// ---------------------------------------------------------------------------

type Opt<T extends string> = T | `${T}?`;

/**
 * What a site asks for, as compact typed strings:
 *   'identity.ageOver21'   one identity claim
 *   'link.github'          a linked GitHub account
 *   'videoCallCompleted'   a site-issued attestation
 * A trailing '?' marks the item optional.
 */
export type ClaimRef =
  | Opt<`identity.${IdentityClaim}`>
  | Opt<`link.${AccountType}`>
  | Opt<SiteKind>;

export interface ParsedClaimRef {
  ref: string;
  kind: CredentialKind;
  /** Identity claim name, or account type for links, or undefined for site kinds. */
  item?: string;
  required: boolean;
}

// ---------------------------------------------------------------------------
// Verification result (adventure.fofo.dev's VerificationRecord + evidence[])
// ---------------------------------------------------------------------------

export interface VerifiedClaim {
  /** e.g. 'identity.ageOver21', 'link.github.handle', 'videoCallCompleted' */
  name: string;
  value: unknown;
  issuer: string;
  issuerName: string;
  evidence?: Evidence;
}

export interface VerifiedCredential {
  kind: CredentialKind;
  vct: string;
  issuer: string;
  issuerName: string;
  /** The credential's jti — the issuer's attestationId. */
  attestationId?: string;
  issuedAt?: string;
  expiresAt?: string;
  status: 'valid' | 'unknown';
  statusCheckedAt?: string;
  /** The credential's status-list entry, kept so a site can re-check it later without a new presentation. */
  statusList?: { uri: string; idx: number };
}

export interface VerificationRecord {
  provider: 'ffn';
  level: 3;
  /** Per-site subject identifier, derived from the holder key and the site's client_id. */
  subjectId: string;
  verifiedAt: string;
  /** Earliest expiry among the presented credentials. */
  expiresAt: string | null;
  claims: VerifiedClaim[];
  /** Flat name → value view of claims, for convenience. */
  values: Record<string, unknown>;
  credentials: VerifiedCredential[];
  evidence: Evidence[];
  /** Requested items the person didn't present, plus every credential's notChecked list. */
  notChecked: string[];
  /** The site's own context passed to createRequest (e.g. its user id). */
  context?: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Trust registry (Flow 8)
// ---------------------------------------------------------------------------

export type RegistryStatus = 'active' | 'suspended' | 'retired';

export interface RegistryIssuer {
  /** did:web identifier. */
  id: string;
  name: string;
  url?: string;
  logoUri?: string;
  /** vct values this issuer may issue. Anything else is rejected by verifiers. */
  credentialTypes: string[];
  status: RegistryStatus;
}

export interface RegistryVerifier {
  /** OpenID4VP pre-registered client_id (the site's host). */
  clientId: string;
  name: string;
  logoUri?: string;
  /** Exact response_uri values the wallet may post presentations to. */
  responseUris: string[];
  status: RegistryStatus;
}

export interface RegistryDocument {
  version: number;
  issuers: RegistryIssuer[];
  verifiers: RegistryVerifier[];
}

export interface SignedRegistry extends RegistryDocument {
  /** The registry signer (FFN admin key). */
  iss: string;
  iat: number;
  exp: number;
}
