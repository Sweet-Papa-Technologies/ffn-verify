import { VCT_BASE } from './catalog.js';
import { signJwt, type JwsSigner } from './jose.js';
import type { Assurance } from './types.js';

// FFN Verified Business (plan v0.1, "Credential design").
//
// A business holds several narrow credentials rather than one big one, so each
// expires and is revoked on its own schedule. The business signs its own
// profile and its delegations; SPT signs only the attestations. Business facts
// are public by design, so these credentials disclose everything; the one that
// touches a person (representative) carries a reference, never personal data.

export const BusinessKinds = {
  /** Signed by the business: what it says about itself. */
  businessProfile: `${VCT_BASE}/business-profile/v1`,
  /** Signed by the delegating DID: "this DID may do these things for me, until this date". */
  delegation: `${VCT_BASE}/delegation/v1`,
  /** SPT attestations. */
  businessIdentity: `${VCT_BASE}/business-identity/v1`,
  officialChannels: `${VCT_BASE}/official-channels/v1`,
  license: `${VCT_BASE}/license/v1`,
  insurance: `${VCT_BASE}/insurance/v1`,
  representative: `${VCT_BASE}/representative/v1`,
} as const;

export type BusinessKind = keyof typeof BusinessKinds;

export const AttestationKinds = [
  'businessIdentity',
  'officialChannels',
  'license',
  'insurance',
  'representative',
] as const;
export type AttestationKind = (typeof AttestationKinds)[number];

export function businessKindForVct(vct: string): BusinessKind | undefined {
  for (const [kind, value] of Object.entries(BusinessKinds)) {
    if (value === vct) return kind as BusinessKind;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Subjects and identifiers (plan, "Identifiers")
// ---------------------------------------------------------------------------

/**
 *   person        did:jwk from the wallet key
 *   organization  did:web on the business's own domain (did:jwk as the key-only fallback)
 *   agent         did:web under its controller's domain, e.g. did:web:example.com:agents:booking
 */
export type SubjectKind = 'person' | 'organization' | 'agent';

// ---------------------------------------------------------------------------
// Evidence (plan, "Evidence record"): every check, its source, date and result,
// including checks not run.
// ---------------------------------------------------------------------------

export type CheckId =
  | 'entity-record'
  | 'license-record'
  | 'insurance-certificate'
  | 'insurance-confirmation'
  | 'domain-did-document'
  | 'domain-dns-txt'
  | 'phone-code'
  | 'representative-pass'
  | 'reviewer-signoff';

export type CheckResult = 'pass' | 'fail' | 'not-run';

export interface CheckEntry {
  check: CheckId;
  /** What was checked, when a check runs per item: a domain, a phone number, a license number. */
  target?: string;
  /** Where the evidence came from, e.g. "California Contractors State License Board". */
  source: string;
  /** ISO 8601; absent when the check was not run. */
  checkedAt?: string;
  result: CheckResult;
  by: 'automated' | 'reviewer';
  /** Plain words, e.g. "Confirmed by the issuing agent by email". Never personal data. */
  note?: string;
}

export interface EvidenceSummary {
  checks: CheckEntry[];
}

// ---------------------------------------------------------------------------
// Claims
// ---------------------------------------------------------------------------

export interface PostalAddress {
  streetAddress?: string;
  locality: string;
  /** e.g. "CA" */
  region: string;
  postalCode?: string;
  /** ISO 3166-1 alpha-2 */
  country: string;
}

/** Self-signed. Everything here is as the business states it. */
export interface BusinessProfileClaims {
  name: string;
  dba?: string[];
  /** Normalized host names (see normalizeDomain). */
  domains: string[];
  /** E.164 */
  phones: string[];
  /** schema.org openingHours strings, e.g. "Mo-Fr 08:00-17:00". */
  hours?: string[];
  address?: PostalAddress;
  serviceArea?: string[];
  /** Trades, e.g. ["HVAC"]. */
  categories?: string[];
}

export interface BusinessIdentityClaims {
  legalName: string;
  entityNumber: string;
  /** ISO 3166-2, e.g. "US-CA". */
  jurisdiction: string;
  entityType?: string;
  entityStatus: 'active';
  evidence: EvidenceSummary;
}

export interface OfficialChannelsClaims {
  domains: string[];
  phones: string[];
  emailDomains?: string[];
  socialHandles?: string[];
  evidence: EvidenceSummary;
}

export interface LicenseClass {
  code: string;
  name?: string;
}

export interface LicenseClaims {
  board: string;
  jurisdiction: string;
  licenseNumber: string;
  classes: LicenseClass[];
  /** YYYY-MM-DD */
  expiresOn: string;
  evidence: EvidenceSummary;
}

export type CoverageType = 'general-liability' | 'workers-compensation' | 'professional-liability';

export interface InsuranceClaims {
  carrier: string;
  coverageType: CoverageType;
  /** Whole currency units. */
  limits?: { perOccurrence?: number; aggregate?: number; currency: string };
  /** YYYY-MM-DD */
  expiresOn: string;
  evidence: EvidenceSummary;
}

export interface RepresentativeClaims {
  role: 'owner' | 'officer' | 'authorized-representative';
  /**
   * The person pass, by reference only. `ref` is the registry's per-site subject
   * id for the person (see subjectIdFor), meaningless anywhere else.
   */
  personPass: { issuer: string; assurance: Assurance; ref: string };
  evidence: EvidenceSummary;
}

export interface DelegationClaims {
  /** What the delegate may do, e.g. ["registry:publish", "registry:serve"]. "booking:*" covers "booking:create". */
  scope: string[];
  delegateKind: SubjectKind;
  /** base64url SHA-256 of the parent delegation's issuer-signed JWT. Absent on a root delegation. */
  parent?: string;
  /** Free text for people reading the chain, e.g. "Books service calls". */
  purpose?: string;
}

/** The delegation every listing carries: the business lets the registry publish and serve its record. */
export const REGISTRY_SCOPES = ['registry:publish', 'registry:serve'] as const;

// ---------------------------------------------------------------------------
// Levels (plan, "Assurance levels")
// ---------------------------------------------------------------------------

export type BusinessLevel = 0 | 1 | 2 | 3;

export const LevelNames: Record<BusinessLevel, string> = {
  0: 'Not verified',
  1: 'Registered',
  2: 'Licensed and insured',
  3: 'Owner verified',
};

/** What each level needs, cumulatively. */
export const LevelRequirements: Record<Exclude<BusinessLevel, 0>, AttestationKind[]> = {
  1: ['businessIdentity', 'officialChannels'],
  2: ['businessIdentity', 'officialChannels', 'license', 'insurance'],
  3: ['businessIdentity', 'officialChannels', 'license', 'insurance', 'representative'],
};

export function levelFor(valid: ReadonlySet<AttestationKind>): BusinessLevel {
  for (const level of [3, 2, 1] as const) {
    if (LevelRequirements[level].every((k) => valid.has(k))) return level;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Status and revocation reasons
// ---------------------------------------------------------------------------

/** Token Status List values (2 bits per entry for business credentials). */
export const StatusValue = { valid: 0, invalid: 1, suspended: 2 } as const;
export type CredentialStatus = 'valid' | 'invalid' | 'suspended' | 'unknown';

export const RevocationReasons = [
  'license-lapsed',
  'insurance-lapsed',
  'entity-inactive',
  'domain-binding-lost',
  'phone-unverified',
  'key-rotated',
  'superseded',
  'business-request',
  'dispute-upheld',
  'issued-in-error',
] as const;
export type RevocationReason = (typeof RevocationReasons)[number];

export const RevocationReasonLabels: Record<RevocationReason, string> = {
  'license-lapsed': 'The license is no longer active',
  'insurance-lapsed': 'The insurance policy lapsed',
  'entity-inactive': 'The business entity is no longer active',
  'domain-binding-lost': 'The domain no longer points to this registry entry',
  'phone-unverified': 'The phone number could not be re-verified',
  'key-rotated': 'The business replaced its key; a new credential was issued',
  superseded: 'Replaced by a newer credential',
  'business-request': 'Withdrawn at the business’s request',
  'dispute-upheld': 'Withdrawn after a dispute',
  'issued-in-error': 'Issued in error',
};

// ---------------------------------------------------------------------------
// The public registry record (plan, "Public registry record")
// ---------------------------------------------------------------------------

export const BUSINESS_RECORD_TYP = 'ffn-business-record+jwt';

export interface RecordRevocation {
  jti: string;
  vct: string;
  status: 'invalid' | 'suspended';
  reason: RevocationReason;
  /** ISO 8601 */
  at: string;
}

/**
 * Signed by the registry. Every credential inside carries its own signature, so
 * the envelope only says "this is what the registry serves for this business".
 */
export interface BusinessRecordPayload {
  iss: string;
  /** The business DID. */
  sub: string;
  iat: number;
  exp: number;
  recordId: string;
  /** Official domains, normalized. Lookups match these. */
  domains: string[];
  phones: string[];
  /** The registry's computed level. Verifiers recompute it from the attestations. */
  level: BusinessLevel;
  /** Compact SD-JWT VCs. */
  profile: string;
  delegation: string;
  attestations: string[];
  revocations: RecordRevocation[];
  binding: { method: 'did-web' | 'dns-only'; checkedAt: string };
  profileUrl: string;
  updatedAt: string;
  /** What this record asserts and what it never does. Absent on records signed before Nov 2026. */
  scope?: RecordScope;
}

// ---------------------------------------------------------------------------
// Scope of assertion: what a record says, and what it never says
// ---------------------------------------------------------------------------

/** One fact a record asserts, backed by the attestation of `kind`. */
export type AssertionCode =
  | 'legal-entity-active'
  | 'domain-control'
  | 'phone-control'
  | 'license-active'
  | 'insurance-active'
  | 'representative-verified';

/** What the registry never asserts, whatever the level. */
export type DisclaimerCode =
  | 'rating'
  | 'ranking'
  | 'recommendation'
  | 'endorsement'
  | 'quality'
  | 'inbound-caller-id';

export interface ScopeAssertion {
  code: AssertionCode;
  /** The attestation that backs it. A verifier keeps the assertion only while that attestation is valid. */
  kind: AttestationKind;
  statement: string;
}

export interface ScopeDisclaimer {
  code: DisclaimerCode;
  statement: string;
}

export interface RecordScope {
  /** Only what this record's current attestations cover. */
  asserts: ScopeAssertion[];
  doesNotAssert: ScopeDisclaimer[];
  /** A page that explains both lists in plain words. */
  explanation: string;
}

export const ScopeAssertions: Record<AssertionCode, Omit<ScopeAssertion, 'code'>> = {
  'legal-entity-active': {
    kind: 'businessIdentity',
    statement:
      'The legal entity was on the official business register, and active, on the date it was checked.',
  },
  'domain-control': {
    kind: 'officialChannels',
    statement:
      'The business controls the listed domains: each points back to this registry entry through its DID document or DNS record.',
  },
  'phone-control': {
    kind: 'officialChannels',
    statement:
      'The business proved it controls each listed phone number (a one-time code by text or call, or a reviewer’s call): calling the number reaches the business.',
  },
  'license-active': {
    kind: 'license',
    statement:
      'The license was active with the licensing board, under the verified legal name, on the date it was checked.',
  },
  'insurance-active': {
    kind: 'insurance',
    statement: 'The insurance policy was confirmed as current, and runs until the date shown.',
  },
  'representative-verified': {
    kind: 'representative',
    statement:
      'A person who verified their identity with an FFN person pass may act for the business.',
  },
};

export const ScopeDisclaimers: ScopeDisclaimer[] = [
  { code: 'rating', statement: 'The registry does not rate or score businesses.' },
  { code: 'ranking', statement: 'The registry does not rank businesses or order them by merit.' },
  { code: 'recommendation', statement: 'A listing is not a recommendation to hire the business.' },
  { code: 'endorsement', statement: 'A listing is not an endorsement.' },
  {
    code: 'quality',
    statement: 'The registry makes no claim about the quality of the business’s work or service.',
  },
  {
    code: 'inbound-caller-id',
    statement:
      'A verified phone number shows the business controls the number when you call it. It never shows that a call or text you receive comes from the business: caller ID can be faked.',
  },
];

/**
 * The scope a record states: one assertion per fact its valid attestations
 * back, phone control only when it lists a phone, and every disclaimer.
 */
export function recordScope(input: {
  valid: Iterable<AttestationKind>;
  phones: readonly string[];
  explanation: string;
}): RecordScope {
  const valid = new Set(input.valid);
  const asserts = (Object.keys(ScopeAssertions) as AssertionCode[])
    .filter((code) => valid.has(ScopeAssertions[code].kind))
    .filter((code) => code !== 'phone-control' || input.phones.length > 0)
    .map((code) => ({ code, ...ScopeAssertions[code] }));
  return {
    asserts,
    doesNotAssert: ScopeDisclaimers.map((d) => ({ ...d })),
    explanation: input.explanation,
  };
}

/** Where a registry explains its scope (its how-it-works page). */
export const scopeExplanationUrl = (registryOrigin: string) =>
  `${registryOrigin.replace(/\/$/, '')}/how-it-works#scope`;

/** Human labels for attestation kinds, shared by the verifier summary and profiles. */
export const BusinessKindLabels: Record<BusinessKind, string> = {
  businessProfile: 'Business profile',
  delegation: 'Delegation',
  businessIdentity: 'Business identity',
  officialChannels: 'Official channels',
  license: 'License',
  insurance: 'Insurance',
  representative: 'Verified representative',
};

/** Sign a registry record (the registry's key; see BusinessRecordPayload). */
export async function signBusinessRecord(
  signer: JwsSigner,
  payload: BusinessRecordPayload,
): Promise<string> {
  return signJwt(signer, payload as unknown as Record<string, unknown>, {
    typ: BUSINESS_RECORD_TYP,
  });
}
