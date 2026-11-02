// The typed schema list (FFN v1 doc, "Credential model" and Flow 8 step 4).
//
// Every credential FFN or a registered site can issue is one entry here. The vct
// strings are identifiers: they stay the same in every network so a
// credential's type never depends on which host issued it. Their type metadata
// is served at the URL (pass-api and the registry both serve /vct/...).
//
// Unlike service hosts (networks.ts), this base must not change once
// credentials are issued: every credential names its vct forever.

export const VCT_BASE = 'https://pass.fofo.network/vct';

export const CredentialKinds = {
  identity: `${VCT_BASE}/identity/v1`,
  link: `${VCT_BASE}/link/v1`,
  videoCallCompleted: `${VCT_BASE}/video-call-completed/v1`,
  referencesChecked: `${VCT_BASE}/references-checked/v1`,
  tripCompleted: `${VCT_BASE}/trip-completed/v1`,
  travelVouch: `${VCT_BASE}/travel-vouch/v1`,
} as const;

export type CredentialKind = keyof typeof CredentialKinds;
export type Vct = (typeof CredentialKinds)[CredentialKind];

/** Kinds issued by a site rather than by FFN. Their claims are always disclosed. */
export const SiteKinds = [
  'videoCallCompleted',
  'referencesChecked',
  'tripCompleted',
  'travelVouch',
] as const;
export type SiteKind = (typeof SiteKinds)[number];

/** Selectively disclosable claims in an FFN Identity credential. */
export const IdentityClaims = [
  'personVerified',
  'ageOver18',
  'ageOver21',
  'birthDate',
  'legalName',
  'holdsValidLicense',
  'issuingState',
] as const;
export type IdentityClaim = (typeof IdentityClaims)[number];

/** Selectively disclosable claims in an FFN Link credential (accountType is always disclosed). */
export const LinkClaims = ['handle', 'accountCreated', 'nameMatchesVerifiedName'] as const;
export type LinkClaim = (typeof LinkClaims)[number];

export const AccountTypes = ['email', 'phone', 'linkedin', 'github', 'google'] as const;
export type AccountType = (typeof AccountTypes)[number];

/**
 * Things FFN never checks in v1. They are listed in every identity credential's
 * notChecked so a verifier sees "unknown", never "false" (design principle 4).
 */
export const IdentityNeverChecked = ['backgroundCheck', 'address', 'licenseSuspension'] as const;

export function kindForVct(vct: string): CredentialKind | undefined {
  for (const [kind, value] of Object.entries(CredentialKinds)) {
    if (value === vct) return kind as CredentialKind;
  }
  return undefined;
}

export function isSiteKind(kind: CredentialKind): kind is SiteKind {
  return (SiteKinds as readonly string[]).includes(kind);
}

/** Human labels shared by the wallet's consent screen and site badges. */
export const ClaimLabels: Record<string, string> = {
  'identity.personVerified': 'Real person verified',
  'identity.ageOver18': 'Over 18',
  'identity.ageOver21': 'Over 21',
  'identity.birthDate': 'Date of birth',
  'identity.legalName': 'Legal name',
  'identity.holdsValidLicense': "Holds a valid driver's license",
  'identity.issuingState': 'License issuing state',
  'link.email': 'Email address',
  'link.phone': 'Phone number',
  'link.linkedin': 'LinkedIn account',
  'link.github': 'GitHub account',
  'link.google': 'Google account',
  videoCallCompleted: 'Video call completed',
  'videoCallCompleted.idViewedByOrganizer': 'ID viewed by the organizer on a video call',
  referencesChecked: 'References checked',
  tripCompleted: 'Trip completed',
  travelVouch: 'Travel vouch',
};
