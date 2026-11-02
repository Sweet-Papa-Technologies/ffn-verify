import { BusinessKinds, BusinessKindLabels, type BusinessKind } from './business.js';
import { CredentialKinds, type CredentialKind } from './catalog.js';

// SD-JWT VC Type Metadata for every vct in the catalog, served publicly at the
// vct URL itself (e.g. GET https://pass.fofo.network/vct/license/v1). Claim lists
// here are the published schema: what each type carries and how a wallet or
// agent should label it.

type SdPolicy = 'always' | 'allowed' | 'never';

interface ClaimMeta {
  path: string[];
  label: string;
  sd?: SdPolicy;
}

interface TypeDefinition {
  name: string;
  description: string;
  claims: ClaimMeta[];
}

const evidence: ClaimMeta = {
  path: ['evidence'],
  label: 'Evidence: each check, its source and date',
  sd: 'never',
};

const definitions: Record<CredentialKind | BusinessKind, TypeDefinition> = {
  identity: {
    name: 'FFN Identity',
    description:
      'Facts FFN checked about a person, each with its own evidence. Never shared in full.',
    claims: [
      { path: ['personVerified'], label: 'Real person verified', sd: 'always' },
      { path: ['ageOver18'], label: 'Over 18', sd: 'always' },
      { path: ['ageOver21'], label: 'Over 21', sd: 'always' },
      { path: ['birthDate'], label: 'Date of birth', sd: 'always' },
      { path: ['legalName'], label: 'Legal name', sd: 'always' },
      { path: ['holdsValidLicense'], label: "Holds a valid driver's license", sd: 'always' },
      { path: ['issuingState'], label: 'License issuing state', sd: 'always' },
      { path: ['notChecked'], label: 'Not checked', sd: 'never' },
      { path: ['assurance'], label: 'Assurance', sd: 'never' },
    ],
  },
  link: {
    name: 'FFN Link',
    description: 'An account the person proved they control.',
    claims: [
      { path: ['accountType'], label: 'Account type', sd: 'never' },
      { path: ['handle'], label: 'Handle', sd: 'always' },
      { path: ['accountCreated'], label: 'Account created', sd: 'always' },
      { path: ['nameMatchesVerifiedName'], label: 'Name matches the verified name', sd: 'always' },
    ],
  },
  videoCallCompleted: {
    name: 'Video call completed',
    description: 'A site attestation: the organizer held a video call with this person.',
    claims: [
      { path: ['videoCallCompleted'], label: 'Video call completed', sd: 'never' },
      { path: ['idViewedByOrganizer'], label: 'ID viewed by the organizer', sd: 'never' },
      evidence,
    ],
  },
  referencesChecked: {
    name: 'References checked',
    description: 'A site attestation: the organizer checked this person’s references.',
    claims: [{ path: ['referencesChecked'], label: 'References checked', sd: 'never' }, evidence],
  },
  tripCompleted: {
    name: 'Trip completed',
    description: 'A site attestation: this person completed a trip.',
    claims: [{ path: ['tripCompleted'], label: 'Trip completed', sd: 'never' }, evidence],
  },
  travelVouch: {
    name: 'Travel vouch',
    description: 'A vouch from another traveler, signed by them.',
    claims: [
      { path: ['tags'], label: 'Tags', sd: 'never' },
      { path: ['note'], label: 'Note', sd: 'never' },
    ],
  },
  businessProfile: {
    name: BusinessKindLabels.businessProfile,
    description: 'What the business states about itself, signed with its own key.',
    claims: [
      { path: ['name'], label: 'Business name' },
      { path: ['dba'], label: 'Doing business as' },
      { path: ['domains'], label: 'Domains' },
      { path: ['phones'], label: 'Phone numbers' },
      { path: ['hours'], label: 'Hours' },
      { path: ['address'], label: 'Address' },
      { path: ['serviceArea'], label: 'Service area' },
      { path: ['categories'], label: 'Trades' },
    ],
  },
  delegation: {
    name: BusinessKindLabels.delegation,
    description:
      'Signed by the delegator: the subject may act for it within this scope until the expiry.',
    claims: [
      { path: ['scope'], label: 'May do' },
      { path: ['delegateKind'], label: 'Delegate kind' },
      { path: ['parent'], label: 'Parent delegation (hash)' },
      { path: ['purpose'], label: 'Purpose' },
    ],
  },
  businessIdentity: {
    name: BusinessKindLabels.businessIdentity,
    description: 'SPT checked the state business entity record.',
    claims: [
      { path: ['legalName'], label: 'Legal name' },
      { path: ['entityNumber'], label: 'Entity number' },
      { path: ['jurisdiction'], label: 'Jurisdiction' },
      { path: ['entityType'], label: 'Entity type' },
      { path: ['entityStatus'], label: 'Entity status' },
      evidence,
    ],
  },
  officialChannels: {
    name: BusinessKindLabels.officialChannels,
    description: 'SPT confirmed the business controls these domains and phone numbers.',
    claims: [
      { path: ['domains'], label: 'Domains' },
      { path: ['phones'], label: 'Phone numbers' },
      { path: ['emailDomains'], label: 'Email domains' },
      { path: ['socialHandles'], label: 'Social handles' },
      evidence,
    ],
  },
  license: {
    name: BusinessKindLabels.license,
    description: 'SPT checked the state license board record.',
    claims: [
      { path: ['board'], label: 'License board' },
      { path: ['jurisdiction'], label: 'Jurisdiction' },
      { path: ['licenseNumber'], label: 'License number' },
      { path: ['classes'], label: 'Classifications' },
      { path: ['expiresOn'], label: 'Expires' },
      evidence,
    ],
  },
  insurance: {
    name: BusinessKindLabels.insurance,
    description: 'SPT confirmed the policy with the carrier or the issuing agent.',
    claims: [
      { path: ['carrier'], label: 'Carrier' },
      { path: ['coverageType'], label: 'Coverage' },
      { path: ['limits'], label: 'Limits' },
      { path: ['expiresOn'], label: 'Policy expires' },
      evidence,
    ],
  },
  representative: {
    name: BusinessKindLabels.representative,
    description:
      'A person verified with an FFN person pass is authorized to act for the business. No personal data.',
    claims: [
      { path: ['role'], label: 'Role' },
      { path: ['personPass'], label: 'Person pass (reference only)' },
      evidence,
    ],
  },
};

const allVcts: Record<string, CredentialKind | BusinessKind> = Object.fromEntries([
  ...Object.entries(CredentialKinds).map(([k, v]) => [v, k]),
  ...Object.entries(BusinessKinds).map(([k, v]) => [v, k]),
]);

/** Type Metadata document for `vct`, or undefined if it isn't in the catalog. */
export function typeMetadata(vct: string): Record<string, unknown> | undefined {
  const kind = allVcts[vct];
  if (!kind) return undefined;
  const def = definitions[kind];
  return {
    vct,
    name: def.name,
    description: def.description,
    display: [{ locale: 'en', name: def.name, description: def.description }],
    claims: def.claims.map((c) => ({
      path: c.path,
      display: [{ locale: 'en', label: c.label }],
      sd: c.sd ?? 'never',
    })),
  };
}

/** Every vct in the catalog, for hosts that serve the metadata. */
export function catalogVcts(): string[] {
  return Object.keys(allVcts);
}
