export {
  verifyBusiness,
  lookupBusiness,
  type BusinessVerification,
  type BusinessQuery,
  type VerifiedFact,
  type FactStatus,
  type BindingStatus,
  type RegistryAnchor,
  type Observed,
  type VerifyBusinessOptions,
  type LookupResult,
} from './verify.js';
export { dohResolver, staticTxt, type DohOptions, type TxtResolver } from './dns.js';
export { PinnedRegistryResolver, keyThumbprint, pinRegistryKeys } from './pin.js';
import { Networks } from '@fofonet/door-core';
/**
 * The production registry, for agents that don't pin their own (see door-core
 * networks.ts), with its key pins: records signed by any other key fail.
 */
export const FFN_BUSINESS_REGISTRY = Networks.production.businessRegistry;
export {
  ScopeAssertions,
  ScopeDisclaimers,
  type AssertionCode,
  type DisclaimerCode,
  type RecordScope,
  type ScopeAssertion,
  type ScopeDisclaimer,
} from '@fofonet/door-core';
export {
  verifyDelegationChain,
  verifyCredential,
  StatusChecker,
  DidResolver,
  type VerifiedChain,
} from '@fofonet/door-core';
export {
  verifyPresentation,
  type PresentationInput,
  type PresentationOptions,
  type PresentationResult,
} from './presentation.js';
export {
  verifyBusinessFor,
  verifyPresentationFor,
  presentationSentence,
  type AgentDeps,
  type VerifyBusinessArgs,
  type VerifyPresentationArgs,
} from './agent.js';
