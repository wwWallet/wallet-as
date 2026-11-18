import { OpenID4VCIProfile } from './OpenID4VCIProfile';
import { WeBuildProfile } from './WeBuildProfile';
import type {
  AttestationClientAuthenticationProfile,
  AttestationClientAuthenticationProfileId,
} from './types';

const profiles: Record<
  AttestationClientAuthenticationProfileId,
  AttestationClientAuthenticationProfile
> = {
  DEFAULT: OpenID4VCIProfile,
  WEBUILD: WeBuildProfile,
};

export function loadAttestationClientAuthenticationProfile(
  id: string,
): AttestationClientAuthenticationProfile {
  if (!Object.prototype.hasOwnProperty.call(profiles, id)) {
    throw new Error(`Unknown attestation client authentication profile: ${id}`);
  }
  return profiles[id as AttestationClientAuthenticationProfileId];
}

export type {
  AttestationClientAuthenticationProfile,
  AttestationClientAuthenticationProfileId,
} from './types';
