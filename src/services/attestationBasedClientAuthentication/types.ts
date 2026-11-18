import type * as oidc from 'oidc-provider';

export type AttestationClientAuthenticationProfileId = 'DEFAULT' | 'WEBUILD';

export interface AttestationValidationInput {
  attestation: oidc.JWTVerificationResult;
}

// Called after provider verification and the service's shared validation.
// Rejects with an oidc-provider error when the profile's policy is not satisfied.
export interface AttestationClientAuthenticationProfile {
  readonly id: AttestationClientAuthenticationProfileId;
  validate(input: AttestationValidationInput): Promise<void>;
}
