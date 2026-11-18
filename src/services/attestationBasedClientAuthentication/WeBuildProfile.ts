import * as oidc from 'oidc-provider';
import { validateStatusList } from './revocationStatus';
import type { AttestationClientAuthenticationProfile } from './types';

import { zStatusClaim } from '@owf/token-status-list';
import { z } from 'zod';

// WE BUILD rules for an already provider-validated WIA payload (CS-04 §§7.1–7.2,
// TS-03 v1.5.2 §2.3.1). The provider owns baseline claims, cnf and PoP validation.
// iat and exp are typed here for the lifetime check in the profile validate function.
export const weBuildAttestationPayloadSchema = z.looseObject({
  iat: z.number(),
  exp: z.number(),
  wallet_name: z.string().refine((value) => value.trim().length > 0),
  wallet_version: z.string().refine((value) => value.trim().length > 0),
  wallet_link: z.url().optional(),
  // TS-03 §2.3.1 explicitly leaves the certification content format undefined.
  wallet_solution_certification_information: z
    .unknown()
    .refine((value) => value != null, 'wallet certification information missing'),
  client_status: z.looseObject({
    exp: z.number(),
    status: zStatusClaim,
  }),
});

export type WeBuildAttestationPayload = z.infer<typeof weBuildAttestationPayloadSchema>;

export const WeBuildProfile: AttestationClientAuthenticationProfile = {
  id: 'WEBUILD',
  async validate({ attestation }) {
    const payload = weBuildAttestationPayloadSchema.safeParse(attestation.payload);
    if (!payload.success) {
      const issue = payload.error.issues[0];
      throw new oidc.errors.InvalidClientAttestation(
        `invalid ${issue.path.join('.')}: ${issue.message}`,
      );
    }
    const { iat, exp } = payload.data;
    if (exp <= iat || exp - iat >= 86400) {
      throw new oidc.errors.InvalidClientAttestation(
        'invalid WIA lifetime (must be positive and below 24 hours)',
      );
    }
    await validateRevocationStatus(attestation, payload.data.client_status);
  },
};

async function validateRevocationStatus(
  attestation: oidc.JWTVerificationResult,
  status: WeBuildAttestationPayload['client_status'],
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  if (status.exp - now < 31 * 86400) {
    throw new oidc.errors.InvalidClientAttestation(
      'invalid client_status or maintenance period below 31 days',
    );
  }
  await validateStatusList(attestation, status.status.status_list);
}
