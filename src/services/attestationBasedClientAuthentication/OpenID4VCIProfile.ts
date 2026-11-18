import { zStatusClaim } from '@owf/token-status-list';
import * as oidc from 'oidc-provider';
import { validateStatusList } from './revocationStatus';
import type { AttestationClientAuthenticationProfile } from './types';

export const OpenID4VCIProfile: AttestationClientAuthenticationProfile = {
  id: 'DEFAULT',
  async validate({ attestation }) {
    await validateRevocationStatus(attestation);
  },
};

async function validateRevocationStatus(attestation: oidc.JWTVerificationResult): Promise<void> {
  if (attestation.payload.status === undefined) {
    return;
  }

  const status = zStatusClaim.safeParse(attestation.payload.status);
  if (!status.success) {
    throw new oidc.errors.InvalidClientAttestation(
      'invalid status or unsupported status mechanism',
    );
  }

  await validateStatusList(attestation, status.data.status_list);
}
