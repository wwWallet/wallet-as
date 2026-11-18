import { fetchStatusList, verifyStatusListJwt } from '@owf/token-status-list';
import * as oidc from 'oidc-provider';
import { compactVerify, exportJWK } from 'jose';
import config from '../../config';

export async function validateStatusList(
  attestation: oidc.JWTVerificationResult,
  reference: { uri: string; idx: number },
): Promise<void> {
  try {
    const origin = new URL(reference.uri).origin;
    if (!config.statusListAllowedOrigins.includes(origin)) {
      throw new Error('status list origin is not allowed');
    }

    const token = await fetchStatusList({
      uri: reference.uri,
      acceptedFormats: ['jwt'],
      customFetcher: (input, init) =>
        fetch(input, { ...init, redirect: 'error', signal: AbortSignal.timeout(5000) }),
    });
    if (typeof token !== 'string') {
      throw new Error('expected a JWT status list');
    }

    await verifyStatusListJwt({
      jwt: token,
      uri: reference.uri,
      idx: reference.idx,
      skewSeconds: 15,
      verifyJwsCallback: async () => {
        await compactVerify(token, attestation.key, {
          algorithms: ['ES256'],
        });
        const jwk = await exportJWK(attestation.key);
        if (!jwk.kty) {
          throw new Error('attestation signing key has no key type');
        }
        return { verified: true, signerJwk: { ...jwk, kty: jwk.kty } };
      },
    });
  } catch {
    throw new oidc.errors.InvalidClientAttestation('client status could not be verified as valid');
  }
}
