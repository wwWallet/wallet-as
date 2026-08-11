import * as oidc from 'oidc-provider';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { evalMock } = vi.hoisted(() => ({ evalMock: vi.fn() }));
vi.mock('../../src/stores/dataStoreClient', () => ({
  dataStoreClient: { eval: evalMock },
}));

import { enforceWalletInstanceAttestationUse, requestFingerprint } from '../../src/services/walletInstanceAttestationUseService';

function context(route: string, body: Record<string, unknown>): oidc.KoaContextWithOIDC {
  return {
    request: { body },
    oidc: { route, params: body },
  } as unknown as oidc.KoaContextWithOIDC;
}

describe('Wallet Instance Attestation use reservation', () => {
  beforeEach(() => evalMock.mockReset());

  it('uses a stable fingerprint while ignoring fresh PoP values', () => {
    const first = context('token', { grant_type: 'authorization_code', code: 'code', client_attestation_pop: 'one' });
    const retry = context('token', { code: 'code', grant_type: 'authorization_code', client_attestation_pop: 'two' });
    expect(requestFingerprint(first)).toBe(requestFingerprint(retry));
  });

  it('accepts an atomic idempotent reservation', async () => {
    evalMock.mockResolvedValue(1);
    await expect(enforceWalletInstanceAttestationUse(
      context('pushed_authorization_request', { client_id: 'wallet', dpop_jkt: 'jkt' }),
      { jti: 'wia-id', sub: 'wallet', exp: Math.floor(Date.now() / 1000) + 300 },
      'jkt',
    )).resolves.toBeUndefined();
    expect(evalMock).toHaveBeenCalledOnce();
  });

  it('rejects a WIA already reserved by another issuance request', async () => {
    evalMock.mockResolvedValue(0);
    await expect(enforceWalletInstanceAttestationUse(
      context('token', { grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code', 'pre-authorized_code': 'another-code' }),
      { jti: 'wia-id', sub: 'wallet', exp: Math.floor(Date.now() / 1000) + 300 },
      'jkt',
    )).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });
});
