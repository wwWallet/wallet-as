import { describe, expect, it, vi } from 'vitest';
import { weBuildAttestationPayloadSchema } from '../../src/services/attestationBasedClientAuthentication/WeBuildProfile';

vi.mock('../../src/config', () => ({ default: {} }));

function payload() {
  return {
    sub: 'wallet',
    iat: 1000,
    exp: 4599,
    cnf: { jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
    wallet_name: 'Wallet',
    wallet_version: '1',
    wallet_solution_certification_information: {},
    client_status: {
      exp: 4000000,
      status: { status_list: { uri: 'https://status.example/list', idx: 0 } },
    },
  };
}

describe('WE BUILD WIA payload schema', () => {
  it('accepts extensions and an optional wallet link without modifying input', () => {
    const value = { ...payload(), wallet_link: 'https://wallet.example', extension: true };
    expect(weBuildAttestationPayloadSchema.parse(value)).toEqual(value);
  });

  it.each([
    'iat',
    'exp',
    'wallet_name',
    'wallet_version',
    'wallet_solution_certification_information',
    'client_status',
  ])('requires %s', (field) => {
    const value: Record<string, unknown> = payload();
    delete value[field];
    expect(weBuildAttestationPayloadSchema.safeParse(value).success).toBe(false);
  });

  it('accepts fractional NumericDates and a lifetime just below 24 hours', () => {
    const value = payload();
    value.iat = 1000.5;
    value.exp = value.iat + 86399.5;
    value.client_status.exp += 0.5;
    expect(weBuildAttestationPayloadSchema.safeParse(value).success).toBe(true);
  });

  it.each([undefined, null])('rejects absent certification information: %j', (certification) => {
    expect(
      weBuildAttestationPayloadSchema.safeParse({
        ...payload(),
        wallet_solution_certification_information: certification,
      }).success,
    ).toBe(false);
  });

  it.each([{}, 'certification', '', '   '])(
    'leaves certification content unspecified: %j',
    (certification) => {
      expect(
        weBuildAttestationPayloadSchema.safeParse({
          ...payload(),
          wallet_solution_certification_information: certification,
        }).success,
      ).toBe(true);
    },
  );

  it.each(['wallet_name', 'wallet_version'])('rejects blank %s', (field) => {
    expect(weBuildAttestationPayloadSchema.safeParse({ ...payload(), [field]: '  ' }).success).toBe(
      false,
    );
  });

  it('rejects an invalid optional wallet URI', () => {
    expect(
      weBuildAttestationPayloadSchema.safeParse({ ...payload(), wallet_link: 'not a URI' }).success,
    ).toBe(false);
  });

  it('validates profile claims without requiring provider-owned sub or cnf', () => {
    const profileClaims: Record<string, unknown> = payload();
    delete profileClaims.sub;
    delete profileClaims.cnf;
    expect(weBuildAttestationPayloadSchema.safeParse(profileClaims).success).toBe(true);
  });
});
