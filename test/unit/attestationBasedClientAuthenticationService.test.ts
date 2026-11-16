import { deflateSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type * as oidc from 'oidc-provider';
import { assertAttestationJwtAndPop } from '../../src/services/attestationBasedClientAuthenticationService';
import config from '../../src/config';

vi.mock('../../src/config', () => ({
  default: {
    openid4vcProfile: 'WEBUILD',
    ttl: { clientAttestation: 86400, clientAttestationPoP: 60 },
    weBuildAbcaStatusListAllowedOrigins: ['https://status.example'],
  },
}));

const now = Math.floor(Date.now() / 1000);
const statusUri = 'https://status.example/list';
let signer: Awaited<ReturnType<typeof generateKeyPair>>;
let confirmation: Awaited<ReturnType<typeof generateKeyPair>>;
let attestation: oidc.JWTVerificationResult;
let ctx: oidc.KoaContextWithOIDC;
let dpop: string;
const fetchMock = vi.fn();

async function statusToken(value = 0, bits = 1, key = signer.privateKey) {
  return new SignJWT({
    status_list: { bits, lst: deflateSync(Buffer.from([value])).toString('base64url') },
    ttl: 300,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
    .setSubject(statusUri)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(key);
}

function popVerificationResult(iat: number): oidc.JWTVerificationResult {
  return {
    protectedHeader: { alg: 'ES256', typ: 'oauth-client-attestation-pop+jwt' },
    key: confirmation.publicKey,
    payload: { iat },
  };
}

async function run() {
  await assertAttestationJwtAndPop(ctx, attestation, popVerificationResult(now), {} as oidc.Client);
}

describe('WIA validation', () => {
  beforeEach(async () => {
    config.openid4vcProfile = 'WEBUILD';
    config.ttl.clientAttestation = 86400;
    config.ttl.clientAttestationPoP = 60;
    vi.useFakeTimers();
    vi.setSystemTime(now * 1000);
    signer = await generateKeyPair('ES256');
    confirmation = await generateKeyPair('ES256');
    const jwk = await exportJWK(confirmation.publicKey);
    dpop = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
      .sign(confirmation.privateKey);
    attestation = {
      protectedHeader: { alg: 'ES256' },
      key: signer.publicKey,
      payload: {
        wallet_name: 'Wallet',
        wallet_version: '1.0',
        wallet_solution_certification_information: {},
        iat: now,
        exp: now + 3600,
        cnf: { jwk },
        client_status: {
          exp: now + 31 * 86400,
          status: { status_list: { uri: statusUri, idx: 0 } },
        },
      },
    };
    ctx = { get: () => dpop, oidc: { route: 'token' } } as unknown as oidc.KoaContextWithOIDC;
    fetchMock.mockReset().mockResolvedValue(new Response(await statusToken()));
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('accepts a valid WIA without attestation aud, jti, or lifecycle tracking', async () => {
    await expect(run()).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      new URL(statusUri),
      expect.objectContaining({ redirect: 'error' }),
    );
  });

  it('skips all WE BUILD checks and status fetching when disabled', async () => {
    config.openid4vcProfile = 'DEFAULT';
    delete attestation.payload.wallet_name;
    delete attestation.payload.wallet_version;
    delete attestation.payload.wallet_solution_certification_information;
    delete attestation.payload.client_status;
    attestation.payload.exp = now + 86400;
    dpop = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', jwk: await exportJWK(signer.publicKey) })
      .sign(signer.privateKey);

    await expect(run()).resolves.toBeUndefined();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('still requires DPoP at the token endpoint when the profile is disabled', async () => {
    config.openid4vcProfile = 'DEFAULT';
    dpop = '';
    await expect(run()).rejects.toMatchObject({
      error_description: 'DPoP is required for token requests',
    });
  });

  it('still rejects future issuance times when the profile is disabled', async () => {
    config.openid4vcProfile = 'DEFAULT';
    attestation.payload.iat = now + 1;
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('applies the configured attestation maximum age under DEFAULT', async () => {
    config.openid4vcProfile = 'DEFAULT';
    config.ttl.clientAttestation = 120;
    attestation.payload.iat = now - 121;
    await expect(run()).rejects.toMatchObject({ error: 'use_fresh_attestation' });
    attestation.payload.iat = now - 120;
    await expect(run()).resolves.toBeUndefined();
  });

  it('bounds remaining validity when DEFAULT receives an attestation without iat', async () => {
    config.openid4vcProfile = 'DEFAULT';
    config.ttl.clientAttestation = 120;
    delete attestation.payload.iat;
    attestation.payload.exp = now + 121;
    await expect(run()).rejects.toMatchObject({ error: 'use_fresh_attestation' });
    attestation.payload.exp = now + 120;
    await expect(run()).resolves.toBeUndefined();
  });

  it('applies the configured PoP maximum age under DEFAULT', async () => {
    config.openid4vcProfile = 'DEFAULT';
    config.ttl.clientAttestationPoP = 10;
    const validate = (iat: number) =>
      assertAttestationJwtAndPop(ctx, attestation, popVerificationResult(iat), {} as oidc.Client);
    await expect(validate(now - 11)).rejects.toMatchObject({ error: 'invalid_client_attestation' });
    await expect(validate(now + 1)).rejects.toMatchObject({ error: 'invalid_client_attestation' });
    await expect(validate(now - 10)).resolves.toBeUndefined();
  });

  it('keeps WEBUILD policy independent of the configurable maximum ages', async () => {
    config.ttl.clientAttestation = 1;
    config.ttl.clientAttestationPoP = 1;
    attestation.payload.iat = now - 60;
    await expect(
      assertAttestationJwtAndPop(
        ctx,
        attestation,
        popVerificationResult(now - 60),
        {} as oidc.Client,
      ),
    ).resolves.toBeUndefined();
  });

  it.each(['wallet_name', 'wallet_version', 'wallet_solution_certification_information'])(
    'rejects a missing WIA field: %s',
    async (field) => {
      delete attestation.payload[field];
      await expect(run()).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([{ iat: now + 0.5 }, { iat: now + 1 }, { exp: now }, { exp: now + 86400 }])(
    'rejects invalid temporal claims: %j',
    async (claims) => {
      Object.assign(attestation.payload, claims);
      await expect(run()).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it('accepts an omitted attestation iat', async () => {
    delete attestation.payload.iat;
    await expect(run()).resolves.toBeUndefined();
  });

  it('accepts a fractional attestation iat', async () => {
    attestation.payload.iat = now - 0.5;
    await expect(run()).resolves.toBeUndefined();
  });

  it('leaves expiration validation to the provider', async () => {
    attestation.payload.iat = now - 3600;
    attestation.payload.exp = now - 61;
    await expect(run()).resolves.toBeUndefined();
  });

  it('requires DPoP at the token endpoint', async () => {
    dpop = '';
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('DPoP is required'),
    });
  });

  it('allows PAR without a DPoP header', async () => {
    dpop = '';
    ctx = {
      get: () => dpop,
      oidc: { route: 'pushed_authorization_request' },
    } as unknown as oidc.KoaContextWithOIDC;
    await expect(run()).resolves.toBeUndefined();
  });

  it('rejects a different DPoP key', async () => {
    dpop = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', jwk: await exportJWK(signer.publicKey) })
      .sign(signer.privateKey);
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('DPoP key does not match'),
    });
  });

  it('rejects malformed DPoP', async () => {
    dpop = 'invalid';
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('DPoP key does not match'),
    });
  });

  it('rejects a missing status reference', async () => {
    delete attestation.payload.client_status;
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('invalid client_status'),
    });
  });

  it('requires at least 31 days of status maintenance', async () => {
    (attestation.payload.client_status as { exp: number }).exp--;
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('maintenance period below 31 days'),
    });
  });

  it('does not fetch an unconfigured origin', async () => {
    attestation.payload.client_status = {
      exp: now + 31 * 86400,
      status: { status_list: { uri: 'https://internal.example/list', idx: 0 } },
    };
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('client status could not be verified'),
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([1, 2, 4, 8])('rejects a nonzero status for %i-bit lists', async (bits) => {
    fetchMock.mockResolvedValue(new Response(await statusToken(1, bits)));
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('client status could not be verified'),
    });
  });

  it('rejects a list signed by another key', async () => {
    fetchMock.mockResolvedValue(new Response(await statusToken(0, 1, confirmation.privateKey)));
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('client status could not be verified'),
    });
  });

  it('checks the indexed entry rather than only the first status', async () => {
    attestation.payload.client_status = {
      exp: now + 31 * 86400,
      status: { status_list: { uri: statusUri, idx: 2 } },
    };
    fetchMock.mockResolvedValue(new Response(await statusToken(1 << 4, 2)));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
    fetchMock.mockResolvedValue(new Response(await statusToken(1, 2)));
    await expect(run()).resolves.toBeUndefined();
  });

  it.each([
    { sub: 'https://status.example/another-list', iat: now, exp: now + 300 },
    { sub: statusUri, iat: now - 600, exp: now - 1 },
    { sub: statusUri, iat: now + 1, exp: now + 300 },
  ])('rejects invalid status token claims: %j', async (claims) => {
    const token = await new SignJWT({
      ...claims,
      status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') },
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .sign(signer.privateKey);
    fetchMock.mockResolvedValue(new Response(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('rejects an oversized status token', async () => {
    fetchMock.mockResolvedValue(new Response('a'.repeat(256 * 1024 + 1)));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('limits decompressed status list size', async () => {
    const token = await new SignJWT({
      status_list: {
        bits: 1,
        lst: deflateSync(Buffer.alloc(1024 * 1024 + 1)).toString('base64url'),
      },
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .setSubject(statusUri)
      .setIssuedAt(now)
      .sign(signer.privateKey);
    fetchMock.mockResolvedValue(new Response(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('rejects an out-of-range status index', async () => {
    attestation.payload.client_status = {
      exp: now + 31 * 86400,
      status: { status_list: { uri: statusUri, idx: 8 } },
    };
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('client status could not be verified'),
    });
  });

  it('fails closed when status retrieval fails', async () => {
    fetchMock.mockRejectedValue(new Error('unavailable'));
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('client status could not be verified'),
    });
  });
});
