import { deflateSync } from 'node:zlib';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { exportJWK, generateKeyPair, SignJWT } from 'jose';
import type * as oidc from 'oidc-provider';
import { assertAttestationJwtAndPop } from '../../src/services/attestationBasedClientAuthenticationService';
import config from '../../src/config';

vi.mock('../../src/config', () => ({
  default: {
    openid4vcProfile: 'WEBUILD',
    statusListAllowedOrigins: ['https://status.example'],
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

function statusListResponse(body: string): Response {
  return new Response(body, { headers: { 'Content-Type': 'application/statuslist+jwt' } });
}

async function statusToken(value: number | number[] = 0, bits = 1, key = signer.privateKey) {
  return new SignJWT({
    status_list: {
      bits,
      lst: deflateSync(Buffer.from(typeof value === 'number' ? [value] : value)).toString(
        'base64url',
      ),
    },
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
        sub: 'wallet-client',
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
    fetchMock.mockReset().mockResolvedValue(statusListResponse(await statusToken()));
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it('accepts a valid WIA without attestation aud, jti, or lifecycle tracking', async () => {
    await expect(run()).resolves.toBeUndefined();
    expect(fetchMock).toHaveBeenCalledWith(
      statusUri,
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

  describe('OpenID4VCI status', () => {
    beforeEach(() => {
      config.openid4vcProfile = 'DEFAULT';
      delete attestation.payload.client_status;
      attestation.payload.status = { status_list: { uri: statusUri, idx: 0 } };
    });

    it('accepts a valid status without WE BUILD maintenance metadata', async () => {
      await expect(run()).resolves.toBeUndefined();
      expect(fetchMock).toHaveBeenCalledOnce();
    });

    it('accepts absent status without fetching', async () => {
      delete attestation.payload.status;
      await expect(run()).resolves.toBeUndefined();
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it.each([
      null,
      [],
      {},
      { other: {} },
      { status_list: {} },
      { status_list: { uri: statusUri, idx: -1 } },
      { status_list: { uri: statusUri, idx: 0.5 } },
    ])('rejects malformed or unsupported status: %j', async (status) => {
      attestation.payload.status = status;
      await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it.each(['revoked', 'wrong key', 'unavailable', 'untrusted origin', 'out of bounds'])(
      'rejects status when %s',
      async (failure) => {
        if (failure === 'revoked') {
          fetchMock.mockResolvedValue(statusListResponse(await statusToken(1)));
        } else if (failure === 'wrong key') {
          fetchMock.mockResolvedValue(
            statusListResponse(await statusToken(0, 1, confirmation.privateKey)),
          );
        } else if (failure === 'unavailable') {
          fetchMock.mockRejectedValue(new Error('unavailable'));
        } else {
          attestation.payload.status = {
            status_list: {
              uri: failure === 'untrusted origin' ? 'https://internal.example/list' : statusUri,
              idx: failure === 'out of bounds' ? 8 : 0,
            },
          };
        }
        await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
        if (failure === 'untrusted origin') expect(fetchMock).not.toHaveBeenCalled();
      },
    );
  });

  it('still requires DPoP at the token endpoint when the profile is disabled', async () => {
    config.openid4vcProfile = 'DEFAULT';
    dpop = '';
    await expect(run()).rejects.toMatchObject({
      error_description: 'DPoP is required for token requests',
    });
  });

  it('does not add future-iat rejection under DEFAULT', async () => {
    config.openid4vcProfile = 'DEFAULT';
    attestation.payload.iat = now + 1;
    await expect(run()).resolves.toBeUndefined();
  });

  it('does not impose exp-after-iat under DEFAULT', async () => {
    config.openid4vcProfile = 'DEFAULT';
    attestation.payload.iat = now + 3600;
    await expect(run()).resolves.toBeUndefined();
  });

  it('allows fractional attestation exp', async () => {
    attestation.payload.exp = now + 3600.5;
    await expect(run()).resolves.toBeUndefined();
  });

  it('accepts an unexpired DEFAULT attestation older than 24 hours', async () => {
    config.openid4vcProfile = 'DEFAULT';
    attestation.payload.iat = now - 2 * 86400;
    await expect(run()).resolves.toBeUndefined();
  });

  it('does not cap DEFAULT attestation remaining validity', async () => {
    config.openid4vcProfile = 'DEFAULT';
    attestation.payload.exp = now + 7 * 86400;
    await expect(run()).resolves.toBeUndefined();
  });

  it.each(['DEFAULT', 'WEBUILD'] as const)(
    'leaves PoP freshness to the provider under %s',
    async (profile) => {
      config.openid4vcProfile = profile;
      await expect(
        assertAttestationJwtAndPop(
          ctx,
          attestation,
          popVerificationResult(now - 3600),
          {} as oidc.Client,
        ),
      ).resolves.toBeUndefined();
    },
  );

  it.each(['wallet_name', 'wallet_version', 'wallet_solution_certification_information'])(
    'rejects a missing WIA field: %s',
    async (field) => {
      delete attestation.payload[field];
      await expect(run()).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([{ exp: now }, { exp: now + 86400 }])(
    'rejects invalid temporal claims: %j',
    async (claims) => {
      Object.assign(attestation.payload, claims);
      await expect(run()).rejects.toThrow();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it.each([-1, 0, 86400, 86401])(
    'rejects a WIA lifetime of %i seconds before fetching status',
    async (lifetime) => {
      attestation.payload.exp = now + lifetime;
      await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it('accepts a WIA lifetime just below 24 hours', async () => {
    attestation.payload.exp = now + 86399;
    await expect(run()).resolves.toBeUndefined();
  });

  it('rejects an omitted WE BUILD attestation iat', async () => {
    delete attestation.payload.iat;
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
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

  it('allows a separate DPoP key alongside attestation PoP', async () => {
    dpop = await new SignJWT({})
      .setProtectedHeader({ alg: 'ES256', jwk: await exportJWK(signer.publicKey) })
      .sign(signer.privateKey);
    await expect(run()).resolves.toBeUndefined();
  });

  it('rejects a missing status reference', async () => {
    delete attestation.payload.client_status;
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('invalid client_status'),
    });
  });

  it.each(['DEFAULT', 'WEBUILD'] as const)(
    'rejects malformed status references before fetching under %s',
    async (profile) => {
      config.openid4vcProfile = profile;
      for (const status of [
        null,
        [],
        {},
        { status_list: null },
        { status_list: { uri: '', idx: 0 } },
        { status_list: { uri: statusUri, idx: '0' } },
        { status_list: { uri: statusUri, idx: -1 } },
        { status_list: { uri: statusUri, idx: 0.5 } },
        { status_list: { uri: statusUri, idx: Number.MAX_SAFE_INTEGER + 1 } },
      ]) {
        if (profile === 'DEFAULT') attestation.payload.status = status;
        else attestation.payload.client_status = { exp: now + 31 * 86400, status };
        await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
        expect(fetchMock).not.toHaveBeenCalled();
      }
    },
  );

  it.each([undefined, null, '9999999999', Number.POSITIVE_INFINITY])(
    'rejects invalid client_status expiry before fetching: %j',
    async (exp) => {
      attestation.payload.client_status = {
        exp,
        status: { status_list: { uri: statusUri, idx: 0 } },
      };
      await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

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
    fetchMock.mockResolvedValue(statusListResponse(await statusToken([1, 0], bits)));
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('client status could not be verified'),
    });
  });

  it.each([1, 2, 4, 8])('accepts an indexed valid entry in a %i-bit list', async (bits) => {
    attestation.payload.client_status = {
      exp: now + 31 * 86400,
      status: { status_list: { uri: statusUri, idx: 1 } },
    };
    fetchMock.mockResolvedValue(statusListResponse(await statusToken([1, 0], bits)));
    await expect(run()).resolves.toBeUndefined();
  });

  it('reads the backend wire format with invalid padding and a valid entry in the next byte', async () => {
    // StatusListService.encodeStatusList(10, [8]): LSB-first, unused entries invalid.
    const token = await new SignJWT({
      status_list: { bits: 1, lst: deflateSync(Buffer.from([0xff, 0xfe])).toString('base64url') },
      ttl: 300,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .setSubject(statusUri)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(signer.privateKey);
    fetchMock.mockResolvedValue(statusListResponse(token));
    attestation.payload.client_status = {
      exp: now + 31 * 86400,
      status: { status_list: { uri: statusUri, idx: 8 } },
    };
    await expect(run()).resolves.toBeUndefined();
    (
      attestation.payload.client_status as { status: { status_list: { idx: number } } }
    ).status.status_list.idx = 9;
    fetchMock.mockResolvedValue(statusListResponse(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it.each([
    Buffer.from('not a ZLIB stream'),
    Buffer.concat([deflateSync(Buffer.from([0])), deflateSync(Buffer.from([0]))]),
  ])('rejects malformed or concatenated compressed lists: %j', async (compressed) => {
    const token = await new SignJWT({
      status_list: { bits: 1, lst: compressed.toString('base64url') },
      ttl: 300,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .setSubject(statusUri)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(signer.privateKey);
    fetchMock.mockResolvedValue(statusListResponse(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('rejects an unsupported signing algorithm', async () => {
    const key = await generateKeyPair('ES384');
    attestation.key = key.publicKey;
    const token = await new SignJWT({
      status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') },
    })
      .setProtectedHeader({ alg: 'ES384', typ: 'statuslist+jwt' })
      .setSubject(statusUri)
      .setIssuedAt(now)
      .sign(key.privateKey);
    fetchMock.mockResolvedValue(statusListResponse(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('does not trust a key supplied in the status list header', async () => {
    const token = await new SignJWT({
      status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') },
    })
      .setProtectedHeader({
        alg: 'ES256',
        typ: 'statuslist+jwt',
        jwk: await exportJWK(confirmation.publicKey),
      })
      .setSubject(statusUri)
      .setIssuedAt(now)
      .sign(confirmation.privateKey);
    fetchMock.mockResolvedValue(statusListResponse(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('rejects a list signed by another key', async () => {
    fetchMock.mockResolvedValue(
      statusListResponse(await statusToken(0, 1, confirmation.privateKey)),
    );
    await expect(run()).rejects.toMatchObject({
      error_description: expect.stringContaining('client status could not be verified'),
    });
  });

  it('checks the indexed entry rather than only the first status', async () => {
    attestation.payload.client_status = {
      exp: now + 31 * 86400,
      status: { status_list: { uri: statusUri, idx: 2 } },
    };
    fetchMock.mockResolvedValue(statusListResponse(await statusToken(1 << 4, 2)));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
    fetchMock.mockResolvedValue(statusListResponse(await statusToken(1, 2)));
    await expect(run()).resolves.toBeUndefined();
  });

  it.each([
    { sub: 'https://status.example/another-list', iat: now, exp: now + 300 },
    { sub: statusUri, iat: now - 600, exp: now - 16 },
    { sub: statusUri, iat: now + 16, exp: now + 300 },
  ])('rejects invalid status token claims: %j', async (claims) => {
    const token = await new SignJWT({
      ...claims,
      status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') },
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .sign(signer.privateKey);
    fetchMock.mockResolvedValue(statusListResponse(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it.each(['DEFAULT', 'WEBUILD'] as const)(
    'delegates status token claim validation under %s',
    async (profile) => {
      config.openid4vcProfile = profile;
      if (profile === 'DEFAULT') {
        attestation.payload.status = { status_list: { uri: statusUri, idx: 0 } };
      }
      for (const claims of [
        { iat: undefined },
        { iat: 'invalid' },
        { iat: now + 16 },
        { nbf: now + 16 },
        { exp: now - 16 },
        { sub: undefined },
        { ttl: 0 },
        { ttl: -1 },
        { ttl: '300' },
      ]) {
        const token = await new SignJWT({
          sub: statusUri,
          iat: now,
          status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') },
          ...claims,
        })
          .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
          .sign(signer.privateKey);
        fetchMock.mockResolvedValue(statusListResponse(token));
        await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
      }
    },
  );

  it('rejects an oversized status token', async () => {
    fetchMock.mockResolvedValue(statusListResponse('a'.repeat(16 * 1024 * 1024 + 1)));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it.each(['text/plain', 'application/statuslist+cwt'])(
    'rejects an unexpected status list content type: %s',
    async (contentType) => {
      fetchMock.mockResolvedValue(
        new Response(await statusToken(), { headers: { 'Content-Type': contentType } }),
      );
      await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
    },
  );

  it('cancels an oversized streamed response without reading the remaining body', async () => {
    const cancel = vi.fn();
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(16 * 1024 * 1024 + 1));
      },
      cancel,
    });
    fetchMock.mockResolvedValue(
      new Response(body, { headers: { 'Content-Type': 'application/statuslist+jwt' } }),
    );
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it.each([0, -1, '300'])('rejects an invalid status list ttl: %j', async (ttl) => {
    const token = await new SignJWT({
      status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') },
      ttl,
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .setSubject(statusUri)
      .setIssuedAt(now - 300)
      .setExpirationTime(now + 300)
      .sign(signer.privateKey);
    fetchMock.mockResolvedValue(statusListResponse(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it.each(['DEFAULT', 'WEBUILD'] as const)(
    'accepts a freshly fetched unexpired list after iat + ttl under %s',
    async (profile) => {
      config.openid4vcProfile = profile;
      if (profile === 'DEFAULT') {
        attestation.payload.status = { status_list: { uri: statusUri, idx: 0 } };
      }
      const token = await new SignJWT({
        status_list: { bits: 1, lst: deflateSync(Buffer.from([0])).toString('base64url') },
        ttl: 300,
      })
        .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
        .setSubject(statusUri)
        .setIssuedAt(now - 600)
        .setExpirationTime(now + 300)
        .sign(signer.privateKey);
      fetchMock.mockResolvedValue(statusListResponse(token));
      await expect(run()).resolves.toBeUndefined();
    },
  );

  it.each([0, 3, '1'])('rejects unsupported status bit widths: %j', async (bits) => {
    const token = await new SignJWT({
      status_list: { bits, lst: deflateSync(Buffer.from([0])).toString('base64url') },
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .setSubject(statusUri)
      .setIssuedAt(now)
      .sign(signer.privateKey);
    fetchMock.mockResolvedValue(statusListResponse(token));
    await expect(run()).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('limits decompressed status list size', async () => {
    const token = await new SignJWT({
      status_list: {
        bits: 1,
        lst: deflateSync(Buffer.alloc(16 * 1024 * 1024 + 1)).toString('base64url'),
      },
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt' })
      .setSubject(statusUri)
      .setIssuedAt(now)
      .sign(signer.privateKey);
    fetchMock.mockResolvedValue(statusListResponse(token));
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
