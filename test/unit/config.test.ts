import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

describe('config', () => {
  const originalCwd = process.cwd();

  beforeEach(() => {
    // Deterministic test fixture only; never use this value in a deployment.
    vi.stubEnv('ABCA_CHALLENGE_SECRET', 'ab'.repeat(32));
    vi.stubEnv('DPOP_NONCE_SECRET', 'test-dpop-nonce-secret-0123456789ab');
    vi.stubEnv('OPENID4VC_PROFILE', 'DEFAULT');
    vi.stubEnv('WEBUILD_ABCA_STATUS_LIST_ALLOWED_ORIGINS', 'https://status.example');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  function writeClientsFile(root: string, clients: unknown) {
    const configDir = path.join(root, 'src/config');
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, 'oauth2clients.json'), JSON.stringify(clients), 'utf-8');
  }

  async function importConfigFromTempProject(clients: unknown, prepare?: (root: string) => void) {
    const tempProject = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-as-config-'));
    writeClientsFile(tempProject, clients);
    prepare?.(tempProject);
    process.chdir(tempProject);
    vi.resetModules();

    try {
      return await import('../../src/config');
    } finally {
      process.chdir(originalCwd);
    }
  }

  async function expectFatalConfig(loadConfig: () => Promise<unknown>, message: string | RegExp) {
    const exitSpy = vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`process.exit:${code}`);
    });
    const consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {});

    try {
      await expect(loadConfig()).rejects.toThrow('process.exit:1');
      expect(exitSpy).toHaveBeenCalledWith(1);
      expect(consoleSpy).toHaveBeenCalledWith(
        typeof message === 'string' ? message : expect.stringMatching(message),
      );
    } finally {
      exitSpy.mockRestore();
      consoleSpy.mockRestore();
    }
  }

  it('normalizes BASE_PATH and reads basic env vars', async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      INTROSPECTION_CLIENT: 'client-a',
      INTROSPECTION_CLIENT_SECRET: 'secret-a',
      BASE_PATH: 'as',
      AUTHORIZATION_CODE_TTL: '90',
      PRE_AUTHORIZED_CONSENT_CLIENT_IDS: 'wallet_issuer, test-client',
    };

    vi.resetModules();
    const config = (await import('../../src/config')).default;

    expect(config.introspectionClient).toBe('client-a');
    expect(config.introspectionClientSecret).toBe('secret-a');
    expect(config.basePath).toBe('/as');
    expect(config.authBrokerRedirectUri).toBe(
      'http://localhost:6060/interaction/authBroker/callback',
    );
    expect(config.ttl.authorizationCode).toBe(90);
    expect(config.preAuthorizedConsentClientIds).toEqual(['wallet_issuer', 'test-client']);

    process.env = originalEnv;
  });

  it('accepts BASE_PATH with leading/trailing slashes', async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      BASE_PATH: '/as/',
    };

    vi.resetModules();
    const config = (await import('../../src/config')).default;

    expect(config.basePath).toBe('/as');

    process.env = originalEnv;
  });

  it('uses SERVICE_URL as authoritative base for default auth broker redirect uri', async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      SERVICE_URL: 'https://qa-issuer.wwwallet.org/as',
      BASE_PATH: '/as',
      AUTH_BROKER_REDIRECT_URI: '',
    };

    vi.resetModules();
    const config = (await import('../../src/config')).default;

    expect(config.serviceUrl).toBe('https://qa-issuer.wwwallet.org/as');
    expect(config.authBrokerRedirectUri).toBe(
      'https://qa-issuer.wwwallet.org/as/interaction/authBroker/callback',
    );

    process.env = originalEnv;
  });

  it('loads oid clients from the project config file and preserves extra client metadata', async () => {
    const { default: config } = await importConfigFromTempProject([
      {
        client_id: 'wallet-client',
        client_secret: 'wallet-secret',
        redirect_uris: ['https://wallet.example/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        client_name: 'wwWallet Client',
        jwks_uri: 'https://wallet.example/jwks.json',
      },
    ]);

    expect(config.oidClients).toEqual([
      {
        client_id: 'wallet-client',
        client_secret: 'wallet-secret',
        redirect_uris: ['https://wallet.example/callback'],
        grant_types: ['authorization_code', 'refresh_token'],
        client_name: 'wwWallet Client',
        jwks_uri: 'https://wallet.example/jwks.json',
      },
    ]);
  });

  it('rejects oauth clients that do not match ClientMetadata requirements', async () => {
    await expect(
      importConfigFromTempProject([
        {
          client_id: 'broken-client',
          grant_types: ['authorization_code'],
        },
      ]),
    ).rejects.toThrow(/redirect_uris/);
  });

  it.each(['missing', 'malformed'])('exits when the OAuth2 clients file is %s', async (kind) => {
    await expectFatalConfig(
      () =>
        importConfigFromTempProject([], (root) => {
          const clientsFile = path.join(root, 'src/config/oauth2clients.json');
          if (kind === 'missing') {
            fs.unlinkSync(clientsFile);
          } else {
            fs.writeFileSync(clientsFile, '{', 'utf-8');
          }
        }),
      /^FATAL: Failed to parse OAuth2 clients file '.*oauth2clients\.json': /,
    );
  });

  it.each([
    [undefined, 'DEFAULT'],
    ['DEFAULT', 'DEFAULT'],
    ['WEBUILD', 'WEBUILD'],
  ])('reads OPENID4VC_PROFILE=%s as %s', async (value, profile) => {
    vi.stubEnv('OPENID4VC_PROFILE', value);
    const { default: config } = await importConfigFromTempProject([]);
    expect(config.openid4vcProfile).toBe(profile);
  });

  it.each(['', 'typo', 'true', 'HAIP', 'ETSI'])(
    'rejects unsupported OPENID4VC_PROFILE: %s',
    async (value) => {
      vi.stubEnv('OPENID4VC_PROFILE', value);
      await expect(importConfigFromTempProject([])).rejects.toThrow();
    },
  );

  it.each([undefined, '', ' , '])(
    'requires status origins under WEBUILD (case %#)',
    async (value) => {
      vi.stubEnv('OPENID4VC_PROFILE', 'WEBUILD');
      vi.stubEnv('WEBUILD_ABCA_STATUS_LIST_ALLOWED_ORIGINS', value);
      await expectFatalConfig(
        () => importConfigFromTempProject([]),
        'FATAL: WEBUILD_ABCA_STATUS_LIST_ALLOWED_ORIGINS is required when OPENID4VC_PROFILE=WEBUILD.',
      );
    },
  );

  it('does not require status origins under DEFAULT', async () => {
    vi.stubEnv('WEBUILD_ABCA_STATUS_LIST_ALLOWED_ORIGINS', undefined);
    const { default: config } = await importConfigFromTempProject([]);
    expect(config.weBuildAbcaStatusListAllowedOrigins).toEqual([]);
  });

  it('reads the WE BUILD status origin list', async () => {
    vi.stubEnv('OPENID4VC_PROFILE', 'WEBUILD');
    vi.stubEnv(
      'WEBUILD_ABCA_STATUS_LIST_ALLOWED_ORIGINS',
      ' https://one.example, https://two.example, ',
    );
    const { default: config } = await importConfigFromTempProject([]);
    expect(config.weBuildAbcaStatusListAllowedOrigins).toEqual([
      'https://one.example',
      'https://two.example',
    ]);
  });

  it.each([32, 33])('accepts a %i-character DPoP nonce secret', async (length) => {
    const secret = 's'.repeat(length);
    vi.stubEnv('DPOP_NONCE_SECRET', secret);
    const first = (await importConfigFromTempProject([])).default;
    const second = (await importConfigFromTempProject([])).default;

    expect(Buffer.isBuffer(first.dpopNonceSecret)).toBe(true);
    expect(first.dpopNonceSecret.length).toBe(32);
    expect(first.dpopNonceSecret).toEqual(createHash('sha256').update(secret).digest());
    expect(second.dpopNonceSecret).toEqual(first.dpopNonceSecret);
  });

  it.each([undefined, '', 's'.repeat(31)])(
    'rejects a missing or short DPoP nonce secret (case %#)',
    async (secret) => {
      vi.stubEnv('DPOP_NONCE_SECRET', secret);
      await expectFatalConfig(
        () => importConfigFromTempProject([]),
        'FATAL: DPOP_NONCE_SECRET must be configured with at least 32 characters.',
      );
    },
  );

  it('decodes the challenge secret into a stable 32-byte Buffer', async () => {
    vi.stubEnv('ABCA_CHALLENGE_SECRET', 'AB'.repeat(32));
    const first = (await importConfigFromTempProject([])).default;
    const second = (await importConfigFromTempProject([])).default;

    expect(Buffer.isBuffer(first.abcaChallengeSecret)).toBe(true);
    expect(first.abcaChallengeSecret.length).toBe(32);
    expect(first.abcaChallengeSecret).toEqual(Buffer.alloc(32, 0xab));
    expect(second.abcaChallengeSecret).toEqual(first.abcaChallengeSecret);
  });

  it.each([
    undefined,
    '',
    'ab'.repeat(31),
    'ab'.repeat(33),
    'a'.repeat(63),
    'gg'.repeat(32),
    `${'ab'.repeat(31)}a!`,
    ` ${'ab'.repeat(32)}`,
    `${'ab'.repeat(32)}\n`,
  ])('rejects a missing or malformed challenge secret (case %#)', async (secret) => {
    vi.stubEnv('ABCA_CHALLENGE_SECRET', secret);

    await expectFatalConfig(
      () => importConfigFromTempProject([]),
      'FATAL: ABCA_CHALLENGE_SECRET must contain exactly 64 hexadecimal characters (32 bytes).',
    );
  });

  it('does not allow production builds to use an insecure Data Store', async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      NODE_ENV: 'production',
      DATA_STORE_PASSWORD: undefined,
    };

    vi.resetModules();

    try {
      await expectFatalConfig(
        () => import('../../src/config'),
        'FATAL: Insecure data store found in production.',
      );
    } finally {
      process.env = originalEnv;
    }
  });
});
