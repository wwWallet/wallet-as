import { describe, expect, it, vi } from 'vitest';
import type { AccessToken, Client, KoaContextWithOIDC } from 'oidc-provider';

const ctx = {} as KoaContextWithOIDC;
const asClient = (client: { clientAuthMethod: string; clientId: string }) =>
  client as unknown as Client;
const asAccessToken = (token: { clientId: string }) => token as unknown as AccessToken;

describe('introspectionAllowedPolicy', () => {
  it('rejects non client_secret_basic auth', async () => {
    vi.resetModules();
    const { introspectionAllowedPolicy } = await import('../../src/util/introspectionHelpers');

    const client = asClient({ clientAuthMethod: 'none', clientId: 'client-a' });
    const token = asAccessToken({ clientId: 'client-a' });

    expect(introspectionAllowedPolicy(ctx, client, token)).toBe(false);
  });

  it('allows matching client and token', async () => {
    vi.resetModules();
    const { introspectionAllowedPolicy } = await import('../../src/util/introspectionHelpers');

    const client = asClient({
      clientAuthMethod: 'client_secret_basic',
      clientId: 'client-a',
    });
    const token = asAccessToken({ clientId: 'client-a' });

    expect(introspectionAllowedPolicy(ctx, client, token)).toBe(true);
  });

  it('allows the configured introspection client', async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      INTROSPECTION_CLIENT: 'introspect-client',
      INTROSPECTION_CLIENT_SECRET: 'secret',
    };

    vi.resetModules();
    const { introspectionAllowedPolicy } = await import('../../src/util/introspectionHelpers');

    const client = asClient({
      clientAuthMethod: 'client_secret_basic',
      clientId: 'introspect-client',
    });
    const token = asAccessToken({ clientId: 'other-client' });

    expect(introspectionAllowedPolicy(ctx, client, token)).toBe(true);

    process.env = originalEnv;
  });
});
