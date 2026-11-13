import { afterEach, describe, expect, it, vi } from 'vitest';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe('PID authentication eligibility', () => {
  it.each([undefined, '', '   '])(
    'blocks the default PID scopes when config is %j',
    async (value) => {
      vi.stubEnv('PID_AUTH_BLOCKED_SCOPES', value);
      vi.resetModules();
      const { isPidAuthAllowed } = await import('../../src/util/pidAuthEligibility');

      expect(isPidAuthAllowed('openid pid:sd_jwt_dc')).toBe(false);
      expect(isPidAuthAllowed('pid:mso_mdoc openid')).toBe(false);
      expect(isPidAuthAllowed('openid profile')).toBe(true);
      expect(isPidAuthAllowed('pid:sd_jwt_dc:other')).toBe(true);
      expect(isPidAuthAllowed(undefined)).toBe(true);
      expect(isPidAuthAllowed(null)).toBe(true);
      expect(isPidAuthAllowed('')).toBe(true);
    },
  );

  it('uses configured scopes, trimming whitespace and ignoring empty entries', async () => {
    vi.stubEnv('PID_AUTH_BLOCKED_SCOPES', ' custom:pid, , other:pid ,');
    vi.resetModules();
    const { isPidAuthAllowed } = await import('../../src/util/pidAuthEligibility');

    expect(isPidAuthAllowed('openid custom:pid')).toBe(false);
    expect(isPidAuthAllowed('  other:pid  openid ')).toBe(false);
    expect(isPidAuthAllowed('custom:pid:other')).toBe(true);
    expect(isPidAuthAllowed('openid pid:sd_jwt_dc pid:mso_mdoc')).toBe(true);
  });
});
