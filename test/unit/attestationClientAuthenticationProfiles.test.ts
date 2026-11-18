import { describe, expect, it, vi } from 'vitest';
import { loadAttestationClientAuthenticationProfile } from '../../src/services/attestationBasedClientAuthentication';

vi.mock('../../src/config', () => ({ default: {} }));

describe('attestation client authentication profile selection', () => {
  it.each(['DEFAULT', 'WEBUILD'])('loads the configured %s profile', (id) => {
    expect(loadAttestationClientAuthenticationProfile(id).id).toBe(id);
  });

  it.each(['', 'UNKNOWN', 'OPENID4VCI', 'constructor', '__proto__', 'toString'])(
    'rejects an unsupported profile instead of falling back: %s',
    (id) => {
      expect(() => loadAttestationClientAuthenticationProfile(id)).toThrow(
        `Unknown attestation client authentication profile: ${id}`,
      );
    },
  );
});
