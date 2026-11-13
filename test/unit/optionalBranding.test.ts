import fs from 'node:fs';
import { describe, expect, it, vi } from 'vitest';

// These page renders do not need a live data store.
vi.mock('../../src/stores/dataStoreClient', () => ({ dataStoreClient: {} }));
vi.mock('../../src/config', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/config')>();
  return {
    default: {
      ...actual.default,
      authenticator: 'user-pass-pid',
      preAuthorizedCredentialIssuance: false,
    },
  };
});

import { createApp } from '../../src/app';

describe('optional public branding', () => {
  it('starts and renders every page when branding files are absent', async () => {
    const originalExistsSync = fs.existsSync;
    const existsSpy = vi.spyOn(fs, 'existsSync').mockImplementation((file) => {
      if (String(file).includes('/public/images/')) return false;
      return originalExistsSync(file);
    });

    try {
      const { app } = createApp();

      for (const view of ['index', 'login', 'consent', 'pid-callback']) {
        const html = await new Promise<string>((resolve, reject) => {
          app.render(
            view,
            { client: { clientName: 'Issuer' }, params: {}, uid: 'test' },
            (error, rendered) => (error ? reject(error) : resolve(rendered)),
          );
        });
        expect(html).toContain('<!DOCTYPE html>');
        if (view === 'consent') {
          expect(html).toContain('src="images/logo.png"');
          expect(html).toContain('onerror="this.hidden=true;this.nextElementSibling.hidden=false"');
          expect(html).toContain('<span hidden>AS</span>');
        }
      }
    } finally {
      existsSpy.mockRestore();
    }
  });
});
