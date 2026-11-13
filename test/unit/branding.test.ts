import path from 'node:path';
import { createRequire } from 'node:module';
import { runInNewContext } from 'node:vm';
import { describe, expect, it } from 'vitest';

const { renderFile } = createRequire(import.meta.url)('pug');
const baseUrl = 'https://example.org/as';

function render(
  view: string,
  client = { clientName: 'Issuer' } as {
    clientName?: string;
    clientId?: string;
    logoUri?: string;
  },
) {
  return renderFile(path.resolve(`src/views/${view}.pug`), {
    displayName: 'Example & Wallet',
    baseUrl,
    client,
    params: {},
    uid: 'test',
  });
}

describe('branding views', () => {
  it.each(['index', 'login', 'consent'])(
    'renders the configured name and base-path-aware icons in %s',
    (view) => {
      const html = render(view);
      expect(html).toContain('<title>Example &amp; Wallet');
      expect(html).toContain(`<base href="${baseUrl}/">`);
    },
  );

  it.each(['index', 'login', 'consent', 'pid-callback'])(
    'renders a favicon without a webmanifest in %s',
    (view) => {
      const html = render(view);
      expect(html).toContain('<link rel="icon" href="images/favicon.ico">');
      expect(html).not.toContain('rel="manifest"');
    },
  );

  it('renders the PID callback with a fixed title and no base URL', () => {
    const html = render('pid-callback');
    expect(html).toContain('<title>Completing sign-in…</title>');
    expect(html).not.toContain('<base ');
  });

  it('renders home branding and the wwWallet attribution link', () => {
    const html = render('index');
    expect(html).toContain('<h1 class="home__title">Example &amp; Wallet</h1>');
    expect(html).toContain('Powered by&nbsp');
    expect(html).toContain('href="https://github.com/wwWallet"');
  });

  it('renders the AS logo with an accessible name and an image-error fallback', () => {
    const html = render('consent');
    expect(html).toContain('src="images/logo.png"');
    expect(html).toContain('alt="Example &amp; Wallet logo"');
    expect(html).toContain('onerror="this.hidden=true;this.nextElementSibling.hidden=false"');
    expect(html).toContain('<span hidden>AS</span>');
  });

  it.each([
    { clientName: 'Issuer', clientId: 'wallet-client', initial: 'I', name: 'Issuer' },
    { clientId: 'wallet-client', initial: 'W', name: 'wallet-client' },
    { clientName: '', clientId: 'wallet-client', initial: 'W', name: 'wallet-client' },
  ])('uses $initial as the client fallback for $name', ({ initial, name, ...client }) => {
    const withoutLogo = render('consent', client);
    expect(withoutLogo).toContain(`<div class="consent__app-circle"><span>${initial}</span></div>`);

    const logoUri = 'https://example.org/client-logo.png';
    const withLogo = render('consent', { ...client, logoUri });
    const clientLogo = withLogo.match(
      /<img src="https:\/\/example.org\/client-logo.png" alt="([^"]*)" onerror="([^"]*)"><span hidden>([^<]*)<\/span>/,
    );
    expect(clientLogo).not.toBeNull();
    expect(clientLogo![1]).toBe(`${name} logo`);
    expect(clientLogo![3]).toBe(initial);

    const image = { hidden: false, nextElementSibling: { hidden: true } };
    runInNewContext(`(function () { ${clientLogo![2]} }).call(image)`, { image });
    expect(image.hidden).toBe(true);
    expect(image.nextElementSibling.hidden).toBe(false);
  });
});
