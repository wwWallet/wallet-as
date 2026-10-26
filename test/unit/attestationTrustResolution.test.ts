import { execFileSync } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { importPKCS8, jwtVerify, SignJWT } from 'jose';
import type * as oidc from 'oidc-provider';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const config = vi.hoisted(() => ({ trustedRootCertificates: [] as string[] }));
vi.mock('../../src/config', () => ({ default: config }));

import { getAttestationSignaturePublicKey } from '../../src/services/attestationBasedClientAuthenticationService';

describe('attestation trust resolution', () => {
  let directory: string;
  let rootPem: string;
  let otherRootPem: string;
  let leafPem: string;
  let leafKeyPem: string;
  let leafBase64: string;

  function openssl(...args: string[]) {
    execFileSync('openssl', args, { cwd: directory, stdio: 'pipe' });
  }

  function resolve(x5c: unknown = [leafBase64], alg = 'ES256') {
    return getAttestationSignaturePublicKey(
      {} as oidc.KoaContextWithOIDC,
      { alg, x5c },
      {},
      {} as oidc.Client,
    );
  }

  beforeAll(() => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), 'wallet-as-trust-test-'));
    for (const name of ['root', 'other-root']) {
      openssl(
        'req',
        '-x509',
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:P-256',
        '-nodes',
        '-keyout',
        `${name}.key`,
        '-out',
        `${name}.pem`,
        '-days',
        '30',
        '-subj',
        `/CN=${name}`,
        '-addext',
        'basicConstraints=critical,CA:TRUE',
        '-addext',
        'keyUsage=critical,keyCertSign,cRLSign',
      );
    }
    openssl(
      'req',
      '-new',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:P-256',
      '-nodes',
      '-keyout',
      'leaf.key',
      '-out',
      'leaf.csr',
      '-subj',
      '/CN=Test Wallet Provider',
    );
    fs.writeFileSync(
      path.join(directory, 'leaf.ext'),
      'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n',
    );
    openssl(
      'x509',
      '-req',
      '-in',
      'leaf.csr',
      '-CA',
      'root.pem',
      '-CAkey',
      'root.key',
      '-CAcreateserial',
      '-out',
      'leaf.pem',
      '-days',
      '1',
      '-extfile',
      'leaf.ext',
    );
    rootPem = fs.readFileSync(path.join(directory, 'root.pem'), 'utf8');
    otherRootPem = fs.readFileSync(path.join(directory, 'other-root.pem'), 'utf8');
    leafPem = fs.readFileSync(path.join(directory, 'leaf.pem'), 'utf8');
    leafKeyPem = fs.readFileSync(path.join(directory, 'leaf.key'), 'utf8');
    leafBase64 = new X509Certificate(leafPem).raw.toString('base64');
  });

  afterAll(() => {
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
  });

  beforeEach(() => {
    config.trustedRootCertificates = [rootPem];
  });

  afterEach(() => vi.useRealTimers());

  it('resolves a trusted leaf to its public JWK and verifies a signed JWT', async () => {
    const jwk = await resolve();
    const expected = new X509Certificate(leafPem).publicKey.export({ format: 'jwk' });
    expect(jwk).toMatchObject(expected);
    expect(jwk).not.toHaveProperty('d');
    const token = await new SignJWT({ sub: 'wallet' })
      .setProtectedHeader({ alg: 'ES256', typ: 'oauth-client-attestation+jwt', x5c: [leafBase64] })
      .sign(await importPKCS8(leafKeyPem, 'ES256'));
    const verified = await jwtVerify(token, (header) =>
      getAttestationSignaturePublicKey(
        {} as oidc.KoaContextWithOIDC,
        header,
        {},
        {} as oidc.Client,
      ),
    );
    expect(verified.payload.sub).toBe('wallet');
    expect(verified.key).toHaveProperty('type', 'public');
  });

  it('accepts the presented chain including its trusted root', async () => {
    await expect(
      resolve([leafBase64, new X509Certificate(rootPem).raw.toString('base64')]),
    ).resolves.toMatchObject({ kty: 'EC', crv: 'P-256' });
  });

  it.each([
    undefined,
    [],
    'not-an-array',
    [42],
    [''],
    ['!!!!'],
    ['abc'],
    ['AAAA'],
    ['A'.repeat(16 * 1024 + 4)],
    Array(6).fill('AAAA'),
  ])('rejects missing, malformed, or oversized x5c (case %#)', async (x5c) => {
    // Explicit undefined must not select resolve's default fixture.
    await expect(
      getAttestationSignaturePublicKey(
        {} as oidc.KoaContextWithOIDC,
        { alg: 'ES256', x5c },
        {},
        {} as oidc.Client,
      ),
    ).rejects.toMatchObject({ error: 'invalid_client_attestation' });
  });

  it('rejects unsupported signing algorithms', async () => {
    await expect(resolve([leafBase64], 'ES384')).rejects.toMatchObject({
      error_description: 'unsupported client attestation alg',
    });
  });

  it('rejects a CA leaf even when that CA is trusted', async () => {
    await expect(
      resolve([new X509Certificate(rootPem).raw.toString('base64')]),
    ).rejects.toMatchObject({
      error_description: 'invalid client attestation signing certificate',
    });
  });

  it('rejects missing trust anchors', async () => {
    config.trustedRootCertificates = [];
    await expect(resolve()).rejects.toMatchObject({
      error_description: 'no Wallet Provider trust anchors configured',
    });
  });

  it('rejects a chain rooted in an untrusted CA', async () => {
    config.trustedRootCertificates = [otherRootPem];
    await expect(resolve()).rejects.toMatchObject({
      error_description: 'untrusted client attestation x5c chain',
    });
  });

  it('rejects a certificate with a tampered issuer signature', async () => {
    const tampered = Buffer.from(new X509Certificate(leafPem).raw);
    tampered[tampered.length - 1] ^= 1;
    await expect(resolve([tampered.toString('base64')])).rejects.toMatchObject({
      error_description: 'untrusted client attestation x5c chain',
    });
  });

  it('rejects an expired leaf', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.parse(new X509Certificate(leafPem).validTo) + 1000));
    await expect(resolve()).rejects.toMatchObject({
      error_description: 'untrusted client attestation x5c chain',
    });
  });

  it('rejects a not-yet-valid leaf', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date(Date.parse(new X509Certificate(leafPem).validFrom) - 1000));
    await expect(resolve()).rejects.toMatchObject({
      error_description: 'untrusted client attestation x5c chain',
    });
  });
});
