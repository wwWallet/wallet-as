import { X509Certificate } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import * as oidc from 'oidc-provider';
import {
  calculateJwkThumbprint,
  decodeProtectedHeader,
  exportJWK,
  importX509,
  jwtVerify,
  type JWK,
} from 'jose';
import config from '../config';
import { verifyX5C } from 'wallet-common';

const MAX_X5C_CERTIFICATES = 5;
const MAX_X5C_CERTIFICATE_LENGTH = 16 * 1024;
const BASE64_CERTIFICATE_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

function parseX5C(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_X5C_CERTIFICATES) {
    throw new oidc.errors.InvalidClientAttestation('invalid client attestation x5c chain');
  }

  return value.map((certificate) => {
    if (
      typeof certificate !== 'string' ||
      certificate.length === 0 ||
      certificate.length > MAX_X5C_CERTIFICATE_LENGTH ||
      certificate.length % 4 !== 0 ||
      !BASE64_CERTIFICATE_PATTERN.test(certificate)
    ) {
      throw new oidc.errors.InvalidClientAttestation('invalid client attestation x5c certificate');
    }

    return certificate;
  });
}

function certificateToPem(certificate: string): string {
  const lines = certificate.match(/.{1,64}/g)?.join('\n') ?? certificate;
  return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----`;
}

function assertNumericDate(value: unknown, claim: string): number {
  if (!Number.isInteger(value) || typeof value !== 'number') {
    throw new oidc.errors.InvalidClientAttestation(`${claim} must be an integer NumericDate`);
  }

  return value;
}

export async function getAttestationSignaturePublicKey(
  _ctx: oidc.KoaContextWithOIDC,
  header: oidc.UnknownObject,
  _payload: oidc.UnknownObject,
  _client: oidc.Client,
): Promise<JWK> {
  if (header.alg !== 'ES256') {
    throw new oidc.errors.InvalidClientAttestation('unsupported client attestation alg');
  }
  const certificateChain = parseX5C(header.x5c);
  try {
    const leafCertificate = new X509Certificate(Buffer.from(certificateChain[0], 'base64'));
    if (leafCertificate.ca) {
      throw new Error('CA certificates cannot sign Wallet Instance Attestations');
    }
  } catch {
    throw new oidc.errors.InvalidClientAttestation(
      'invalid client attestation signing certificate',
    );
  }

  if (config.trustedRootCertificates.length === 0) {
    throw new oidc.errors.InvalidClientAttestation('no Wallet Provider trust anchors configured');
  }

  let trusted: boolean;
  try {
    trusted = await verifyX5C(certificateChain, config.trustedRootCertificates);
  } catch {
    trusted = false;
  }
  if (!trusted) {
    throw new oidc.errors.InvalidClientAttestation('untrusted client attestation x5c chain');
  }

  try {
    return await exportJWK(await importX509(certificateToPem(certificateChain[0]), header.alg));
  } catch {
    throw new oidc.errors.InvalidClientAttestation(
      'invalid client attestation signing certificate',
    );
  }
}

export async function assertAttestationJwtAndPop(
  ctx: oidc.KoaContextWithOIDC,
  attestation: oidc.JWTVerificationResult,
  _pop: oidc.JWTVerificationResult,
  _client: oidc.Client,
): Promise<void> {
  const payload = attestation.payload;
  const now = Math.floor(Date.now() / 1000);
  // The provider validates NumericDate types. Draft 10 permits an omitted iat.
  const issuedAt = payload.iat;
  const expiresAt = assertNumericDate(payload.exp, 'attestation exp');
  if (typeof issuedAt === 'number' && (issuedAt > now || expiresAt <= issuedAt)) {
    throw new oidc.errors.InvalidClientAttestation(
      'attestation iat is in the future or exp is not after iat',
    );
  }
  if (ctx.oidc.route === 'token' && !ctx.get('DPoP')) {
    throw new oidc.errors.InvalidClientAttestation('DPoP is required for token requests');
  }

  if (config.openid4vcProfile === 'WEBUILD') {
    await assertAttestationJwtAndPopWeBuildProfile(ctx, attestation, _pop, _client);
  } else {
    if (typeof issuedAt === 'number') {
      if (now - issuedAt > config.ttl.clientAttestation) {
        throw new oidc.errors.UseFreshAttestation('attestation is too old');
      }
    } else if (expiresAt - now > config.ttl.clientAttestation) {
      throw new oidc.errors.UseFreshAttestation('attestation exp is too far in the future');
    }
    const popIssuedAt = _pop.payload.iat;
    if (
      typeof popIssuedAt !== 'number' ||
      !Number.isFinite(popIssuedAt) ||
      popIssuedAt > now ||
      now - popIssuedAt > config.ttl.clientAttestationPoP
    ) {
      throw new oidc.errors.InvalidClientAttestation('PoP iat is outside the allowed age window');
    }
  }
}

async function assertAttestationJwtAndPopWeBuildProfile(
  ctx: oidc.KoaContextWithOIDC,
  attestation: oidc.JWTVerificationResult,
  _pop: oidc.JWTVerificationResult,
  _client: oidc.Client,
): Promise<void> {
  const payload = attestation.payload;
  for (const name of ['wallet_name', 'wallet_version']) {
    if (typeof payload[name] !== 'string' || payload[name].trim().length === 0) {
      throw new oidc.errors.InvalidClientAttestation(`invalid ${name}`);
    }
  }
  const certification = payload.wallet_solution_certification_information;
  if (
    certification === undefined ||
    certification === null ||
    (typeof certification === 'string' && certification.trim().length === 0)
  ) {
    throw new oidc.errors.InvalidClientAttestation('wallet certification information missing');
  }

  const issuedAt = payload.iat;
  const expiresAt = payload.exp as number;
  if (typeof issuedAt === 'number' && expiresAt - issuedAt >= 86400) {
    throw new oidc.errors.InvalidClientAttestation('invalid WIA lifetime (must be below 24 hours)');
  }

  const dpop = ctx.get('DPoP');
  if (dpop) {
    try {
      const confirmation = payload.cnf as { jwk: JWK };
      const dpopKey = decodeProtectedHeader(dpop).jwk;
      if (
        !dpopKey ||
        (await calculateJwkThumbprint(dpopKey)) !== (await calculateJwkThumbprint(confirmation.jwk))
      ) {
        throw new Error('key mismatch');
      }
    } catch {
      throw new oidc.errors.InvalidClientAttestation('DPoP key does not match WIA cnf.jwk');
    }
  }

  await validateRevocationStatus(attestation);
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

async function validateRevocationStatus(attestation: oidc.JWTVerificationResult): Promise<void> {
  const status = asRecord(attestation.payload.client_status);
  const reference = asRecord(asRecord(status?.status)?.status_list);
  const now = Math.floor(Date.now() / 1000);
  if (
    typeof status?.exp !== 'number' ||
    !Number.isSafeInteger(status.exp) ||
    status.exp - now < 31 * 86400 ||
    typeof reference?.uri !== 'string' ||
    !Number.isSafeInteger(reference.idx) ||
    (reference.idx as number) < 0
  ) {
    throw new oidc.errors.InvalidClientAttestation(
      'invalid client_status or maintenance period below 31 days',
    );
  }

  try {
    const url = new URL(reference.uri);
    if (
      url.username ||
      url.password ||
      url.hash ||
      !config.weBuildAbcaStatusListAllowedOrigins.includes(url.origin) ||
      (url.protocol !== 'https:' &&
        !(
          process.env.NODE_ENV !== 'production' &&
          url.protocol === 'http:' &&
          ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)
        ))
    ) {
      throw new Error('status list origin is not allowed');
    }
    const response = await fetch(url, {
      headers: { Accept: 'application/statuslist+jwt' },
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
    });
    if (!response.ok || !response.body) throw new Error('status list unavailable');
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > 256 * 1024) {
          await reader.cancel();
          throw new Error('status list token too large');
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    // Minimal signer policy: the status list must use the WIA signing key.
    const verified = await jwtVerify(Buffer.concat(chunks).toString('utf8'), attestation.key, {
      algorithms: ['ES256'],
      typ: 'statuslist+jwt',
      subject: reference.uri,
      requiredClaims: ['sub', 'iat', 'status_list'],
    });
    const list = asRecord(verified.payload.status_list);
    const bits = list?.bits;
    if (
      typeof verified.payload.iat !== 'number' ||
      verified.payload.iat > now ||
      (verified.payload.ttl !== undefined &&
        (typeof verified.payload.ttl !== 'number' ||
          verified.payload.ttl <= 0 ||
          now >= verified.payload.iat + verified.payload.ttl)) ||
      typeof bits !== 'number' ||
      ![1, 2, 4, 8].includes(bits) ||
      typeof list?.lst !== 'string' ||
      !/^[A-Za-z0-9_-]+$/.test(list.lst)
    ) {
      throw new Error('invalid status list payload');
    }
    const bytes = inflateSync(Buffer.from(list.lst, 'base64url'), { maxOutputLength: 1024 * 1024 });
    const index = reference.idx as number;
    if (index >= bytes.length * (8 / bits)) throw new Error('status index out of bounds');
    const bitOffset = index * bits;
    const value = (bytes[Math.floor(bitOffset / 8)] >> (bitOffset % 8)) & ((1 << bits) - 1);
    if (value !== 0) throw new Error('WIA is revoked or not valid');
  } catch {
    throw new oidc.errors.InvalidClientAttestation('client status could not be verified as valid');
  }
}
