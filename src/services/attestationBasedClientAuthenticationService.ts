import * as oidc from "oidc-provider";
import { X509Certificate } from "node:crypto";
import { inflateSync } from "node:zlib";
import { calculateJwkThumbprint, decodeProtectedHeader, exportJWK, importJWK, importX509, jwtVerify, type JWK, type JWTPayload } from "jose";
import { verifyX5C } from "wallet-common";
import config from "../config";

const MAX_X5C_CERTIFICATES = 5;
const MAX_X5C_CERTIFICATE_LENGTH = 16 * 1024;
const BASE64_CERTIFICATE_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;
const PRIVATE_JWK_MEMBERS = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];
const MAX_STATUS_LIST_TOKEN_LENGTH = 256 * 1024;
const MAX_STATUS_LIST_DECOMPRESSED_LENGTH = 1024 * 1024;

async function readResponseTextLimited(response: Response, maximumBytes: number): Promise<string> {
  if (!response.body) return '';
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) throw new Error('status list response is too large');
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

function isConfiguredAlgorithm(
  value: unknown,
  configuredAlgorithms: readonly oidc.AsymmetricSigningAlgorithm[],
): value is oidc.AsymmetricSigningAlgorithm {
  return typeof value === 'string'
    && configuredAlgorithms.some((algorithm) => algorithm === value);
}

function parseX5C(value: unknown): string[] {
  if (
    !Array.isArray(value)
    || value.length === 0
    || value.length > MAX_X5C_CERTIFICATES
  ) {
    throw new oidc.errors.InvalidClientAttestation('invalid client attestation x5c chain');
  }

  return value.map((certificate) => {
    if (
      typeof certificate !== 'string'
      || certificate.length === 0
      || certificate.length > MAX_X5C_CERTIFICATE_LENGTH
      || certificate.length % 4 !== 0
      || !BASE64_CERTIFICATE_PATTERN.test(certificate)
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

function asRecord(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function assertPublicConfirmationJwk(value: unknown): asserts value is JWK {
  const jwk = asRecord(value);
  if (!jwk || PRIVATE_JWK_MEMBERS.some((member) => member in jwk)) {
    throw new oidc.errors.InvalidClientAttestation('client attestation cnf.jwk must be public');
  }
  const expectedAlgorithm = jwk.crv === 'P-256' ? 'ES256'
    : jwk.crv === 'P-384' ? 'ES384'
      : jwk.crv === 'P-521' ? 'ES512'
        : undefined;
  if (
    jwk.kty !== 'EC'
    || typeof jwk.x !== 'string'
    || typeof jwk.y !== 'string'
    || !expectedAlgorithm
    || (jwk.alg !== undefined && jwk.alg !== expectedAlgorithm)
  ) {
    throw new oidc.errors.InvalidClientAttestation('client attestation cnf.jwk is unsupported');
  }
}

function assertStatusListUrlAllowed(url: URL): void {
  if (url.username || url.password || (process.env.NODE_ENV === 'production' && url.protocol !== 'https:')) {
    throw new oidc.errors.InvalidClientAttestation('client status list URI is not allowed');
  }
  const configuredOrigins = (config.abca as typeof config.abca & { statusListAllowedOrigins?: string[] }).statusListAllowedOrigins ?? [];
  if (configuredOrigins.includes(url.origin)) return;
  if (process.env.NODE_ENV !== 'production' && url.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) return;
  throw new oidc.errors.InvalidClientAttestation('client status list URI is not allowed');
}

export function decodeStatusListEntry(payload: JWTPayload, index: number): boolean {
  const statusList = asRecord(payload.status_list);
  if (!Number.isSafeInteger(payload.ttl) || (payload.ttl as number) <= 0 || !statusList || statusList.bits !== 1 || typeof statusList.lst !== 'string') {
    throw new Error('invalid status list payload');
  }
  const bytes = inflateSync(Buffer.from(statusList.lst, 'base64url'), {
    maxOutputLength: MAX_STATUS_LIST_DECOMPRESSED_LENGTH,
  });
  if (index < 0 || index >= bytes.length * 8) throw new Error('status list index is out of bounds');
  return ((bytes[Math.floor(index / 8)] >> (index % 8)) & 1) === 1;
}

export async function validateClientStatus(
  payload: oidc.UnknownObject,
  attestationHeader: oidc.UnknownObject,
  options: { fetchStatusList?: typeof fetch } = {},
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const clientStatus = asRecord(payload.client_status);
  const status = asRecord(clientStatus?.status);
  const reference = asRecord(status?.status_list);
  const minimumRemaining = (config.abca as typeof config.abca & { statusMinimumRemainingSeconds?: number }).statusMinimumRemainingSeconds
    ?? 31 * 24 * 60 * 60;
  if (
    !clientStatus
    || typeof clientStatus.exp !== 'number'
    || !Number.isSafeInteger(clientStatus.exp)
    || clientStatus.exp - now < minimumRemaining
    || !reference
    || typeof reference.uri !== 'string'
    || !Number.isSafeInteger(reference.idx)
    || (reference.idx as number) < 0
  ) {
    throw new oidc.errors.InvalidClientAttestation('client attestation client_status is invalid or insufficiently maintained');
  }

  let statusListUrl: URL;
  try {
    statusListUrl = new URL(reference.uri);
    assertStatusListUrlAllowed(statusListUrl);
  } catch (error) {
    if (error instanceof oidc.errors.InvalidClientAttestation) throw error;
    throw new oidc.errors.InvalidClientAttestation('client status list URI is invalid');
  }

  const controller = new AbortController();
  const timeoutMilliseconds = (config.abca as typeof config.abca & { statusListTimeoutMilliseconds?: number }).statusListTimeoutMilliseconds ?? 5000;
  const timeout = setTimeout(() => controller.abort(), timeoutMilliseconds);
  try {
    const response = await (options.fetchStatusList ?? fetch)(statusListUrl, {
      headers: { Accept: 'application/statuslist+jwt' },
      signal: controller.signal,
      redirect: 'error',
    });
    const contentLength = Number(response.headers.get('content-length') ?? 0);
    if (!response.ok || contentLength > MAX_STATUS_LIST_TOKEN_LENGTH) {
      throw new Error('status list response is not acceptable');
    }
    const token = await readResponseTextLimited(response, MAX_STATUS_LIST_TOKEN_LENGTH);
    if (token.length === 0 || token.length > MAX_STATUS_LIST_TOKEN_LENGTH || token.split('.').length !== 3) {
      throw new Error('status list token has an invalid size or structure');
    }
    const header = decodeProtectedHeader(token);
    const x5c = parseX5C(header.x5c);
    if (
      header.typ !== 'statuslist+jwt'
      || !isConfiguredAlgorithm(header.alg, config.abca.clientAttestationSigningAlgs)
      || x5c[0] !== (attestationHeader.x5c as unknown[] | undefined)?.[0]
      || !await verifyX5C(x5c, config.clientAttestationTrustAnchors)
    ) {
      throw new Error('status list signer is invalid');
    }
    const publicKey = await importX509(certificateToPem(x5c[0]), header.alg);
    const verified = await jwtVerify(token, publicKey, {
      algorithms: [header.alg],
      subject: statusListUrl.toString(),
      typ: 'statuslist+jwt',
      clockTolerance: config.abca.clientAttestationClockTolerance,
      requiredClaims: ['sub', 'iat', 'exp'],
    });
    if (decodeStatusListEntry(verified.payload, reference.idx as number)) {
      throw new oidc.errors.InvalidClientAttestation('client attestation has been revoked');
    }
  } catch (error) {
    if (error instanceof oidc.errors.InvalidClientAttestation) throw error;
    throw new oidc.errors.InvalidClientAttestation('client attestation status could not be verified');
  } finally {
    clearTimeout(timeout);
  }
}

export async function getAttestationSignaturePublicKey(
  _ctx: oidc.KoaContextWithOIDC,
  header: oidc.UnknownObject,
  _payload: oidc.UnknownObject,
) {
  if (!isConfiguredAlgorithm(header.alg, config.abca.clientAttestationSigningAlgs)) {
    throw new oidc.errors.InvalidClientAttestation('unsupported client attestation alg');
  }

  // The WUA profile identifies the Wallet Provider through the signing
  // certificate and requires its chain to terminate at a trusted anchor.
  // The JOSE header is still unverified here, so never return its leaf key
  // before the complete chain has been validated.
  const certificateChain = parseX5C(header.x5c);
  try {
    const leafCertificate = new X509Certificate(
      Buffer.from(certificateChain[0], 'base64'),
    );
    if (leafCertificate.ca) {
      throw new Error('CA certificates cannot sign Wallet Instance Attestations');
    }
  } catch {
    throw new oidc.errors.InvalidClientAttestation('invalid client attestation signing certificate');
  }

  if (config.clientAttestationTrustAnchors.length === 0) {
    throw new oidc.errors.InvalidClientAttestation('no Wallet Provider trust anchors configured');
  }

  let trusted: boolean;
  try {
    trusted = await verifyX5C(certificateChain, config.clientAttestationTrustAnchors);
  } catch {
    trusted = false;
  }
  if (!trusted) {
    throw new oidc.errors.InvalidClientAttestation('untrusted client attestation x5c chain');
  }

  try {
    return await exportJWK(
      await importX509(certificateToPem(certificateChain[0]), header.alg),
    );
  } catch {
    throw new oidc.errors.InvalidClientAttestation('invalid client attestation signing certificate');
  }
}

export async function assertAttestationJwtAndPop(
  ctx: oidc.KoaContextWithOIDC,
  attestation: oidc.JWTVerificationResult,
  pop: oidc.JWTVerificationResult,
  statusValidator: typeof validateClientStatus = validateClientStatus,
  useValidator: (ctx: oidc.KoaContextWithOIDC, payload: oidc.UnknownObject, confirmationKeyThumbprint: string) => Promise<void> = async () => undefined,
) {
  const now = Math.floor(Date.now() / 1000);
  const attestationAlg = attestation.protectedHeader?.alg;
  const popAlg = pop.protectedHeader?.alg;

  // oidc-provider validates both JWTs against the combined ABCA algorithm
  // allowlist. Keep these checks to enforce wwWallet's distinct per-JWT lists.
  if (!isConfiguredAlgorithm(attestationAlg, config.abca.clientAttestationSigningAlgs)) {
    throw new oidc.errors.InvalidClientAttestation('unsupported client attestation alg');
  }

  if (!isConfiguredAlgorithm(popAlg, config.abca.clientAttestationPopSigningAlgs)) {
    throw new oidc.errors.InvalidClientAttestation('unsupported client attestation pop alg');
  }

  if (attestation.protectedHeader?.typ !== 'oauth-client-attestation+jwt') {
    throw new oidc.errors.InvalidClientAttestation('invalid client attestation typ');
  }
  if (
    typeof attestation.payload.sub !== 'string'
    || attestation.payload.sub.length === 0
    || typeof attestation.payload.aud !== 'string'
    || attestation.payload.aud !== ctx.oidc.issuer
    || typeof attestation.payload.jti !== 'string'
    || attestation.payload.jti.length === 0
    || 'iss' in attestation.payload
    || typeof attestation.payload.wallet_name !== 'string'
    || attestation.payload.wallet_name.length === 0
    || typeof attestation.payload.wallet_version !== 'string'
    || attestation.payload.wallet_version.length === 0
    || (!asRecord(attestation.payload.wallet_solution_certification_information)
      && (typeof attestation.payload.wallet_solution_certification_information !== 'string'
        || attestation.payload.wallet_solution_certification_information.length === 0))
    || !Number.isSafeInteger(attestation.payload.iat)
    || !Number.isSafeInteger(attestation.payload.exp)
    || (attestation.payload.wallet_link !== undefined
      && (typeof attestation.payload.wallet_link !== 'string' || !URL.canParse(attestation.payload.wallet_link)))
  ) {
    throw new oidc.errors.InvalidClientAttestation('client attestation required claims are invalid');
  }

  const attestationCnf = attestation.payload.cnf as { jwk?: JWK } | undefined;
  const attestationJwk = attestationCnf?.jwk;
  if (!attestationJwk || typeof attestationJwk !== 'object') {
    throw new oidc.errors.InvalidClientAttestation('client attestation cnf.jwk missing');
  }
  assertPublicConfirmationJwk(attestationJwk);
  try {
    const algorithm = attestationJwk.crv === 'P-256' ? 'ES256' : attestationJwk.crv === 'P-384' ? 'ES384' : 'ES512';
    await importJWK(attestationJwk, algorithm);
  } catch {
    throw new oidc.errors.InvalidClientAttestation('client attestation cnf.jwk is malformed');
  }
  const attestationJkt = await calculateJwkThumbprint(attestationJwk);
  // Client authentication runs before the PAR authorization-request middleware
  // has copied every form parameter into ctx.oidc.params. Express has already
  // parsed the body, so use it as the authoritative fallback at this stage.
  const requestBody = (ctx.request as { body?: Record<string, unknown> } | undefined)?.body
    ?? (ctx.req as typeof ctx.req & { body?: Record<string, unknown> } | undefined)?.body;
  const requestDpopJkt = ctx.oidc.params?.dpop_jkt ?? requestBody?.dpop_jkt;
  if (ctx.oidc.route === 'pushed_authorization_request' && requestDpopJkt === undefined) {
    throw new oidc.errors.InvalidClientAttestation('dpop_jkt is required for pushed authorization requests');
  }
  if (requestDpopJkt !== undefined) {
    if (typeof requestDpopJkt !== 'string' || requestDpopJkt !== attestationJkt) {
      throw new oidc.errors.InvalidClientAttestation('dpop_jkt does not match client attestation cnf.jwk');
    }
  }

  const dpopProof = ctx.get?.('DPoP');
  if (dpopProof) {
    try {
      const dpopJwk = decodeProtectedHeader(dpopProof).jwk;
      if (!dpopJwk || await calculateJwkThumbprint(dpopJwk) !== attestationJkt) {
        throw new Error('key mismatch');
      }
    } catch {
      throw new oidc.errors.InvalidClientAttestation('DPoP key does not match client attestation cnf.jwk');
    }
  }
  if (ctx.oidc.route === 'token' && !dpopProof) {
    throw new oidc.errors.InvalidClientAttestation('DPoP is required for token client authentication');
  }

  // Signature, typ, sub, exp, cnf.jwk, aud, jti, iat, replay, and challenge
  // validation are performed by oidc-provider before and after this callback.
  // The checks below are wwWallet-specific maximum-age/freshness policies.
  const popIat = assertNumericDate(pop.payload.iat, 'pop iat');
  if (popIat > now + config.abca.clientAttestationClockTolerance) {
    throw new oidc.errors.InvalidClientAttestation('pop iat is in the future');
  }

  if (now - popIat > config.abca.clientAttestationPopMaxAge + config.abca.clientAttestationClockTolerance) {
    throw new oidc.errors.InvalidClientAttestation('pop is too old');
  }

  if (attestation.payload.iat !== undefined) {
    const attestationIat = assertNumericDate(attestation.payload.iat, 'attestation iat');
    if (attestationIat > now + config.abca.clientAttestationClockTolerance) {
      throw new oidc.errors.InvalidClientAttestation('attestation iat is in the future');
    }

    if (now - attestationIat > config.abca.clientAttestationMaxAge + config.abca.clientAttestationClockTolerance) {
      throw new oidc.errors.UseFreshAttestation('attestation is too old');
    }
    const attestationExp = assertNumericDate(attestation.payload.exp, 'attestation exp');
    if (attestationExp <= attestationIat || attestationExp - attestationIat >= 24 * 60 * 60) {
      throw new oidc.errors.InvalidClientAttestation('client attestation lifetime must be below 24 hours');
    }
  } else {
    const attestationExp = assertNumericDate(attestation.payload.exp, 'attestation exp');
    if (attestationExp - now > config.abca.clientAttestationMaxAge + config.abca.clientAttestationClockTolerance) {
      throw new oidc.errors.UseFreshAttestation('attestation exp is too far in the future');
    }
  }

  await statusValidator(attestation.payload, attestation.protectedHeader ?? {});
  await useValidator(ctx, attestation.payload, attestationJkt);
}
