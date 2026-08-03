import * as oidc from "oidc-provider";
import { X509Certificate } from "node:crypto";
import { exportJWK, importX509 } from "jose";
import { verifyX5C } from "wallet-common";
import config from "../config";

const MAX_X5C_CERTIFICATES = 5;
const MAX_X5C_CERTIFICATE_LENGTH = 16 * 1024;
const BASE64_CERTIFICATE_PATTERN = /^[A-Za-z0-9+/]+={0,2}$/;

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
  _ctx: oidc.KoaContextWithOIDC,
  attestation: oidc.JWTVerificationResult,
  pop: oidc.JWTVerificationResult,
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
  } else {
    const attestationExp = assertNumericDate(attestation.payload.exp, 'attestation exp');
    if (attestationExp - now > config.abca.clientAttestationMaxAge + config.abca.clientAttestationClockTolerance) {
      throw new oidc.errors.UseFreshAttestation('attestation exp is too far in the future');
    }
  }
}
