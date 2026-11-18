import { X509Certificate } from 'node:crypto';
import * as oidc from 'oidc-provider';
import { exportJWK, type JWK } from 'jose';
import config from '../config';
import { loadAttestationClientAuthenticationProfile } from './attestationBasedClientAuthentication';
import { z } from 'zod';
import { verifyX5C } from 'wallet-common';

const x5cSchema = z.array(z.base64().min(1)).min(1);

function parseX5C(value: unknown): string[] {
  const chain = x5cSchema.safeParse(value);
  if (!chain.success) {
    throw new oidc.errors.InvalidClientAttestation('invalid client attestation x5c chain');
  }
  return chain.data;
}

export async function getAttestationSignaturePublicKey(
  _ctx: oidc.KoaContextWithOIDC,
  header: oidc.UnknownObject,
  _payload: oidc.UnknownObject,
  _client: oidc.Client,
): Promise<JWK> {
  const certificateChain = parseX5C(header.x5c);
  let leafCertificate: X509Certificate;
  try {
    leafCertificate = new X509Certificate(Buffer.from(certificateChain[0], 'base64'));
  } catch {
    throw new oidc.errors.InvalidClientAttestation(
      'malformed client attestation signing certificate',
    );
  }

  if (leafCertificate.ca) {
    throw new oidc.errors.InvalidClientAttestation(
      'CA certificates cannot sign Wallet Instance Attestations',
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
    return await exportJWK(leafCertificate.publicKey);
  } catch {
    throw new oidc.errors.InvalidClientAttestation(
      'unable to export client attestation signing certificate public key',
    );
  }
}

export async function assertAttestationJwtAndPop(
  ctx: oidc.KoaContextWithOIDC,
  attestation: oidc.JWTVerificationResult,
  _pop: oidc.JWTVerificationResult,
  _client: oidc.Client,
): Promise<void> {
  if (ctx.oidc.route === 'token' && !ctx.get('DPoP')) {
    throw new oidc.errors.InvalidClientAttestation('DPoP is required for token requests');
  }

  await loadAttestationClientAuthenticationProfile(config.openid4vcProfile).validate({
    attestation,
  });
}
