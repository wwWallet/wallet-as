import * as oidc from "oidc-provider";
import { exportJWK, importSPKI } from "jose";
import config from "../config";

function assertNumericDate(value: unknown, claim: string): number {
  if (!Number.isInteger(value) || typeof value !== 'number') {
    throwInvalidClientAttestation(`${claim} must be an integer NumericDate`);
  }

  return value;
}

function throwInvalidClientAttestation(description: string): never {
  const InvalidClientAttestation = (oidc.errors as any).InvalidClientAttestation as new (
    description?: string,
    detail?: string,
  ) => Error;

  throw new InvalidClientAttestation(description);
}

function throwUseFreshAttestation(description: string): never {
  const err = new oidc.errors.OIDCProviderError(400, 'use_fresh_attestation');
  err.error_description = description;
  throw err;
}

export async function getAttestationSignaturePublicKey(
  _ctx: any,
  iss: any,
  header: any,
  _client: any,
) {
  if (!config.abca.clientAttestationSigningAlgs.includes(header?.alg)) {
    throwInvalidClientAttestation('unsupported client attestation alg');
  }

  if (!Object.keys(config.trustedClientAttesters).includes(iss)) {
    throwInvalidClientAttestation('unknown attester');
  }

  return (
    await exportJWK(
      await importSPKI(
        config.trustedClientAttesters[iss],
        'ES256'
      )
    )
  );
}

export async function assertAttestationJwtAndPop(
  _ctx: any,
  attestation: any,
  pop: any,
) {
  const now = Math.floor(Date.now() / 1000);
  const attestationAlg = attestation.protectedHeader?.alg;
  const popAlg = pop.protectedHeader?.alg;

  if (!config.abca.clientAttestationSigningAlgs.includes(attestationAlg)) {
    throwInvalidClientAttestation('unsupported client attestation alg');
  }

  if (!config.abca.clientAttestationPopSigningAlgs.includes(popAlg)) {
    throwInvalidClientAttestation('unsupported client attestation pop alg');
  }

  if (!attestation.payload.cnf?.jwk) {
    throwInvalidClientAttestation('missing client attestation cnf.jwk');
  }

  const popIat = assertNumericDate(pop.payload.iat, 'pop iat');
  if (popIat > now + config.abca.clientAttestationClockTolerance) {
    throwInvalidClientAttestation('pop iat is in the future');
  }

  if (now - popIat > config.abca.clientAttestationPopMaxAge + config.abca.clientAttestationClockTolerance) {
    throwInvalidClientAttestation('pop is too old');
  }

  if (attestation.payload.iat !== undefined) {
    const attestationIat = assertNumericDate(attestation.payload.iat, 'attestation iat');
    if (attestationIat > now + config.abca.clientAttestationClockTolerance) {
      throwInvalidClientAttestation('attestation iat is in the future');
    }

    if (now - attestationIat > config.abca.clientAttestationMaxAge + config.abca.clientAttestationClockTolerance) {
      throwUseFreshAttestation('attestation is too old');
    }
  } else {
    const attestationExp = assertNumericDate(attestation.payload.exp, 'attestation exp');
    if (attestationExp - now > config.abca.clientAttestationMaxAge + config.abca.clientAttestationClockTolerance) {
      throwUseFreshAttestation('attestation exp is too far in the future');
    }
  }
}
