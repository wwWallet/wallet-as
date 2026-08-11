import * as crypto from "node:crypto";
import { deflateSync } from "node:zlib";
import fs from "node:fs";
import path from "node:path";
import * as oidc from "oidc-provider";
import { calculateJwkThumbprint, importPKCS8, SignJWT } from "jose";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockConfig = vi.hoisted(() => ({
  abca: {
    clientAttestationSigningAlgs: ["ES256"] as oidc.AsymmetricSigningAlgorithm[],
    clientAttestationPopSigningAlgs: ["ES256"] as oidc.AsymmetricSigningAlgorithm[],
    clientAttestationPopMaxAge: 300,
    clientAttestationMaxAge: 86400,
    clientAttestationClockTolerance: 60,
  },
  clientAttestationTrustAnchors: [] as string[],
}));

vi.mock("../../src/config", () => ({ default: mockConfig }));

import {
  assertAttestationJwtAndPop,
  decodeStatusListEntry,
  getAttestationSignaturePublicKey,
  validateClientStatus,
} from "../../src/services/attestationBasedClientAuthenticationService";

const context = {
  oidc: { issuer: 'https://as.example', params: {} },
  get: vi.fn().mockReturnValue(""),
} as unknown as oidc.KoaContextWithOIDC;
const unusedKey = {} as crypto.webcrypto.CryptoKey;
const clientInstanceJwk = {
  kty: "EC",
  crv: "P-256",
  x: "18wHLeIgW9wVN6VD1Txgpqy2LszYkMf6J8njVAibvhM",
  y: "-V4dS4UaLMgP_4fY4j8ir7cl1TXlFdAgcx55o7TkcSA",
};

function verificationResult(
  protectedHeader: oidc.UnknownObject,
  payload: oidc.UnknownObject,
): oidc.JWTVerificationResult {
  if (payload.cnf) {
    protectedHeader = { typ: 'oauth-client-attestation+jwt', x5c: ['leaf'], ...protectedHeader };
    payload = {
      sub: 'https://wallet.example/callback',
      aud: 'https://as.example',
      jti: crypto.randomUUID(),
      wallet_name: 'wwWallet',
      wallet_version: '1.0.0',
      wallet_solution_certification_information: { scheme: 'test' },
      client_status: {
        status: { status_list: { idx: 0, uri: 'https://provider.example/status/wia/1' } },
        exp: 1_800_000_000,
      },
      ...payload,
    };
  }
  return { protectedHeader, payload, key: unusedKey };
}

const acceptStatus = async () => undefined;

async function signedStatusList(uri: string, revoked: boolean): Promise<{ token: string; x5c: string }> {
  const leafCertificate = fs.readFileSync(path.join(process.cwd(), 'keys/pem.crt'), 'utf8');
  const x5c = leafCertificate.replace(/-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g, '');
  const privateKey = await importPKCS8(fs.readFileSync(path.join(process.cwd(), 'keys/pem.key'), 'utf8'), 'ES256');
  const bytes = Buffer.from([revoked ? 1 : 0]);
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({
    ttl: 300,
    status_list: { bits: 1, lst: deflateSync(bytes).toString('base64url') },
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'statuslist+jwt', x5c: [x5c] })
    .setSubject(uri)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(privateKey);
  return { token, x5c };
}

describe("attestationBasedClientAuthenticationService", () => {
  const now = 1_700_000_000;

  beforeEach(() => {
    vi.setSystemTime(now * 1000);
    mockConfig.abca.clientAttestationSigningAlgs = ["ES256"];
    mockConfig.abca.clientAttestationPopSigningAlgs = ["ES256"];
    mockConfig.clientAttestationTrustAnchors = [];
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("resolves the leaf key from an x5c chain anchored in Wallet Provider trust", async () => {
    vi.setSystemTime(new Date("2026-08-03T00:00:00.000Z"));
    const leafCertificate = fs.readFileSync(
      path.join(process.cwd(), "keys/pem.crt"),
      "utf8",
    );
    mockConfig.clientAttestationTrustAnchors = [fs.readFileSync(
      path.join(process.cwd(), "certs/wwwallet_org_iaca.pem"),
      "utf8",
    )];
    const x5c = leafCertificate.replace(
      /-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g,
      "",
    );

    const key = await getAttestationSignaturePublicKey(
      context,
      { alg: "ES256", x5c: [x5c] },
      {},
    );

    expect(key).toMatchObject({ kty: "EC", crv: "P-256" });
    expect(key).not.toHaveProperty("d");
  });

  it("rejects a request without an x5c chain", async () => {
    await expect(
      getAttestationSignaturePublicKey(
        context,
        { alg: "ES256" },
        {},
      ),
    ).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it("rejects a chain when no Wallet Provider trust anchor is configured", async () => {
    const leafCertificate = fs.readFileSync(
      path.join(process.cwd(), "keys/pem.crt"),
      "utf8",
    );
    const x5c = leafCertificate.replace(
      /-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g,
      "",
    );

    await expect(
      getAttestationSignaturePublicKey(
        context,
        { alg: "ES256", x5c: [x5c] },
        {},
      ),
    ).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it("rejects a CA certificate as the attestation signing certificate", async () => {
    const rootCertificate = fs.readFileSync(
      path.join(process.cwd(), "certs/wwwallet_org_iaca.pem"),
      "utf8",
    );
    mockConfig.clientAttestationTrustAnchors = [rootCertificate];
    const x5c = rootCertificate.replace(
      /-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\s/g,
      "",
    );

    await expect(
      getAttestationSignaturePublicKey(
        context,
        { alg: "ES256", x5c: [x5c] },
        {},
      ),
    ).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it("accepts verified JWTs that satisfy wwWallet freshness policy", async () => {
    const attestation = verificationResult(
      { alg: "ES256" },
      { iat: now - 60, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: "ES256" }, { iat: now - 10 });

    await expect(
      assertAttestationJwtAndPop(context, attestation, pop, acceptStatus),
    ).resolves.toBeUndefined();
  });

  it('rejects a WIA issued for another Authorization Server', async () => {
    const attestation = verificationResult(
      { alg: 'ES256' },
      { aud: 'https://other-as.example', iat: now - 60, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: 'ES256' }, { iat: now - 10 });
    await expect(assertAttestationJwtAndPop(context, attestation, pop, acceptStatus))
      .rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it("rejects a PoP that exceeds the configured maximum age", async () => {
    const attestation = verificationResult(
      { alg: "ES256" },
      { iat: now - 60, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: "ES256" }, { iat: now - 361 });

    await expect(
      assertAttestationJwtAndPop(context, attestation, pop),
    ).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it("requests a fresh attestation when its iat is too old", async () => {
    const attestation = verificationResult(
      { alg: "ES256" },
      { iat: now - 86461, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: "ES256" }, { iat: now - 10 });

    await expect(
      assertAttestationJwtAndPop(context, attestation, pop),
    ).rejects.toBeInstanceOf(oidc.errors.UseFreshAttestation);
  });

  it("rejects a PAR dpop_jkt that does not match the WIA cnf key", async () => {
    const mismatchedContext = {
      oidc: { issuer: 'https://as.example', params: { dpop_jkt: "wrong-thumbprint" } },
      get: vi.fn().mockReturnValue(""),
    } as unknown as oidc.KoaContextWithOIDC;
    const attestation = verificationResult(
      { alg: "ES256" },
      { iat: now - 60, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: "ES256" }, { iat: now - 10 });

    await expect(
      assertAttestationJwtAndPop(mismatchedContext, attestation, pop),
    ).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it("requires dpop_jkt for PAR client authentication", async () => {
    const parContext = {
      oidc: { issuer: 'https://as.example', route: "pushed_authorization_request", params: {} },
      get: vi.fn().mockReturnValue(""),
    } as unknown as oidc.KoaContextWithOIDC;
    const attestation = verificationResult(
      { alg: "ES256" },
      { iat: now - 60, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: "ES256" }, { iat: now - 10 });

    await expect(
      assertAttestationJwtAndPop(parContext, attestation, pop, acceptStatus),
    ).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it("reads PAR dpop_jkt from the parsed request body during client authentication", async () => {
    const parContext = {
      oidc: { issuer: 'https://as.example', route: "pushed_authorization_request", params: {} },
      request: {
        body: { dpop_jkt: await calculateJwkThumbprint(clientInstanceJwk) },
      },
      get: vi.fn().mockReturnValue(""),
    } as unknown as oidc.KoaContextWithOIDC;
    const attestation = verificationResult(
      { alg: "ES256" },
      { iat: now - 60, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: "ES256" }, { iat: now - 10 });

    await expect(
      assertAttestationJwtAndPop(parContext, attestation, pop, acceptStatus),
    ).resolves.toBeUndefined();
  });

  it('decodes valid and revoked draft-20 one-bit status entries', () => {
    const bytes = Buffer.from([0, 2]);
    const payload = { ttl: 300, status_list: { bits: 1, lst: deflateSync(bytes).toString('base64url') } };
    expect(decodeStatusListEntry(payload, 8)).toBe(false);
    expect(decodeStatusListEntry(payload, 9)).toBe(true);
    expect(() => decodeStatusListEntry(payload, 16)).toThrow(/out of bounds/);
  });

  it('rejects an insufficient client-status maintenance period before fetching', async () => {
    const fetchStatusList = vi.fn();
    await expect(validateClientStatus({
      client_status: {
        exp: now + 60,
        status: { status_list: { idx: 0, uri: 'https://provider.example/status/wia/1' } },
      },
    }, { x5c: ['leaf'] }, { fetchStatusList })).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
    expect(fetchStatusList).not.toHaveBeenCalled();
  });

  it('verifies a certificate-signed status list and rejects its revoked entry', async () => {
    vi.setSystemTime(new Date('2026-08-03T00:00:00.000Z'));
    const uri = 'http://localhost/status/wia/1';
    mockConfig.clientAttestationTrustAnchors = [fs.readFileSync(path.join(process.cwd(), 'certs/wwwallet_org_iaca.pem'), 'utf8')];
    const valid = await signedStatusList(uri, false);
    const payload = {
      client_status: {
        exp: Math.floor(Date.now() / 1000) + 32 * 24 * 60 * 60,
        status: { status_list: { idx: 0, uri } },
      },
    };
    await expect(validateClientStatus(payload, { x5c: [valid.x5c] }, {
      fetchStatusList: vi.fn().mockResolvedValue(new Response(valid.token, { status: 200 })),
    })).resolves.toBeUndefined();

    const revoked = await signedStatusList(uri, true);
    await expect(validateClientStatus(payload, { x5c: [revoked.x5c] }, {
      fetchStatusList: vi.fn().mockResolvedValue(new Response(revoked.token, { status: 200 })),
    })).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it('blocks authentication when WIA status validation reports revocation', async () => {
    const attestation = verificationResult(
      { alg: 'ES256' },
      { iat: now - 60, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: 'ES256' }, { iat: now - 10 });
    const revoked = vi.fn().mockRejectedValue(new oidc.errors.InvalidClientAttestation('revoked'));
    await expect(assertAttestationJwtAndPop(context, attestation, pop, revoked))
      .rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });
});
