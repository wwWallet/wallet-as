import * as crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import * as oidc from "oidc-provider";
import { calculateJwkThumbprint } from "jose";
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
  getAttestationSignaturePublicKey,
} from "../../src/services/attestationBasedClientAuthenticationService";

const context = {
  oidc: { params: {} },
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
  return { protectedHeader, payload, key: unusedKey };
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
      assertAttestationJwtAndPop(context, attestation, pop),
    ).resolves.toBeUndefined();
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
      oidc: { params: { dpop_jkt: "wrong-thumbprint" } },
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
      oidc: { route: "pushed_authorization_request", params: {} },
      get: vi.fn().mockReturnValue(""),
    } as unknown as oidc.KoaContextWithOIDC;
    const attestation = verificationResult(
      { alg: "ES256" },
      { iat: now - 60, exp: now + 300, cnf: { jwk: clientInstanceJwk } },
    );
    const pop = verificationResult({ alg: "ES256" }, { iat: now - 10 });

    await expect(
      assertAttestationJwtAndPop(parContext, attestation, pop),
    ).rejects.toBeInstanceOf(oidc.errors.InvalidClientAttestation);
  });

  it("reads PAR dpop_jkt from the parsed request body during client authentication", async () => {
    const parContext = {
      oidc: { route: "pushed_authorization_request", params: {} },
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
      assertAttestationJwtAndPop(parContext, attestation, pop),
    ).resolves.toBeUndefined();
  });
});
