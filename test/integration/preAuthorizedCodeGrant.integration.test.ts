import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";
import * as jose from "jose";

const { mockConsumePreAuthorizedCode, mockCalculateJwkThumbprint } = vi.hoisted(() => ({
  mockConsumePreAuthorizedCode: vi.fn(),
  mockCalculateJwkThumbprint: vi.fn(),
}));

vi.mock("../../src/services/preAuthorizedCodeService", () => ({
  consumePreAuthorizedCode: mockConsumePreAuthorizedCode,
}));

vi.mock("jose", async () => {
  const actual = await vi.importActual<typeof import("jose")>("jose");
  return {
    ...actual,
    calculateJwkThumbprint: mockCalculateJwkThumbprint,
  };
});

describe("pre-authorized code grant", () => {
  const originalEnv = process.env;
  let dpopPrivateKey: jose.KeyLike;
  let dpopPublicJwk: jose.JWK;

  async function createDpopProof(issuer: string) {
    return new jose.SignJWT({
      htm: "POST",
      htu: `${issuer}/token`,
    })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: dpopPublicJwk })
      .setIssuedAt()
      .setJti(crypto.randomUUID())
      .sign(dpopPrivateKey);
  }

  beforeEach(async () => {
    vi.resetModules();
    process.env = {
      ...originalEnv,
      PRE_AUTHORIZED_CREDENTIAL_ISSUANCE: "true",
      PRE_AUTHORIZED_CODE_API_URL: "http://issuer.test",
      PRE_AUTHORIZED_CODE_API_BEARER_TOKEN: "test-token",
    };

    mockConsumePreAuthorizedCode.mockResolvedValue({
      "pre-authorized_code": "test-code",
      credential_configuration_ids: ["test-credential"],
      account_id: "user-123",
      allow_refresh_token: false,
      tx_code: {
        input_mode: "numeric",
        length: 5,
      },
      tx_value: "12345",
      scope: "openid",
    });
    mockCalculateJwkThumbprint.mockResolvedValue("thumbprint");
    const { privateKey, publicKey } = await jose.generateKeyPair("ES256");
    dpopPrivateKey = privateKey;
    dpopPublicJwk = await jose.exportJWK(publicKey);

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          credential_configurations_supported: {
            "test-credential": {
              scope: "openid",
            },
          },
        }),
      })
    );
  });

  afterEach(() => {
    process.env = originalEnv;
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("issues an access token for a valid pre-authorized grant request", async () => {
    const { createApp } = await import("../../src/app");
    const { app, provider } = createApp();

    const res = await request(app)
      .post("/token")
      .type("form")
      .set("Host", "localhost:6060")
      .set("DPoP", await createDpopProof(provider.issuer))
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "test-code",
        tx_code: "12345",
      });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeDefined();
    expect(res.body.token_type).toBe("DPoP");
    expect(mockConsumePreAuthorizedCode).toHaveBeenCalledWith("test-code", "12345");
  });

  it("passes the pre-authorized code and transaction code to the issuer API", async () => {
    const { createApp } = await import("../../src/app");
    const { app, provider } = createApp();

    await request(app)
      .post("/token")
      .type("form")
      .set("Host", "localhost:6060")
      .set("DPoP", await createDpopProof(provider.issuer))
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "another-code",
        tx_code: "12345",
      });

    expect(mockConsumePreAuthorizedCode).toHaveBeenLastCalledWith("another-code", "12345");
  });

  it("returns an OAuth error from the pre-authorized code API", async () => {
    mockConsumePreAuthorizedCode.mockResolvedValueOnce({
      error: "invalid_grant",
      error_description: "The pre-authorized code is invalid",
    });

    const { createApp } = await import("../../src/app");
    const { app, provider } = createApp();

    const res = await request(app)
      .post("/token")
      .type("form")
      .set("Host", "localhost:6060")
      .set("DPoP", await createDpopProof(provider.issuer))
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized-code": "invalid-code",
        tx_code: "12345",
      });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_request");
    expect(res.body.error_description).toBe("invalid_grant");
  });
});
