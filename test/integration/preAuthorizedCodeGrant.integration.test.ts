import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import request from "supertest";
import { randomUUID } from "node:crypto";
import { exportJWK, generateKeyPair, SignJWT } from "jose";

const mockConsumePreAuthorizedCode = vi.fn();

vi.mock("../../src/services/preAuthorizedCodeService", () => ({
  consumePreAuthorizedCode: mockConsumePreAuthorizedCode,
}));

describe("pre-authorized code grant", () => {
  const originalEnv = process.env;
  let server: Server;
  let tokenEndpoint: string;

  beforeEach(async () => {
    vi.resetModules();
    process.env = {
      ...originalEnv,
      PRE_AUTHORIZED_CREDENTIAL_ISSUANCE: "true",
      PRE_AUTHORIZED_CODE_API_URL: "http://issuer.test",
      PRE_AUTHORIZED_CODE_API_BEARER_TOKEN: "test-token",
    };

    mockConsumePreAuthorizedCode.mockResolvedValue({
      credential_configuration_ids: ["test-credential"],
      account_id: "user-123",
      allow_refresh_token: false,
      tx_code: true,
      tx_value: "12345",
      scope: "openid",
    });

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

    const { createApp } = await import("../../src/app");
    const { app } = createApp();
    server = app.listen();
    const { port } = server.address() as AddressInfo;
    tokenEndpoint = `http://127.0.0.1:${port}/token`;
  });

  afterEach(() => {
    server?.close();
    process.env = originalEnv;
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("issues an access token for a valid pre-authorized grant request", async () => {
    const res = await requestPreAuthorizedToken({
      "pre-authorized_code": "test-code",
      tx_code: "12345",
    });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeDefined();
    expect(res.body.token_type).toBe("DPoP");
    expect(res.body.refresh_token).toBeUndefined();
    expect(mockConsumePreAuthorizedCode).toHaveBeenCalledWith("test-code", "12345");
  });

  it("passes the pre-authorized code and transaction code to the issuer API", async () => {
    await requestPreAuthorizedToken({
      "pre-authorized_code": "another-code",
      tx_code: "12345",
    });

    expect(mockConsumePreAuthorizedCode).toHaveBeenLastCalledWith("another-code", "12345");
  });

  it("challenges once for a DPoP nonce and accepts a proof containing it", async () => {
    await restartServer({
      DPOP_NONCE_REQUIRED: "true",
      DPOP_NONCE_SECRET: "test-dpop-nonce-secret-with-32-chars",
    });

    const firstResponse = await requestPreAuthorizedToken({
      "pre-authorized_code": "nonce-code",
      tx_code: "12345",
    });

    expect(firstResponse.status).toBe(400);
    expect(firstResponse.headers["dpop-nonce"]).toMatch(/^\d+\.[A-Za-z0-9_-]+$/);
    expect(mockConsumePreAuthorizedCode).not.toHaveBeenCalledWith("nonce-code", "12345");

    const retryResponse = await requestPreAuthorizedToken({
      "pre-authorized_code": "nonce-code",
      tx_code: "12345",
      dpopNonce: firstResponse.headers["dpop-nonce"],
    });

    expect(retryResponse.status).toBe(200);
    expect(retryResponse.body.token_type).toBe("DPoP");
  });

  it("rejects a tampered DPoP nonce", async () => {
    await restartServer({
      DPOP_NONCE_REQUIRED: "true",
      DPOP_NONCE_SECRET: "test-dpop-nonce-secret-with-32-chars",
    });

    const response = await requestPreAuthorizedToken({
      "pre-authorized_code": "tampered-nonce-code",
      tx_code: "12345",
      dpopNonce: "1234567890.invalid",
    });

    expect(response.status).toBe(400);
    expect(response.headers["dpop-nonce"]).toBeDefined();
  });

  async function requestPreAuthorizedToken(params: {
    "pre-authorized_code": string;
    tx_code?: string;
    dpopNonce?: string;
  }) {
    const dpop = await createDpopProof(tokenEndpoint, params.dpopNonce);

    return request(server)
      .post("/token")
      .type("form")
      .set("DPoP", dpop)
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        ...params,
      });
  }

  async function restartServer(env: Record<string, string>) {
    server?.close();
    process.env = {
      ...originalEnv,
      PRE_AUTHORIZED_CREDENTIAL_ISSUANCE: "true",
      PRE_AUTHORIZED_CODE_API_URL: "http://issuer.test",
      PRE_AUTHORIZED_CODE_API_BEARER_TOKEN: "test-token",
      ...env,
    };
    vi.resetModules();
    const { createApp } = await import("../../src/app");
    const { app } = createApp();
    server = app.listen();
    const { port } = server.address() as AddressInfo;
    tokenEndpoint = `http://127.0.0.1:${port}/token`;
  }
});

async function createDpopProof(htu: string, nonce?: string) {
  const { privateKey, publicKey } = await generateKeyPair("ES256", { extractable: true });
  const publicJwk = await exportJWK(publicKey);

  return new SignJWT({
    htm: "POST",
    htu,
    jti: randomUUID(),
    ...(nonce ? { nonce } : {}),
  })
    .setProtectedHeader({
      alg: "ES256",
      typ: "dpop+jwt",
      jwk: publicJwk,
    })
    .setIssuedAt()
    .sign(privateKey);
}
