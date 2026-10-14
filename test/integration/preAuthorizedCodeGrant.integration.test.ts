import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import request from "supertest";
import { randomUUID } from "node:crypto";
import { calculateJwkThumbprint, decodeProtectedHeader, exportJWK, generateKeyPair, SignJWT } from "jose";

const { mockConsumePreAuthorizedCode } = vi.hoisted(() => ({
  mockConsumePreAuthorizedCode: vi.fn(),
}));

vi.mock("../../src/services/preAuthorizedCodeService", () => ({
  consumePreAuthorizedCode: mockConsumePreAuthorizedCode,
}));

describe("pre-authorized code grant", () => {
  const originalEnv = process.env;
  let server: Server;
  let provider: import("oidc-provider").Provider;
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
    const config = (await import("../../src/config")).default;
    config.oidClients.push({
      client_id: "pre-authorized-authenticated-test",
      client_secret: "test-client-secret",
      token_endpoint_auth_method: "client_secret_basic",
      grant_types: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
      response_types: [],
      redirect_uris: [],
    });
    const created = createApp();
    provider = created.provider;
    const testApp = created.app;
    server = testApp.listen();
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
    const token = await provider.AccessToken.find(res.body.access_token);
    expect(token?.clientId).toBe("__pre-authorized_code_client__");
    expect(mockConsumePreAuthorizedCode).toHaveBeenCalledWith("test-code", "12345");
  });

  it("issues a token associated with the authenticated client", async () => {
    const res = await requestPreAuthorizedToken({
      "pre-authorized_code": "authenticated-code",
      tx_code: "12345",
    }, "Basic " + Buffer.from("pre-authorized-authenticated-test:test-client-secret").toString("base64"));

    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe("DPoP");
    expect(res.body.refresh_token).toBeUndefined();
    const token = await provider.AccessToken.find(res.body.access_token);
    expect(token?.clientId).toBe("pre-authorized-authenticated-test");
    expect(token?.jkt).toBe(res.body.cnf.jkt);
  });

  it.each([
    ["invalid credentials", "pre-authorized-authenticated-test:wrong-secret", "invalid_client"],
    ["unknown client", "unknown-client:secret", "invalid_client"],
    ["client without grant permission", "test:test", "invalid_request"],
  ])("rejects %s before consuming the code", async (_name, credentials, error) => {
    const res = await requestPreAuthorizedToken({
      "pre-authorized_code": "unconsumed-code",
      tx_code: "12345",
    }, "Basic " + Buffer.from(credentials).toString("base64"));

    expect(res.status).toBeGreaterThanOrEqual(400);
    expect(res.body.error).toBe(error);
    expect(res.body.access_token).toBeUndefined();
    expect(mockConsumePreAuthorizedCode).not.toHaveBeenCalled();
  });

  it.each(["pre-authorized-authenticated-test", "unknown-client"])(
    "rejects client_id %s without valid authentication instead of using the anonymous client",
    async (clientId) => {
      const res = await requestPreAuthorizedToken({
        "pre-authorized_code": "unconsumed-code",
        tx_code: "12345",
        client_id: clientId,
      });

      expect(res.status).toBeGreaterThanOrEqual(400);
      expect(res.body.error).toBe("invalid_client");
      expect(mockConsumePreAuthorizedCode).not.toHaveBeenCalled();
    }
  );

  it("returns an issuer API OAuth error without issuing tokens", async () => {
    mockConsumePreAuthorizedCode.mockResolvedValueOnce({
      error: "invalid_grant",
      error_description: "The pre-authorized code is invalid",
    });

    const res = await requestPreAuthorizedToken({
      "pre-authorized_code": "invalid-code",
      tx_code: "12345",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
    expect(res.body.access_token).toBeUndefined();
    expect(res.body.cnf).toBeUndefined();
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
    client_id?: string;
  }, authorization?: string) {
    const dpop = await createDpopProof(tokenEndpoint, params.dpopNonce);

    const tokenRequest = request(server)
      .post("/token")
      .type("form")
      .set("DPoP", dpop);
    if (authorization) {
      tokenRequest.set("Authorization", authorization);
    }
    const response = await tokenRequest.send({
      grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
      ...params,
    });

    if (response.status === 200) {
      const { jwk } = decodeProtectedHeader(dpop);
      if (!jwk) {
        throw new Error("Test DPoP proof is missing its public key");
      }
      expect(response.body.cnf).toEqual({ jkt: await calculateJwkThumbprint(jwk) });
    }
    return response;
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
