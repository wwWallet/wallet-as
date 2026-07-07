import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import request from "supertest";

const mockConsumePreAuthorizedCode = vi.fn();
const mockCalculateJwkThumbprint = vi.fn();

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

  beforeEach(() => {
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
    mockCalculateJwkThumbprint.mockResolvedValue("thumbprint");

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
    const { app } = createApp();

    const res = await request(app)
      .post("/token")
      .type("form")
      .set("DPoP", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0")
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "test-code",
        tx_code: "12345",
      });

    expect(res.status).toBe(200);
    expect(res.body.access_token).toBeDefined();
    expect(res.body.token_type).toBe("Bearer");
    expect(mockConsumePreAuthorizedCode).toHaveBeenCalledWith("test-code", "12345");
  });

  it("passes the pre-authorized code and transaction code to the issuer API", async () => {
    const { createApp } = await import("../../src/app");
    const { app } = createApp();

    await request(app)
      .post("/token")
      .type("form")
      .set("DPoP", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ0ZXN0In0")
      .send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "another-code",
        tx_code: "12345",
      });

    expect(mockConsumePreAuthorizedCode).toHaveBeenLastCalledWith("another-code", "12345");
  });
});
