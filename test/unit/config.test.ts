import { describe, expect, it, vi } from "vitest";

describe("config", () => {
  it("normalizes BASE_PATH and reads basic env vars", async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      INTROSPECTION_CLIENT: "client-a",
      INTROSPECTION_CLIENT_SECRET: "secret-a",
      BASE_PATH: "as",
    };

    vi.resetModules();
    const config = (await import("../../src/config")).default;

    expect(config.introspectionClient).toBe("client-a");
    expect(config.introspectionClientSecret).toBe("secret-a");
    expect(config.basePath).toBe("/as");
    expect(config.authBrokerRedirectUri).toBe("http://localhost:6060/interaction/authBroker/callback");

    process.env = originalEnv;
  });

  it("accepts BASE_PATH with leading/trailing slashes", async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      BASE_PATH: "/as/",
    };

    vi.resetModules();
    const config = (await import("../../src/config")).default;

    expect(config.basePath).toBe("/as");

    process.env = originalEnv;
  });

  it("uses SERVICE_URL as authoritative base for default auth broker redirect uri", async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      SERVICE_URL: "https://qa-issuer.wwwallet.org/as",
      BASE_PATH: "/as",
      AUTH_BROKER_REDIRECT_URI: "",
    };

    vi.resetModules();
    const config = (await import("../../src/config")).default;

    expect(config.serviceUrl).toBe("https://qa-issuer.wwwallet.org/as");
    expect(config.authBrokerRedirectUri).toBe(
      "https://qa-issuer.wwwallet.org/as/interaction/authBroker/callback"
    );

    process.env = originalEnv;
  });
});
