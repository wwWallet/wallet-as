import { describe, expect, it, vi } from "vitest";

describe("config", () => {
  it("reads env vars when present", async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      INTROSPECTION_CLIENT: "client-a",
      INTROSPECTION_CLIENT_SECRET: "secret-a",
      GRANT_REUSE_WINDOW_SECONDS: "33",
    };

    vi.resetModules();
    const config = (await import("../src/config")).default;

    expect(config.introspectionClient).toBe("client-a");
    expect(config.introspectionClientSecret).toBe("secret-a");
    expect(config.ttl.grantReuseWindowSeconds).toBe(33);

    process.env = originalEnv;
  });
});
