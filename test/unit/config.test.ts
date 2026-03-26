import { describe, expect, it, vi } from "vitest";

describe("config", () => {
  it("reads env vars when present", async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      INTROSPECTION_CLIENT: "client-a",
      INTROSPECTION_CLIENT_SECRET: "secret-a",
    };

    vi.resetModules();
    const config = (await import("../../src/config")).default;

    expect(config.introspectionClient).toBe("client-a");
    expect(config.introspectionClientSecret).toBe("secret-a");

    process.env = originalEnv;
  });
});
