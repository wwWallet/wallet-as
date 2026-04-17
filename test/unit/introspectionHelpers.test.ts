import { describe, expect, it, vi } from "vitest";

describe("introspectionAllowedPolicy", () => {
  it("rejects non client_secret_basic auth", async () => {
    vi.resetModules();
    const { introspectionAllowedPolicy } = await import(
      "../../src/util/introspectionHelpers"
    );

    const ctx = {} as any;
    const client = { clientAuthMethod: "none", clientId: "client-a" } as any;
    const token = { clientId: "client-a" } as any;

    expect(introspectionAllowedPolicy(ctx, client, token)).toBe(false);
  });

  it("allows matching client and token", async () => {
    vi.resetModules();
    const { introspectionAllowedPolicy } = await import(
      "../../src/util/introspectionHelpers"
    );

    const ctx = {} as any;
    const client = {
      clientAuthMethod: "client_secret_basic",
      clientId: "client-a",
    } as any;
    const token = { clientId: "client-a" } as any;

    expect(introspectionAllowedPolicy(ctx, client, token)).toBe(true);
  });

  it("allows the configured introspection client", async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      INTROSPECTION_CLIENT: "introspect-client",
      INTROSPECTION_CLIENT_SECRET: "secret",
    };

    vi.resetModules();
    const { introspectionAllowedPolicy } = await import(
      "../../src/util/introspectionHelpers"
    );

    const ctx = {} as any;
    const client = {
      clientAuthMethod: "client_secret_basic",
      clientId: "introspect-client",
    } as any;
    const token = { clientId: "other-client" } as any;

    expect(introspectionAllowedPolicy(ctx, client, token)).toBe(true);

    process.env = originalEnv;
  });
});
