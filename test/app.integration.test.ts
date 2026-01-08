import { describe, expect, it } from "vitest";
import request from "supertest";
import { createApp } from "../src/app";

describe("app integration", () => {
  const { app } = createApp();

  it("serves the home page", async () => {
    const res = await request(app).get("/");

    expect(res.status).toBe(200);
    expect(res.text).toContain("Wallet Authorization Server");
  });

  it("serves OIDC discovery metadata", async () => {
    const res = await request(app).get("/.well-known/openid-configuration");

    expect(res.status).toBe(200);
    expect(typeof res.body.issuer).toBe("string");
    expect(res.body.issuer.length).toBeGreaterThan(0);
    expect(typeof res.body.authorization_endpoint).toBe("string");
    expect(typeof res.body.token_endpoint).toBe("string");
    expect(typeof res.body.jwks_uri).toBe("string");
  });
});
