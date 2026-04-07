import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import request from "supertest";
import { createApp } from "../src/app";

describe("app integration", () => {
  const { app } = createApp();

  it("serves the home page", async () => {
    const res = await request(app).get("/as/");

    expect(res.status).toBe(200);
    expect(res.text).toContain("Wallet Authorization Server");
  });

  it("serves OIDC discovery metadata", async () => {
    const res = await request(app).get("/as/.well-known/openid-configuration");

    expect(res.status).toBe(200);
    expect(typeof res.body.issuer).toBe("string");
    expect(res.body.issuer.length).toBeGreaterThan(0);
    expect(typeof res.body.authorization_endpoint).toBe("string");
    expect(typeof res.body.token_endpoint).toBe("string");
    expect(typeof res.body.jwks_uri).toBe("string");
  });

  describe("introspection flow", () => {
    const originalEnv = process.env;
    let agent: request.SuperAgentTest;
    let accessToken: string;
    let introspectionPath: string;

    beforeAll(async () => {
      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
        INTROSPECTION_CLIENT: "introspect-client",
        INTROSPECTION_CLIENT_SECRET: "introspect-secret",
      };

      vi.resetModules();
      const { createApp: createIntrospectionApp } = await import("../src/app");
      const { app: introspectionApp } = createIntrospectionApp();
      agent = request.agent(introspectionApp);

      const tokenResponse = await issueAccessToken(agent);
      accessToken = tokenResponse.accessToken;
      introspectionPath = tokenResponse.introspectionPath;
    });

    afterAll(() => {
      process.env = originalEnv;
    });

    it("allows the token's client to introspect", async () => {
      const sameClientRes = await agent
        .post(introspectionPath)
        .auth("test", "test")
        .type("form")
        .send({ token: accessToken })
        .expect(200);
      expect(sameClientRes.body.active).toBe(true);
    });

    it("allows the configured introspection client to introspect", async () => {
      const introspectionClientRes = await agent
        .post(introspectionPath)
        .auth("introspect-client", "introspect-secret")
        .type("form")
        .send({ token: accessToken })
        .expect(200);
      expect(introspectionClientRes.body.active).toBe(true);
    });

    it("rejects an unrelated client", async () => {
      const unrelatedClientRes = await agent
        .post(introspectionPath)
        .auth("test2", "test2")
        .type("form")
        .send({ token: accessToken })
        .expect(200);
      expect(unrelatedClientRes.body.active).toBe(false);
    });

    it("accepts issuer_state in pushed authorization requests", async () => {
      const discoveryRes = await agent
        .get("/as/.well-known/openid-configuration")
        .expect(200);
      const pushedAuthPath = new URL(
        discoveryRes.body.pushed_authorization_request_endpoint as string
      ).pathname;

      const parRes = await agent
        .post(pushedAuthPath)
        .auth("test", "test")
        .type("form")
        .send({
          client_id: "test",
          redirect_uri: "http://localhost:9876/callback",
          response_type: "code",
          scope: "openid",
          state: "state-123",
          issuer_state: "issuer-state-123",
        })
        .expect(201);

      expect(typeof parRes.body.request_uri).toBe("string");
      expect(parRes.body.request_uri.length).toBeGreaterThan(0);
      expect(typeof parRes.body.expires_in).toBe("number");
    });

    it("returns issuer_state in introspection after token issuance", async () => {
      const issuerState = "issuer-state-123";
      const tokenResponse = await issueAccessToken(agent, {
        issuer_state: issuerState,
      });

      const introspectionRes = await agent
        .post(tokenResponse.introspectionPath)
        .auth("test", "test")
        .type("form")
        .send({ token: tokenResponse.accessToken })
        .expect(200);

      expect(introspectionRes.body.active).toBe(true);
      expect(introspectionRes.body.issuer_state).toBe(issuerState);
    });
  });

  describe("token ttl", () => {
    const originalEnv = process.env;

    afterAll(() => {
      process.env = originalEnv;
    });

    it("uses ACCESS_TOKEN_TTL for token response expires_in", async () => {
      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
        ACCESS_TOKEN_TTL: "120",
      };

      vi.resetModules();
      const { createApp: createTtlApp } = await import("../src/app");
      const { app: ttlApp } = createTtlApp();
      const agent = request.agent(ttlApp);

      const tokenResponse = await issueAccessToken(agent);
      expect(tokenResponse.expiresIn).toBe(120);
    });
  });
});

function extractInteractionUid(location: string) {
  const match = location.match(/\/(?:as\/)?interaction\/([^/]+)/);
  if (!match) {
    throw new Error(`Missing interaction uid in location: ${location}`);
  }
  return match[1];
}

function normalizeLocation(location: string) {
  if (!location.startsWith("http://") && !location.startsWith("https://")) {
    return location.startsWith("/") ? location : `/${location}`;
  }
  const url = new URL(location);
  return `${url.pathname}${url.search}`;
}

async function followRedirectsToOk(
  agent: request.SuperAgentTest,
  location: string,
  maxHops = 5
) {
  let nextLocation = normalizeLocation(location);
  for (let hop = 0; hop < maxHops; hop += 1) {
    const res = await agent.get(nextLocation);
    if (res.status === 200) {
      return { response: res, location: nextLocation };
    }
    if (!res.headers.location) {
      throw new Error(`Expected redirect location, got ${res.status}`);
    }
    nextLocation = normalizeLocation(res.headers.location as string);
  }
  throw new Error(`Too many redirects while fetching ${location}`);
}

async function followRedirectsToAuthCode(
  agent: request.SuperAgentTest,
  location: string,
  redirectUri: string,
  maxHops = 5
) {
  let nextLocation = location;
  for (let hop = 0; hop < maxHops; hop += 1) {
    const directCode = tryExtractAuthCode(nextLocation, redirectUri);
    if (directCode) {
      return directCode;
    }

    const normalized = normalizeLocation(nextLocation);
    const res = await agent.get(normalized);
    if (!res.headers.location) {
      throw new Error(`Expected redirect location, got ${res.status}`);
    }
    nextLocation = res.headers.location as string;
  }
  throw new Error(`Too many redirects while fetching ${location}`);
}

function tryExtractAuthCode(location: string, redirectUri: string) {
  try {
    const url = new URL(location, "http://localhost");
    if (!url.href.startsWith(redirectUri)) {
      return null;
    }
    return url.searchParams.get("code");
  } catch {
    return null;
  }
}

async function issueAccessToken(
  agent: request.SuperAgentTest,
  authQuery: Record<string, string> = {}
) {
  const authRes = await agent
    .get("/as/auth")
    .query({
      client_id: "test",
      redirect_uri: "http://localhost:9876/callback",
      response_type: "code",
      scope: "openid",
      state: "state-123",
      ...authQuery,
    })
    .expect(303);

  const authLocation = authRes.headers.location;
  expect(authLocation).toBeTruthy();
  const interactionUid = extractInteractionUid(authLocation as string);

  await followRedirectsToOk(agent, authLocation as string);

  const loginRes = await agent
    .post(`/as/interaction/${interactionUid}/login`)
    .type("form")
    .send({ login: "test", password: "test" })
    .expect(303);

  const consentLocation = loginRes.headers.location;
  expect(consentLocation).toBeTruthy();
  const consentPage = await followRedirectsToOk(
    agent,
    consentLocation as string
  );
  const consentUid = extractInteractionUid(consentPage.location);

  const consentRes = await agent
    .post(`/as/interaction/${consentUid}/confirm`)
    .type("form")
    .send({})
    .expect((res) => {
      if (res.status !== 302 && res.status !== 303) {
        throw new Error(`Unexpected status ${res.status}`);
      }
    });

  const redirectLocation = consentRes.headers.location;
  expect(redirectLocation).toBeTruthy();
  const code = await followRedirectsToAuthCode(
    agent,
    redirectLocation as string,
    "http://localhost:9876/callback"
  );

  const tokenRes = await agent
    .post("/as/token")
    .auth("test", "test")
    .type("form")
    .send({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://localhost:9876/callback",
    })
    .expect(200);

  const accessToken = tokenRes.body.access_token as string;
  expect(accessToken).toBeTruthy();
  const expiresIn = tokenRes.body.expires_in as number;

  const discoveryRes = await agent
    .get("/as/.well-known/openid-configuration")
    .expect(200);

  const introspectionPath = new URL(
    discoveryRes.body.introspection_endpoint as string
  ).pathname;

  return { accessToken, introspectionPath, expiresIn };
}
