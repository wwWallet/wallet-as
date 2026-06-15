import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import request from "supertest";
import { createApp } from "../../src/app";

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
      const { createApp: createIntrospectionApp } = await import("../../src/app");
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
        .get("/.well-known/openid-configuration")
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

    it("returns a huge issuer_state in introspection after token issuance", async () => {
      const issuerState = "x".repeat(10_000);
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

  describe("data store", () => {
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
      const { createApp: createDataStoreApp } = await import("../../src/app");
      const { app: dataStoreApp } = createDataStoreApp();
      const agent = request.agent(dataStoreApp);

      const tokenResponse = await issueAccessToken(agent);
      expect(tokenResponse.expiresIn).toBe(120);
    });
  });

  describe("parallel issuance grants", () => {
    const originalEnv = process.env;

    afterAll(() => {
      process.env = originalEnv;
    });

    it("keeps POR refresh token valid when PID issuance starts before POR access token expires", async () => {
      const trustedIssuer = "http://localhost:8003/openid";
      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
        USER_PASS_PID_DEMO_USERNAME: "test",
        USER_PASS_PID_DEMO_PASSWORD: "test",
        ACCESS_TOKEN_TTL: "10",
        REFRESH_TOKEN_TTL: "2592000",
        SCOPES: "openid,por:sd_jwt_vc,pid:sd_jwt_dc",
        TRUSTED_ISSUERS: trustedIssuer,
      };

      vi.resetModules();
      const { createApp: createParallelIssuanceApp } = await import("../../src/app");
      const { app: parallelIssuanceApp, provider } =
        createParallelIssuanceApp();
      const agent = request.agent(parallelIssuanceApp);

      const porTokenResponse = await issueAccessToken(agent, {
        scope: "openid por:sd_jwt_vc",
        resource: trustedIssuer,
        issuer_state: "issuer-state-por",
      });
      const pidTokenResponse = await issueAccessToken(agent, {
        scope: "openid pid:sd_jwt_dc",
        resource: trustedIssuer,
        issuer_state: "issuer-state-pid",
      });

      const porToken = await provider.AccessToken.find(porTokenResponse.accessToken);
      const pidToken = await provider.AccessToken.find(pidTokenResponse.accessToken);

      expect(porToken).toBeTruthy();
      expect(pidToken).toBeTruthy();

      const porGrantId = (porToken as any).grantId;
      const pidGrantId = (pidToken as any).grantId;

      expect((pidToken as any).clientId).toBe((porToken as any).clientId);
      expect((pidToken as any).sessionUid).toBe((porToken as any).sessionUid);
      expect(typeof porGrantId).toBe("string");
      expect(porGrantId.length).toBeGreaterThan(0);
      expect(typeof pidGrantId).toBe("string");
      expect(pidGrantId.length).toBeGreaterThan(0);
      expect(pidGrantId).toBe(porGrantId);

      const refreshedPorTokenResponse = await refreshAccessToken(agent, {
        refreshToken: porTokenResponse.refreshToken,
        scope: "por:sd_jwt_vc",
      });
      const refreshedPorToken = await provider.AccessToken.find(
        refreshedPorTokenResponse.accessToken
      );

      expect(refreshedPorToken).toBeTruthy();
      expect((refreshedPorToken as any).grantId).toBe(porGrantId);
    });

    it("keeps POR refresh token valid when PID issuance starts after POR access token expires", async () => {
      const trustedIssuer = "http://localhost:8003/openid";
      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
        USER_PASS_PID_DEMO_USERNAME: "test",
        USER_PASS_PID_DEMO_PASSWORD: "test",
        ACCESS_TOKEN_TTL: "1",
        REFRESH_TOKEN_TTL: "2592000",
        SCOPES: "openid,por:sd_jwt_vc,pid:sd_jwt_dc",
        TRUSTED_ISSUERS: trustedIssuer,
      };

      vi.resetModules();
      const { createApp: createParallelIssuanceApp } = await import("../../src/app");
      const { app: parallelIssuanceApp, provider } =
        createParallelIssuanceApp();
      const agent = request.agent(parallelIssuanceApp);

      const porTokenResponse = await issueAccessToken(agent, {
        scope: "openid por:sd_jwt_vc",
        resource: trustedIssuer,
        issuer_state: "issuer-state-por",
      });

      await new Promise((resolve) => setTimeout(resolve, 1100));

      const savedPorRefreshTokenBeforePid = await provider.RefreshToken.find(
        porTokenResponse.refreshToken,
        { ignoreExpiration: true }
      );
      expect(savedPorRefreshTokenBeforePid).toBeTruthy();

      const pidTokenResponse = await issueAccessToken(agent, {
        scope: "openid pid:sd_jwt_dc",
        resource: trustedIssuer,
        issuer_state: "issuer-state-pid",
      });

      const savedPorRefreshTokenAfterPid = await provider.RefreshToken.find(
        porTokenResponse.refreshToken,
        { ignoreExpiration: true }
      );
      expect(savedPorRefreshTokenAfterPid).toBeTruthy();

      const porToken = await provider.AccessToken.find(
        porTokenResponse.accessToken,
        { ignoreExpiration: true }
      );
      const pidToken = await provider.AccessToken.find(pidTokenResponse.accessToken);

      expect(porToken).toBeTruthy();
      expect(pidToken).toBeTruthy();

      const porGrantId = (porToken as any).grantId;
      const pidGrantId = (pidToken as any).grantId;

      expect((pidToken as any).clientId).toBe((porToken as any).clientId);
      expect((pidToken as any).sessionUid).toBe((porToken as any).sessionUid);
      expect(typeof porGrantId).toBe("string");
      expect(porGrantId.length).toBeGreaterThan(0);
      expect(typeof pidGrantId).toBe("string");
      expect(pidGrantId.length).toBeGreaterThan(0);
      expect(pidGrantId).toBe(porGrantId);
      expect((savedPorRefreshTokenAfterPid as any).grantId).toBe(porGrantId);

      const refreshedPorTokenResponse = await refreshAccessToken(agent, {
        refreshToken: porTokenResponse.refreshToken,
        scope: "por:sd_jwt_vc",
      });
      const refreshedPorToken = await provider.AccessToken.find(
        refreshedPorTokenResponse.accessToken
      );

      expect(refreshedPorToken).toBeTruthy();
      expect((refreshedPorToken as any).grantId).toBe(porGrantId);
    });
  });

  describe("issuer_state token scoping", () => {
    const originalEnv = process.env;

    afterAll(() => {
      process.env = originalEnv;
    });

    it("does not inherit issuer_state from a reused grant", async () => {
      const trustedIssuer = "http://localhost:8003/openid";
      const issuerState = "issuer-state-diploma";

      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
        USER_PASS_PID_DEMO_USERNAME: "test",
        USER_PASS_PID_DEMO_PASSWORD: "test",
        SCOPES: "openid,diploma",
        TRUSTED_ISSUERS: trustedIssuer,
      };

      vi.resetModules();
      const { createApp: createIssuerStateReuseApp } = await import("../../src/app");
      const { app: issuerStateReuseApp } = createIssuerStateReuseApp();
      const agent = request.agent(issuerStateReuseApp);

      const credentialOfferTokenResponse = await issueAccessToken(agent, {
        scope: "openid diploma",
        resource: trustedIssuer,
        issuer_state: issuerState,
      });
      const sameSessionTokenResponse = await issueAccessToken(agent, {
        scope: "openid diploma",
        resource: trustedIssuer,
      });

      const credentialOfferIntrospection = await introspectAccessToken(
        agent,
        credentialOfferTokenResponse
      );
      const sameSessionIntrospection = await introspectAccessToken(
        agent,
        sameSessionTokenResponse
      );

      expect(credentialOfferIntrospection.active).toBe(true);
      expect(credentialOfferIntrospection.issuer_state).toBe(issuerState);
      expect(sameSessionIntrospection.active).toBe(true);
      expect(sameSessionIntrospection.issuer_state).toBeUndefined();
    });
  });

  describe("application restart", () => {
    const originalEnv = process.env;

    afterAll(() => {
      process.env = originalEnv;
    });

    it("can introspect tokens issued before the application restarted", async () => {
      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
      };

      //
      // First application instance
      //
      vi.resetModules();

      const { createApp: createFirstApp } = await import("../../src/app");

      const { app: firstApp } = createFirstApp();

      const firstAgent = request.agent(firstApp);

      const token = await issueAccessToken(firstAgent);

      //
      // Simulate application restart
      //
      vi.resetModules();

      const { createApp: createSecondApp } = await import("../../src/app");

      const { app: secondApp } = createSecondApp();

      const secondAgent = request.agent(secondApp);

      //
      // The second instance should still be able to read state
      // from Valkey.
      //
      const introspection = await secondAgent
        .post(token.introspectionPath)
        .auth("test", "test")
        .type("form")
        .send({
          token: token.accessToken,
        })
        .expect(200);

      expect(introspection.body.active).toBe(true);
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
    .get("/auth")
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

  let interactionPage = await followRedirectsToOk(agent, authLocation as string);
  let consentUid = extractInteractionUid(interactionPage.location);

  if (interactionPage.response.text.includes('name="login"')) {
    const loginRes = await agent
      .post(`/interaction/${consentUid}/login`)
      .type("form")
      .send({ login: "test", password: "test" })
      .expect(303);

    const consentLocation = loginRes.headers.location;
    expect(consentLocation).toBeTruthy();
    interactionPage = await followRedirectsToOk(
      agent,
      consentLocation as string
    );
    consentUid = extractInteractionUid(interactionPage.location);
  }

  const consentRes = await agent
    .post(`/interaction/${consentUid}/confirm`)
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
    .post("/token")
    .auth("test", "test")
    .type("form")
    .send({
      grant_type: "authorization_code",
      code,
      redirect_uri: "http://localhost:9876/callback",
    })
    .expect(200);

  const accessToken = tokenRes.body.access_token as string;
  const refreshToken = tokenRes.body.refresh_token as string;
  expect(accessToken).toBeTruthy();
  expect(refreshToken).toBeTruthy();
  const expiresIn = tokenRes.body.expires_in as number;

  const discoveryRes = await agent
    .get("/.well-known/openid-configuration")
    .expect(200);

  const introspectionPath = new URL(
    discoveryRes.body.introspection_endpoint as string
  ).pathname;

  return { accessToken, refreshToken, introspectionPath, expiresIn };
}

async function introspectAccessToken(
  agent: request.SuperAgentTest,
  tokenResponse: Awaited<ReturnType<typeof issueAccessToken>>
) {
  const introspectionRes = await agent
    .post(tokenResponse.introspectionPath)
    .auth("test", "test")
    .type("form")
    .send({ token: tokenResponse.accessToken })
    .expect(200);

  return introspectionRes.body;
}

async function refreshAccessToken(
  agent: request.SuperAgentTest,
  options: {
    refreshToken: string;
    scope?: string;
  }
) {
  const tokenRes = await agent
    .post("/token")
    .auth("test", "test")
    .type("form")
    .send({
      grant_type: "refresh_token",
      refresh_token: options.refreshToken,
      ...(options.scope ? { scope: options.scope } : {}),
    })
    .expect(200);

  const accessToken = tokenRes.body.access_token as string;
  const refreshToken = tokenRes.body.refresh_token as string | undefined;
  expect(accessToken).toBeTruthy();

  return {
    accessToken,
    refreshToken,
    expiresIn: tokenRes.body.expires_in as number,
  };
}
