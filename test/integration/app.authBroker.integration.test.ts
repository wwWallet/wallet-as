import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import type { AddressInfo } from "node:net";
import { createServer, type Server } from "node:http";
import request from "supertest";
import { createApp } from "../../src/app";

vi.mock("openid-client", async () => {
  const actual = await vi.importActual<typeof import("openid-client")>("openid-client");

  const discoveryWithHttpAllowed: typeof actual.discovery = async (
    server,
    clientId,
    metadata,
    clientAuthentication,
    options
  ) => {
    const configuration = await actual.discovery(
      server,
      clientId,
      metadata,
      clientAuthentication,
      {
        ...options,
        execute: [...(options?.execute ?? []), actual.allowInsecureRequests],
      }
    );
    actual.allowInsecureRequests(configuration);
    return configuration;
  };

  return {
    ...actual,
    discovery: discoveryWithHttpAllowed,
  };
});

describe("app integration", () => {
  const { app } = createApp();
  const externalDemoUsername = "broker-demo-user";
  const externalDemoPassword = "broker-demo-pass";
  const brokerClientId = "test";
  const brokerClientSecret = "test";
  const externalRedirectUri = "http://localhost:9876/callback";

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
    let externalAgent: request.SuperAgentTest;
    let externalServer: Server;
    let accessToken: string;
    let introspectionPath: string;
    let externalIssuer: string;
    let brokerIssuer: string;
    let reachedBrokerCallback: boolean;

    beforeAll(async () => {
      const externalPort = await getFreePort();
      const brokerPort = await getFreePort();
      externalIssuer = `http://127.0.0.1:${externalPort}`;
      brokerIssuer = `http://127.0.0.1:${brokerPort}`;

      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
        SERVICE_URL: externalIssuer,
        USER_PASS_PID_DEMO_USERNAME: externalDemoUsername,
        USER_PASS_PID_DEMO_PASSWORD: externalDemoPassword,
      };

      vi.resetModules();
      const { createApp: createExternalApp } = await import("../../src/app");
      const { app: externalApp } = createExternalApp();
      externalServer = await listenOnPort(externalApp, externalPort);
      externalAgent = request.agent(`http://127.0.0.1:${externalPort}`);

      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "auth-broker",
        SERVICE_URL: brokerIssuer,
        AUTH_BROKER_PROVIDER_URL: externalIssuer,
        AUTH_BROKER_CLIENT_ID: brokerClientId,
        AUTH_BROKER_CLIENT_SECRET: brokerClientSecret,
        AUTH_BROKER_SCOPE: "openid",
        AUTH_BROKER_REDIRECT_URI: externalRedirectUri,
        AUTH_BROKER_SKIP_LOGOUT: "true",
        INTROSPECTION_CLIENT: "introspect-client",
        INTROSPECTION_CLIENT_SECRET: "introspect-secret",
      };

      vi.resetModules();
      const { createApp: createIntrospectionApp } = await import("../../src/app");
      const { app: introspectionApp } = createIntrospectionApp();
      agent = request.agent(introspectionApp);

      const tokenResponse = await issueAccessToken(
        agent,
        externalAgent,
        externalIssuer,
        brokerIssuer
      );
      accessToken = tokenResponse.accessToken;
      introspectionPath = tokenResponse.introspectionPath;
      reachedBrokerCallback = tokenResponse.reachedBrokerCallback;
    });

    afterAll(async () => {
      process.env = originalEnv;
      if (externalServer) {
        await closeServer(externalServer);
      }
    });

    it("logs in at the external issuer and returns via broker callback", async () => {
      expect(reachedBrokerCallback).toBe(true);
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
  });

  describe("data store", () => {
    const originalEnv = process.env;
    let externalServer: Server;

    afterAll(async () => {
      process.env = originalEnv;
      if (externalServer) {
        await closeServer(externalServer);
      }
    });

    it("uses ACCESS_TOKEN_TTL for token response expires_in", async () => {
      const externalPort = await getFreePort();
      const brokerPort = await getFreePort();
      const externalIssuer = `http://127.0.0.1:${externalPort}`;
      const brokerIssuer = `http://127.0.0.1:${brokerPort}`;

      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
        SERVICE_URL: externalIssuer,
        USER_PASS_PID_DEMO_USERNAME: externalDemoUsername,
        USER_PASS_PID_DEMO_PASSWORD: externalDemoPassword,
      };

      vi.resetModules();
      const { createApp: createExternalApp } = await import("../../src/app");
      const { app: externalApp } = createExternalApp();
      externalServer = await listenOnPort(externalApp, externalPort);
      const externalAgent = request.agent(`http://127.0.0.1:${externalPort}`);

      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "auth-broker",
        SERVICE_URL: brokerIssuer,
        AUTH_BROKER_PROVIDER_URL: externalIssuer,
        AUTH_BROKER_CLIENT_ID: brokerClientId,
        AUTH_BROKER_CLIENT_SECRET: brokerClientSecret,
        AUTH_BROKER_SCOPE: "openid",
        AUTH_BROKER_REDIRECT_URI: externalRedirectUri,
        AUTH_BROKER_SKIP_LOGOUT: "true",
        ACCESS_TOKEN_TTL: "120",
      };

      vi.resetModules();
      const { createApp: createDataStoreApp } = await import("../../src/app");
      const { app: dataStoreApp } = createDataStoreApp();
      const agent = request.agent(dataStoreApp);

      const tokenResponse = await issueAccessToken(
        agent,
        externalAgent,
        externalIssuer,
        brokerIssuer
      );
      expect(tokenResponse.expiresIn).toBe(120);
    });
  });

  describe("application restart", () => {
    const originalEnv = process.env;
    let externalServer: Server;

    afterAll(() => {
      process.env = originalEnv;
    });

    it("can introspect tokens issued before the application restarted", async () => {
    //
    // Start external issuer
    //

      const externalPort = await getFreePort();
      const brokerPort = await getFreePort();

      const externalIssuer = `http://127.0.0.1:${externalPort}`;
      const brokerIssuer = `http://127.0.0.1:${brokerPort}`;

      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "user-pass-pid",
        SERVICE_URL: externalIssuer,
        USER_PASS_PID_DEMO_USERNAME: externalDemoUsername,
        USER_PASS_PID_DEMO_PASSWORD: externalDemoPassword,
      };

      vi.resetModules();

      const { createApp } = await import("../../src/app");

      const { app: externalApp } = createApp();

      externalServer = await listenOnPort(externalApp, externalPort);

      const externalAgent = request.agent(`http://127.0.0.1:${externalPort}`);

      //
      // Configure broker
      //

      process.env = {
        ...originalEnv,
        AUTHENTICATOR: "auth-broker",
        SERVICE_URL: brokerIssuer,
        AUTH_BROKER_PROVIDER_URL: externalIssuer,
        AUTH_BROKER_CLIENT_ID: brokerClientId,
        AUTH_BROKER_CLIENT_SECRET: brokerClientSecret,
        AUTH_BROKER_SCOPE: "openid",
        AUTH_BROKER_REDIRECT_URI: externalRedirectUri,
        AUTH_BROKER_SKIP_LOGOUT: "true",
      };

      //
      // App instance #1
      //

      const firstAgent = await createBrokerApp();

      const token = await issueAccessToken(
        firstAgent,
        externalAgent,
        externalIssuer,
        brokerIssuer
      );

      //
      // "Restart"
      //

      const secondAgent = await createBrokerApp();

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
  if (match[1] === "authBroker") {
    throw new Error(`Location is auth-broker callback, not interaction uid: ${location}`);
  }
  return match[1];
}

function normalizeLocation(location: string) {
  if (!location.startsWith("http://") && !location.startsWith("https://")) {
    const path = location.startsWith("/") ? location : `/${location}`;
    return path;
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

async function followRedirectsToOkAcrossOrigins(
  location: string,
  externalAgent: request.SuperAgentTest,
  brokerAgent: request.SuperAgentTest,
  externalIssuer: string,
  brokerIssuer: string,
  maxHops = 8
) {
  const externalOrigin = new URL(externalIssuer).origin;
  const brokerOrigin = new URL(brokerIssuer).origin;
  let nextLocation = location;

  for (let hop = 0; hop < maxHops; hop += 1) {
    const url = new URL(nextLocation, externalOrigin);
    const normalizedPath = normalizeLocation(url.toString());

    let targetAgent: request.SuperAgentTest;
    if (url.origin === externalOrigin) {
      targetAgent = externalAgent;
    } else if (url.origin === brokerOrigin) {
      targetAgent = brokerAgent;
    } else {
      throw new Error(`Unexpected redirect origin ${url.origin}`);
    }

    const res = await targetAgent.get(normalizedPath);
    if (res.status === 200) {
      return { response: res, location: `${url.origin}${normalizedPath}` };
    }
    if (!res.headers.location) {
      throw new Error(
        `Expected redirect location, got ${res.status} for ${url.origin}${normalizedPath}`
      );
    }
    nextLocation = res.headers.location as string;
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
      throw new Error(
        `Expected redirect location, got ${res.status} for next='${nextLocation}' normalized='${normalized}'`
      );
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
  externalAgent: request.SuperAgentTest,
  externalIssuer: string,
  brokerIssuer: string
) {
  const authRes = await agent
    .get("/auth")
    .query({
      client_id: "test",
      redirect_uri: "http://localhost:9876/callback",
      response_type: "code",
      scope: "openid",
      state: "state-123",
    })
    .expect(303);

  const authLocation = authRes.headers.location;
  expect(authLocation).toBeTruthy();

  const brokerRedirectRes = await agent
    .get(normalizeLocation(authLocation as string))
    .expect(302);
  const externalAuthorizeUrl = new URL(brokerRedirectRes.headers.location as string);

  const externalAuthRes = await externalAgent
    .get(normalizeLocation(externalAuthorizeUrl.toString()))
    .expect(303);

  const externalInteractionPage = await followRedirectsToOkAcrossOrigins(
    externalAuthRes.headers.location as string,
    externalAgent,
    agent,
    externalIssuer,
    brokerIssuer
  );
  const externalInteractionUid = extractInteractionUid(externalInteractionPage.location);

  const externalLoginRes = await externalAgent
    .post(`/interaction/${externalInteractionUid}/login`)
    .type("form")
    .send({ login: "broker-demo-user", password: "broker-demo-pass" })
    .expect(303);

  const externalConsentLocation = externalLoginRes.headers.location;
  expect(externalConsentLocation).toBeTruthy();
  const externalConsentPage = await followRedirectsToOk(
    externalAgent,
    externalConsentLocation as string
  );
  const externalConsentUid = extractInteractionUid(externalConsentPage.location);

  const externalConsentRes = await externalAgent
    .post(`/interaction/${externalConsentUid}/confirm`)
    .type("form")
    .send({})
    .expect((res) => {
      if (res.status !== 302 && res.status !== 303) {
        throw new Error(`Unexpected status ${res.status}`);
      }
    });

  const brokerCallbackLocation = await followRedirectsToBrokerCallback(
    externalConsentRes.headers.location as string,
    externalAgent,
    agent,
    externalIssuer,
    brokerIssuer
  );
  const brokerCallbackUrl = normalizeToBrokerCallbackUrl(
    brokerCallbackLocation,
    brokerIssuer
  );
  const reachedBrokerCallback = brokerCallbackUrl.startsWith(
    `${brokerIssuer}/interaction/authBroker/callback`
  );

  const brokerCallbackRes = await agent
    .get(normalizeLocation(brokerCallbackUrl))
    .expect((res) => {
      if (res.status !== 302 && res.status !== 303) {
        throw new Error(`Unexpected status ${res.status}`);
      }
    });

  const code = await followRedirectsToAuthCode(
    agent,
    brokerCallbackRes.headers.location as string,
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
  expect(accessToken).toBeTruthy();
  const expiresIn = tokenRes.body.expires_in as number;

  const discoveryRes = await agent
    .get("/.well-known/openid-configuration")
    .expect(200);

  const introspectionPath = new URL(
    discoveryRes.body.introspection_endpoint as string
  ).pathname;

  return { accessToken, introspectionPath, expiresIn, reachedBrokerCallback };
}

function normalizeToBrokerCallbackUrl(location: string, brokerIssuer: string) {
  const url = new URL(location, "http://localhost");
  const brokerOrigin = new URL(brokerIssuer).origin;
  if (
    url.origin === brokerOrigin &&
    url.pathname === "/interaction/authBroker/callback"
  ) {
    return url.toString();
  }
  return `${brokerIssuer}/interaction/authBroker/callback${url.search}`;
}

async function followRedirectsToBrokerCallback(
  location: string,
  externalAgent: request.SuperAgentTest,
  brokerAgent: request.SuperAgentTest,
  externalIssuer: string,
  brokerIssuer: string,
  maxHops = 8
) {
  const externalOrigin = new URL(externalIssuer).origin;
  const brokerOrigin = new URL(brokerIssuer).origin;
  let nextLocation = location;

  for (let hop = 0; hop < maxHops; hop += 1) {
    const url = new URL(nextLocation, externalOrigin);
    if (
      url.origin === brokerOrigin &&
      url.pathname === "/interaction/authBroker/callback"
    ) {
      return url.toString();
    }

    if (url.origin !== externalOrigin && url.origin !== brokerOrigin) {
      return url.toString();
    }

    const targetAgent = url.origin === externalOrigin ? externalAgent : brokerAgent;
    const res = await targetAgent.get(normalizeLocation(url.toString()));
    if (!res.headers.location) {
      throw new Error(`Expected redirect location, got ${res.status}`);
    }
    nextLocation = res.headers.location as string;
  }

  throw new Error("Too many redirects while trying to reach broker callback");
}

async function createBrokerApp() {
  vi.resetModules();

  const { createApp } = await import("../../src/app");

  const { app } = createApp();

  return request.agent(app);
}

function listenOnPort(app: Parameters<typeof createServer>[0], port: number) {
  return new Promise<Server>((resolve, reject) => {
    const server = createServer(app);
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      resolve(server);
    });
  });
}

function closeServer(server: Server) {
  return new Promise<void>((resolve, reject) => {
    server.close((err) => {
      if (err) {
        reject(err);
        return;
      }
      resolve();
    });
  });
}

function getFreePort() {
  return new Promise<number>((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address() as AddressInfo;
      const { port } = address;
      probe.close((err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(port);
      });
    });
  });
}
