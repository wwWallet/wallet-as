import { execFileSync } from "node:child_process";
import { randomUUID, X509Certificate } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { calculateJwkThumbprint, exportJWK, generateKeyPair, importPKCS8, SignJWT } from "jose";
import type * as oidc from "oidc-provider";
import request from "supertest";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const consumeCode = vi.hoisted(() => vi.fn());
vi.mock("../../src/services/preAuthorizedCodeService", () => ({ consumePreAuthorizedCode: consumeCode }));

describe("attestation client authentication through the AS", () => {
  const issuer = "https://as.example.test";
  const clientId = `abca-test-${randomUUID()}`;
  let directory: string;
  let app: ReturnType<typeof import("../../src/app").createApp>["app"];
  let provider: oidc.Provider;
  let config: typeof import("../../src/config").default;
  let attesterKey: Awaited<ReturnType<typeof importPKCS8>>;
  let instanceKeys: Awaited<ReturnType<typeof generateKeyPair>>;
  let leafBase64: string;

  function openssl(...args: string[]) {
    execFileSync("openssl", args, { cwd: directory, stdio: "pipe" });
  }

  beforeAll(async () => {
    directory = fs.mkdtempSync(path.join(os.tmpdir(), "wallet-as-abca-integration-"));
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-nodes", "-keyout", "root.key", "-out", "root.pem", "-days", "2", "-subj", "/CN=Test CA",
      "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign");
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
      "-nodes", "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", "/CN=Test Attester");
    fs.writeFileSync(path.join(directory, "leaf.ext"),
      "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n");
    openssl("x509", "-req", "-in", "leaf.csr", "-CA", "root.pem", "-CAkey", "root.key",
      "-CAcreateserial", "-out", "leaf.pem", "-days", "1", "-extfile", "leaf.ext");
    leafBase64 = new X509Certificate(fs.readFileSync(path.join(directory, "leaf.pem"))).raw.toString("base64");
    attesterKey = await importPKCS8(fs.readFileSync(path.join(directory, "leaf.key"), "utf8"), "ES256");
    instanceKeys = await generateKeyPair("ES256");

    vi.stubEnv("SERVICE_URL", issuer);
    vi.stubEnv("BASE_PATH", "");
    vi.stubEnv("AUTHENTICATOR", "user-pass-pid");
    vi.stubEnv("OPENID4VC_PROFILE", "DEFAULT");
    vi.stubEnv("PRE_AUTHORIZED_CREDENTIAL_ISSUANCE", "true");
    vi.resetModules();
    config = (await import("../../src/config")).default;
    config.trustedRootCertificates = [fs.readFileSync(path.join(directory, "root.pem"), "utf8")];
    config.oidClients = [{
      client_id: clientId,
      token_endpoint_auth_method: "attest_jwt_client_auth",
      grant_types: ["urn:ietf:params:oauth:grant-type:pre-authorized_code"],
      response_types: [], redirect_uris: ["https://wallet.example/callback"],
    }];
    ({ app, provider } = (await import("../../src/app")).createApp());
  });

  afterAll(async () => {
    if (typeof app !== "undefined") await (await import("../../src/stores/dataStoreClient")).dataStoreClient.quit();
    vi.unstubAllEnvs();
    if (directory) fs.rmSync(directory, { recursive: true, force: true });
  });

  beforeEach(() => {
    consumeCode.mockReset().mockResolvedValue({ account_id: "abca-user", scope: "openid" });
    config.openid4vcProfile = "DEFAULT";
  });

  async function attestation(key = attesterKey) {
    return new SignJWT({ cnf: { jwk: await exportJWK(instanceKeys.publicKey) } })
      .setProtectedHeader({ alg: "ES256", typ: "oauth-client-attestation+jwt", x5c: [leafBase64] })
      .setSubject(clientId).setIssuedAt().setExpirationTime("5m").sign(key);
  }

  async function pop(challenge?: string, audience = issuer) {
    return new SignJWT(challenge ? { challenge } : {})
      .setProtectedHeader({ alg: "ES256", typ: "oauth-client-attestation-pop+jwt" })
      .setAudience(audience).setIssuedAt().setJti(randomUUID()).sign(instanceKeys.privateKey);
  }

  async function tokenRequest(wia: string, proof: string) {
    const dpop = await new SignJWT({ htm: "POST", htu: `${issuer}/token` })
      .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(instanceKeys.publicKey) })
      .setIssuedAt().setJti(randomUUID()).sign(instanceKeys.privateKey);
    return request(app).post("/token").set("Host", "as.example.test").set("X-Forwarded-Proto", "https")
      .set("OAuth-Client-Attestation", wia).set("OAuth-Client-Attestation-PoP", proof).set("DPoP", dpop)
      .type("form").send({
        grant_type: "urn:ietf:params:oauth:grant-type:pre-authorized_code",
        "pre-authorized_code": "integration-code",
      });
  }

  async function challenge() {
    const discovery = await request(app).get("/.well-known/openid-configuration").expect(200);
    expect(discovery.body.token_endpoint_auth_methods_supported).toContain("attest_jwt_client_auth");
    const response = await request(app).post(new URL(discovery.body.challenge_endpoint).pathname).expect(200);
    expect(response.body.attestation_challenge).toEqual(expect.any(String));
    return response.body.attestation_challenge as string;
  }

  it("challenges, then authenticates the attested client and issues its token", async () => {
    const wia = await attestation();
    const first = await tokenRequest(wia, await pop());
    expect(first.status).toBe(400);
    expect(first.body.error).toBe("use_attestation_challenge");
    expect(consumeCode).not.toHaveBeenCalled();
    const nextChallenge = first.headers["oauth-client-attestation-challenge"];
    expect(nextChallenge).toEqual(expect.any(String));

    const response = await tokenRequest(wia, await pop(nextChallenge));
    expect(response.status).toBe(200);
    expect(response.body.access_token).toEqual(expect.any(String));
    expect(consumeCode).toHaveBeenCalledOnce();
    const accessToken = await provider.AccessToken.find(response.body.access_token);
    expect(accessToken?.clientId).toBe(clientId);
    expect(accessToken?.jkt).toBe(await calculateJwkThumbprint(await exportJWK(instanceKeys.publicKey)));
  });

  it("rejects an attestation signed by a key different from its trusted certificate", async () => {
    const wrongSigner = await generateKeyPair("ES256");
    const response = await tokenRequest(await attestation(wrongSigner.privateKey), await pop(await challenge()));
    expect(response.status).toBe(401);
    expect(response.body.error).toBe("invalid_client");
    expect(consumeCode).not.toHaveBeenCalled();
  });

  it("rejects a PoP intended for another AS", async () => {
    const response = await tokenRequest(await attestation(), await pop(await challenge(), "https://other-as.example"));
    expect(response.status).toBe(401);
    expect(response.body.error).toBe("invalid_client");
    expect(consumeCode).not.toHaveBeenCalled();
  });

  it("rejects replay of a successfully authenticated PoP", async () => {
    const wia = await attestation();
    const proof = await pop(await challenge());
    const first = await tokenRequest(wia, proof);
    expect(first.status).toBe(200);
    const replay = await tokenRequest(wia, proof);
    expect(replay.status).toBe(401);
    expect(replay.body.error).toBe("invalid_client");
    expect(consumeCode).toHaveBeenCalledOnce();
  });

  it("runs the WE BUILD callback when that profile is selected", async () => {
    config.openid4vcProfile = "WEBUILD";
    const response = await tokenRequest(await attestation(), await pop(await challenge()));
    expect(response.status).toBe(400);
    expect(response.body.error).toBe("invalid_client_attestation");
    expect(response.body.error_description).toContain("wallet_name");
    expect(consumeCode).not.toHaveBeenCalled();
  });
});
