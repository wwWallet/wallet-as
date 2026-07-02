import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, expect, it, vi } from "vitest";

describe("config", () => {
  const originalCwd = process.cwd();

  function writeClientsFile(root: string, clients: unknown) {
    const configDir = path.join(root, "src/config");
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(
      path.join(configDir, "oauth2clients.json"),
      JSON.stringify(clients),
      "utf-8"
    );
  }

  async function importConfigFromTempProject(clients: unknown) {
    const tempProject = fs.mkdtempSync(path.join(os.tmpdir(), "wallet-as-config-"));
    writeClientsFile(tempProject, clients);
    process.chdir(tempProject);
    vi.resetModules();

    try {
      return await import("../../src/config");
    } finally {
      process.chdir(originalCwd);
    }
  }

  it("normalizes BASE_PATH and reads basic env vars", async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      INTROSPECTION_CLIENT: "client-a",
      INTROSPECTION_CLIENT_SECRET: "secret-a",
      BASE_PATH: "as",
      AUTHORIZATION_CODE_TTL: "90",
      PRE_AUTHORIZED_CONSENT_CLIENT_IDS: "wallet_issuer, test-client",
    };

    vi.resetModules();
    const config = (await import("../../src/config")).default;

    expect(config.introspectionClient).toBe("client-a");
    expect(config.introspectionClientSecret).toBe("secret-a");
    expect(config.basePath).toBe("/as");
    expect(config.authBrokerRedirectUri).toBe("http://localhost:6060/interaction/authBroker/callback");
    expect(config.ttl.authorizationCode).toBe(90);
    expect(config.preAuthorizedConsentClientIds).toEqual(["wallet_issuer", "test-client"]);

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

  it("loads oid clients from the project config file and preserves extra client metadata", async () => {
    const { default: config } = await importConfigFromTempProject([
      {
        client_id: "wallet-client",
        client_secret: "wallet-secret",
        redirect_uris: ["https://wallet.example/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        client_name: "wwWallet Client",
        jwks_uri: "https://wallet.example/jwks.json",
      },
    ]);

    expect(config.oidClients).toEqual([
      {
        client_id: "wallet-client",
        client_secret: "wallet-secret",
        redirect_uris: ["https://wallet.example/callback"],
        grant_types: ["authorization_code", "refresh_token"],
        client_name: "wwWallet Client",
        jwks_uri: "https://wallet.example/jwks.json",
      },
    ]);
  });

  it("rejects oauth clients that do not match ClientMetadata requirements", async () => {
    await expect(
      importConfigFromTempProject([
        {
          client_id: "broken-client",
          grant_types: ["authorization_code"],
        },
      ])
    ).rejects.toThrow(/redirect_uris/);
  });

  it("does not allow production builds to use an insecure Data Store", async () => {
    const originalEnv = process.env;
    process.env = {
      ...originalEnv,
      NODE_ENV: "production",
      DATA_STORE_PASSWORD: undefined
    };

    const exitSpy = vi
      .spyOn(process, "exit")
      .mockImplementation((code?: number) => {
        throw new Error(`process.exit:${code}`);
      });
    const consoleSpy = vi
      .spyOn(console, "error")
      .mockImplementation(() => {});

    vi.resetModules();

    try {
      await expect(import("../../src/config")).rejects.toThrow(
        "process.exit:1"
      );
      expect(exitSpy).toHaveBeenCalledWith(1);
      expect(consoleSpy).toHaveBeenCalledWith(
        "FATAL: Insecure data store found in production."
      );
    } finally {
      process.env = originalEnv;
      exitSpy.mockRestore();
      consoleSpy.mockRestore();
    }
  });
});
