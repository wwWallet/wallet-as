import { afterAll, describe, expect, it } from "vitest";
import Valkey from "iovalkey";
import { createOidcValkeyAdapter } from "../../src/stores/OidcValkeyAdapter";

const client = new Valkey({
  host: process.env.DATA_STORE_HOST,
  port: Number(process.env.DATA_STORE_PORT),
  password: process.env.DATA_STORE_PASSWORD ?? undefined,
});

afterAll(async () => {
  client.disconnect();
});

describe("oidc valkey adapter integration", () => {
  it("persists session and grant data through real Valkey", async () => {
    const suffix = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const sessionUid = `session-uid-${suffix}`;
    const sessionId = `session-${suffix}`;
    const grantId = `grant-${suffix}`;
    const accessTokenId = `access-token-${suffix}`;

    const sessionAdapter = createOidcValkeyAdapter(client as any)("Session");
    const accessTokenAdapter = createOidcValkeyAdapter(client as any)(
      "AccessToken"
    );

    await sessionAdapter.upsert(
      sessionId,
      {
        uid: sessionUid,
        accountId: "account-1",
      } as any,
      60
    );

    await accessTokenAdapter.upsert(
      accessTokenId,
      {
        grantId,
        sessionUid,
        clientId: "client-1",
      } as any,
      120
    );

    const restartedSessionAdapter = createOidcValkeyAdapter(client as any)(
      "Session"
    );
    const restartedAccessTokenAdapter = createOidcValkeyAdapter(client as any)(
      "AccessToken"
    );

    expect(await restartedSessionAdapter.findByUid(sessionUid)).toMatchObject({
      uid: sessionUid,
      accountId: "account-1",
    });
    expect(await restartedAccessTokenAdapter.find(accessTokenId)).toMatchObject({
      grantId,
      sessionUid,
      clientId: "client-1",
    });

    await restartedAccessTokenAdapter.revokeByGrantId(grantId);

    expect(await restartedAccessTokenAdapter.find(accessTokenId)).toBeUndefined();
    expect(await restartedSessionAdapter.findByUid(sessionUid)).toMatchObject({
      uid: sessionUid,
      accountId: "account-1",
    });
  });
});
