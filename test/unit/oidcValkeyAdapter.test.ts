import { describe, expect, it, vi } from "vitest";
import { createOidcValkeyAdapter } from "../../src/stores/OidcValkeyAdapter";

class FakeValkey {
  private strings = new Map<string, string>();
  private sets = new Map<string, Set<string>>();
  private expiresAt = new Map<string, number>();
  nowMs = 1_000_000;

  async get(key: string) {
    if (this.isExpired(key)) {
      return null;
    }
    return this.strings.get(key) ?? null;
  }

  async set(
    key: string,
    value: string,
    ttlMode?: "EX" | "PX",
    ttl?: number
  ) {
    this.strings.set(key, value);
    if (ttlMode === "EX" && typeof ttl === "number") {
      this.expiresAt.set(key, this.nowMs + ttl * 1000);
    } else if (ttlMode === "PX" && typeof ttl === "number") {
      this.expiresAt.set(key, this.nowMs + ttl);
    } else {
      this.expiresAt.delete(key);
    }
  }

  async del(...keys: string[]) {
    for (const key of keys) {
      this.strings.delete(key);
      this.sets.delete(key);
      this.expiresAt.delete(key);
    }
  }

  async sadd(key: string, value: string) {
    const set = this.sets.get(key) ?? new Set<string>();
    set.add(value);
    this.sets.set(key, set);
  }

  async smembers(key: string) {
    if (this.isExpired(key)) {
      return [];
    }
    return [...(this.sets.get(key) ?? new Set<string>())];
  }

  async srem(key: string, value: string) {
    this.sets.get(key)?.delete(value);
  }

  async expire(key: string, seconds: number) {
    this.expiresAt.set(key, this.nowMs + seconds * 1000);
  }

  async ttl(key: string) {
    if (!this.exists(key)) {
      return -2;
    }
    const expiresAt = this.expiresAt.get(key);
    if (expiresAt === undefined) {
      return -1;
    }
    return Math.ceil((expiresAt - this.nowMs) / 1000);
  }

  async pttl(key: string) {
    if (!this.exists(key)) {
      return -2;
    }
    const expiresAt = this.expiresAt.get(key);
    if (expiresAt === undefined) {
      return -1;
    }
    return expiresAt - this.nowMs;
  }

  rawString(key: string) {
    return this.strings.get(key);
  }

  private exists(key: string) {
    return this.strings.has(key) || this.sets.has(key);
  }

  private isExpired(key: string) {
    const expiresAt = this.expiresAt.get(key);
    if (expiresAt === undefined || expiresAt > this.nowMs) {
      return false;
    }
    this.strings.delete(key);
    this.sets.delete(key);
    this.expiresAt.delete(key);
    return true;
  }
}

describe("OidcValkeyAdapter", () => {
  it("stores and finds primary payloads with the oidc-provider expiresIn", async () => {
    const client = new FakeValkey();
    const adapter = createOidcValkeyAdapter(client as any)("AccessToken");

    await adapter.upsert("token-1", { clientId: "client-a" }, 123);

    expect(JSON.parse(client.rawString("oidc:AccessToken:token-1")!)).toEqual({
      clientId: "client-a",
    });
    expect(await client.ttl("oidc:AccessToken:token-1")).toBe(123);
    expect(await adapter.find("token-1")).toEqual({ clientId: "client-a" });
  });

  it("resolves session uid and user code indexes", async () => {
    const client = new FakeValkey();
    const sessionAdapter = createOidcValkeyAdapter(client as any)("Session");
    const deviceAdapter = createOidcValkeyAdapter(client as any)("DeviceCode");

    await sessionAdapter.upsert("session-1", { uid: "uid-1" }, 300);
    await deviceAdapter.upsert("device-1", { userCode: "ABCD" }, 120);

    expect(await sessionAdapter.findByUid("uid-1")).toEqual({ uid: "uid-1" });
    expect(await deviceAdapter.findByUserCode("ABCD")).toEqual({
      userCode: "ABCD",
    });
    expect(await client.ttl("oidc:sessionUid:uid-1")).toBe(300);
    expect(await client.ttl("oidc:userCode:ABCD")).toBe(120);
  });

  it("marks consumed payloads and preserves remaining ttl", async () => {
    const client = new FakeValkey();
    const adapter = createOidcValkeyAdapter(client as any)("AuthorizationCode");
    vi.setSystemTime(new Date("2026-06-16T12:00:00Z"));

    await adapter.upsert("code-1", { clientId: "client-a" }, 60);
    client.nowMs += 15_000;

    await adapter.consume("code-1");

    expect(await adapter.find("code-1")).toMatchObject({
      clientId: "client-a",
      consumed: 1781611200,
    });
    expect(await client.pttl("oidc:AuthorizationCode:code-1")).toBe(45_000);

    vi.useRealTimers();
  });

  it("revokes all primary keys indexed by grant id", async () => {
    const client = new FakeValkey();
    const accessTokenAdapter = createOidcValkeyAdapter(client as any)(
      "AccessToken"
    );
    const refreshTokenAdapter = createOidcValkeyAdapter(client as any)(
      "RefreshToken"
    );

    await accessTokenAdapter.upsert("access-1", { grantId: "grant-1" }, 30);
    await refreshTokenAdapter.upsert("refresh-1", { grantId: "grant-1" }, 300);

    await accessTokenAdapter.revokeByGrantId("grant-1");

    expect(await accessTokenAdapter.find("access-1")).toBeUndefined();
    expect(await refreshTokenAdapter.find("refresh-1")).toBeUndefined();
    expect(await client.smembers("oidc:grant:grant-1")).toEqual([]);
  });

});
