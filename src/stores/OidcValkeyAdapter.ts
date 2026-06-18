import type Valkey from "iovalkey";
import type * as oidc from "oidc-provider";

const GRANTABLE_MODELS = new Set([
  "AccessToken",
  "AuthorizationCode",
  "RefreshToken",
  "DeviceCode",
  "BackchannelAuthenticationRequest",
]);

const epochTime = () => Math.floor(Date.now() / 1000);

export function createOidcValkeyAdapter(client: Valkey): oidc.AdapterFactory {
  return (modelName: string) => new OidcValkeyAdapter(client, modelName);
}

class OidcValkeyAdapter implements oidc.Adapter {
  constructor(
    private readonly client: Valkey,
    private readonly modelName: string
  ) {}

  async upsert(
    id: string,
    payload: oidc.AdapterPayload,
    expiresIn: number
  ): Promise<void> {
    const primaryKey = this.primaryKey(id);

    await this.client.set(primaryKey, JSON.stringify(payload), "EX", expiresIn);

    if (this.modelName === "Session" && typeof payload.uid === "string") {
      await this.client.set(this.sessionUidKey(payload.uid), id, "EX", expiresIn);
    }

    if (typeof payload.userCode === "string") {
      await this.client.set(
        this.userCodeKey(payload.userCode),
        id,
        "EX",
        expiresIn
      );
    }

    if (
      GRANTABLE_MODELS.has(this.modelName) &&
      typeof payload.grantId === "string"
    ) {
      const grantKey = this.grantKey(payload.grantId);
      await this.client.sadd(grantKey, primaryKey);
      await this.extendTtl(grantKey, expiresIn);
    }
  }

  async find(id: string): Promise<oidc.AdapterPayload | undefined> {
    const stored = await this.client.get(this.primaryKey(id));
    if (!stored) {
      return undefined;
    }

    try {
      return JSON.parse(stored) as oidc.AdapterPayload;
    } catch {
      return undefined;
    }
  }

  async findByUid(uid: string): Promise<oidc.AdapterPayload | undefined> {
    const id = await this.client.get(this.sessionUidKey(uid));
    return id ? this.find(id) : undefined;
  }

  async findByUserCode(
    userCode: string
  ): Promise<oidc.AdapterPayload | undefined> {
    const id = await this.client.get(this.userCodeKey(userCode));
    return id ? this.find(id) : undefined;
  }

  async consume(id: string): Promise<void> {
    const key = this.primaryKey(id);
    const stored = await this.find(id);
    if (!stored) {
      return;
    }

    const ttlMs = await this.client.pttl(key);
    const consumed = {
      ...stored,
      consumed: epochTime(),
    };

    if (ttlMs > 0) {
      await this.client.set(key, JSON.stringify(consumed), "PX", ttlMs);
      return;
    }

    if (ttlMs === -1) {
      await this.client.set(key, JSON.stringify(consumed));
    }
  }

  async destroy(id: string): Promise<void> {
    const stored = await this.find(id);
    const primaryKey = this.primaryKey(id);

    await this.client.del(primaryKey);

    if (!stored) {
      return;
    }

    if (this.modelName === "Session" && typeof stored.uid === "string") {
      await this.client.del(this.sessionUidKey(stored.uid));
    }

    if (typeof stored.userCode === "string") {
      await this.client.del(this.userCodeKey(stored.userCode));
    }

    if (
      GRANTABLE_MODELS.has(this.modelName) &&
      typeof stored.grantId === "string"
    ) {
      await this.client.srem(this.grantKey(stored.grantId), primaryKey);
    }
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    const grantKey = this.grantKey(grantId);
    const keys = await this.client.smembers(grantKey);

    if (keys.length > 0) {
      await this.client.del(...keys);
    }

    await this.client.del(grantKey);
  }

  private primaryKey(id: string): string {
    return `oidc:${this.modelName}:${id}`;
  }

  private sessionUidKey(uid: string): string {
    return `oidc:sessionUid:${uid}`;
  }

  private userCodeKey(userCode: string): string {
    return `oidc:userCode:${userCode}`;
  }

  private grantKey(grantId: string): string {
    return `oidc:grant:${grantId}`;
  }

  private async extendTtl(key: string, expiresIn: number): Promise<void> {
    const currentTtl = await this.client.ttl(key);

    if (currentTtl < expiresIn) {
      await this.client.expire(key, expiresIn);
    }
  }
}
