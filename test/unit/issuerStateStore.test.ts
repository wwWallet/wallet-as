import { beforeEach, describe, expect, it, vi } from "vitest";

const set = vi.fn();
const get = vi.fn();
const deleteKey = vi.fn();

vi.mock("../../src/config", () => ({
  default: {
    ttl: {
      authorizationCode: 60,
    },
  },
}));

vi.mock("../../src/stores/dataStoreClient", () => ({
  dataStoreClient: {},
}));

vi.mock("../../src/stores/DataStore", () => ({
  DataStore: vi.fn().mockImplementation(function DataStore() {
    return {
      set,
      get,
      delete: deleteKey,
    };
  }),
}));

describe("issuerStateStore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("saves issuer_state with the authorization code ttl", async () => {
    const { saveIssuerStateForAuthorizationCode } = await import(
      "../../src/stores/issuerStateStore"
    );

    await saveIssuerStateForAuthorizationCode("code-1", "issuer-state");

    expect(set).toHaveBeenCalledWith("code-1", "issuer-state", 60_000);
  });

  it("does not save blank or non-string issuer_state values", async () => {
    const { saveIssuerStateForAuthorizationCode } = await import(
      "../../src/stores/issuerStateStore"
    );

    await saveIssuerStateForAuthorizationCode("code-1", "");
    await saveIssuerStateForAuthorizationCode("code-1", undefined);

    expect(set).not.toHaveBeenCalled();
  });

  it("consumes issuer_state and removes the entry", async () => {
    get.mockResolvedValueOnce("issuer-state");
    const { consumeIssuerStateForAuthorizationCode } = await import(
      "../../src/stores/issuerStateStore"
    );

    await expect(
      consumeIssuerStateForAuthorizationCode("code-1")
    ).resolves.toBe("issuer-state");
    expect(get).toHaveBeenCalledWith("code-1");
    expect(deleteKey).toHaveBeenCalledWith("code-1");
  });

  it("returns undefined for invalid authorization code ids", async () => {
    const { consumeIssuerStateForAuthorizationCode } = await import(
      "../../src/stores/issuerStateStore"
    );

    await expect(consumeIssuerStateForAuthorizationCode("")).resolves.toBeUndefined();
    await expect(
      consumeIssuerStateForAuthorizationCode(undefined)
    ).resolves.toBeUndefined();
    expect(get).not.toHaveBeenCalled();
    expect(deleteKey).not.toHaveBeenCalled();
  });
});
