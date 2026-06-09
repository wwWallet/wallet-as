import { describe, it, expect, vi, beforeEach } from "vitest";
import { DataStore } from "../../src/stores/DataStore";

const mockClient = {
  get: vi.fn(),
  set: vi.fn(),
  del: vi.fn(),
  smembers: vi.fn(),
  mget: vi.fn(),
  multi: vi.fn(),
};

mockClient.multi.mockReturnValue({
  set: vi.fn().mockReturnThis(),
  sadd: vi.fn().mockReturnThis(),
  del: vi.fn().mockReturnThis(),
  srem: vi.fn().mockReturnThis(),
  exec: vi.fn(),
});

describe("DataStore (unit)", () => {
  let store: DataStore<any>;

  beforeEach(() => {
    vi.clearAllMocks();

    store = new DataStore<any>(
      mockClient as any,
      "test"
    );

  });

  it("builds prefixed keys correctly", async () => {
    mockClient.get.mockResolvedValueOnce(null);

    await store.get("abc");

    expect(mockClient.get).toHaveBeenCalledWith("test:abc");
  });

  it("sets serialized value", async () => {
    await store.set("a", { x: 1 });

    expect(mockClient.set).toHaveBeenCalledWith(
      "test:a",
      JSON.stringify({ x: 1 })
    );
  });

  it("gets and deserializes value", async () => {
    mockClient.get.mockResolvedValueOnce(JSON.stringify({ x: 1 }));

    const result = await store.get("a");

    expect(result).toEqual({ x: 1 });
  });

  it("returns undefined when missing", async () => {
    mockClient.get.mockResolvedValueOnce(null);

    const result = await store.get("missing");

    expect(result).toBeUndefined();
  });

  it("deletes keys", async () => {
    await store.delete("a");

    expect(mockClient.del).toHaveBeenCalledWith("test:a");
  });
});