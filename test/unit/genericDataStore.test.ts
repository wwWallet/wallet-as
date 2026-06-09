import { beforeEach, describe, expect, it, vi } from "vitest";
import { GenericDataStore } from "../../src/stores/GenericDataStore";

const mockMulti = {
  set: vi.fn().mockReturnThis(),
  sadd: vi.fn().mockReturnThis(),
  del: vi.fn().mockReturnThis(),
  srem: vi.fn().mockReturnThis(),
  exec: vi.fn().mockResolvedValue([]),
};

const mockClient = {
  get: vi.fn(),
  smembers: vi.fn(),
  mget: vi.fn(),
  multi: vi.fn(() => mockMulti),
};

describe("GenericDataStore", () => {
  let store: GenericDataStore<string, any>;

  beforeEach(() => {
    vi.clearAllMocks();

    store = new GenericDataStore<string, any>(
      mockClient as any,
      "test"
    );
  });

  describe("get", () => {
    it("returns undefined when key does not exist", async () => {
      mockClient.get.mockResolvedValueOnce(null);

      const result = await store.get("abc");

      expect(result).toBeUndefined();
      expect(mockClient.get).toHaveBeenCalledWith("test:\"abc\"");
    });

    it("deserializes stored values", async () => {
      mockClient.get.mockResolvedValueOnce(
        JSON.stringify({ name: "Alice" })
      );

      const result = await store.get("abc");

      expect(result).toEqual({
        name: "Alice",
      });
    });

    it("uses prefixed key", async () => {
      mockClient.get.mockResolvedValueOnce(null);

      await store.get("abc");

      expect(mockClient.get).toHaveBeenCalledWith(
        "test:\"abc\""
      );
    });
  });

  describe("set", () => {
    it("stores value without TTL", async () => {
      await store.set("abc", {
        foo: "bar",
      });

      expect(mockClient.multi).toHaveBeenCalled();

      expect(mockMulti.set).toHaveBeenCalledWith(
        "test:\"abc\"",
        JSON.stringify({
          foo: "bar",
        })
      );

      expect(mockMulti.sadd).toHaveBeenCalledWith(
        "test:__keys",
        "test:\"abc\""
      );

      expect(mockMulti.exec).toHaveBeenCalled();
    });

    it("stores value with TTL", async () => {
      await store.set(
        "abc",
        {
          foo: "bar",
        },
        60_000
      );

      expect(mockMulti.set).toHaveBeenCalledWith(
        "test:\"abc\"",
        JSON.stringify({
          foo: "bar",
        }),
        "PX",
        60_000
      );

      expect(mockMulti.sadd).toHaveBeenCalledWith(
        "test:__keys",
        "test:\"abc\""
      );

      expect(mockMulti.exec).toHaveBeenCalled();
    });

    it("supports TTL of zero if explicitly provided", async () => {
      await store.set(
        "abc",
        {
          foo: "bar",
        },
        0
      );

      expect(mockMulti.set).toHaveBeenCalledWith(
        "test:\"abc\"",
        JSON.stringify({
          foo: "bar",
        }),
        "PX",
        0
      );
    });
  });

  describe("delete", () => {
    it("removes key and index entry", async () => {
      await store.delete("abc");

      expect(mockMulti.del).toHaveBeenCalledWith(
        "test:\"abc\""
      );

      expect(mockMulti.srem).toHaveBeenCalledWith(
        "test:__keys",
        "test:\"abc\""
      );

      expect(mockMulti.exec).toHaveBeenCalled();
    });
  });

  describe("getAll", () => {
    it("returns empty array when index is empty", async () => {
      mockClient.smembers.mockResolvedValueOnce([]);

      const result = await store.getAll();

      expect(result).toEqual([]);
      expect(mockClient.mget).not.toHaveBeenCalled();
    });

    it("returns all deserialized values", async () => {
      mockClient.smembers.mockResolvedValueOnce([
        "test:\"a\"",
        "test:\"b\"",
      ]);

      mockClient.mget.mockResolvedValueOnce([
        JSON.stringify({ id: 1 }),
        JSON.stringify({ id: 2 }),
      ]);

      const result = await store.getAll();

      expect(mockClient.mget).toHaveBeenCalledWith(
        "test:\"a\"",
        "test:\"b\""
      );

      expect(result).toEqual([
        { id: 1 },
        { id: 2 },
      ]);
    });

    it("filters out missing values", async () => {
      mockClient.smembers.mockResolvedValueOnce([
        "test:\"a\"",
        "test:\"b\"",
      ]);

      mockClient.mget.mockResolvedValueOnce([
        JSON.stringify({ id: 1 }),
        null,
      ]);

      const result = await store.getAll();

      expect(result).toEqual([
        { id: 1 },
      ]);
    });
  });
});