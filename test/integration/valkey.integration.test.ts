import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { GenericContainer, StartedTestContainer } from "testcontainers";
import Valkey from "iovalkey";
import { DataStore } from "../../src/stores/DataStore";

describe("Valkey integration (real container)", () => {
  let container: StartedTestContainer;
  let client: Valkey;
  let store: DataStore<any>;

  beforeAll(async () => {
    container = await new GenericContainer("valkey/valkey:latest")
      .withExposedPorts(6379)
      .start();

    const host = container.getHost();
    const port = container.getMappedPort(6379);

    client = new Valkey({
      host,
      port,
    });

    store = new DataStore(client, "test");
  }, 60_000);

  afterAll(async () => {
    await client.quit();
    await container.stop();
  });

  it("sets and gets a value", async () => {
    await store.set("user1", { name: "Alice" });

    const result = await store.get("user1");

    expect(result).toEqual({ name: "Alice" });
  });

  it("returns undefined for missing key", async () => {
    const result = await store.get("does-not-exist");

    expect(result).toBeUndefined();
  });

  it("deletes a key", async () => {
    await store.set("temp", 123);

    await store.delete("temp");

    const result = await store.get("temp");

    expect(result).toBeUndefined();
  });

  it("persists multiple values", async () => {
    await store.set("a", 1);
    await store.set("b", 2);

    const a = await store.get("a");
    const b = await store.get("b");

    expect(a).toBe(1);
    expect(b).toBe(2);
  });
});