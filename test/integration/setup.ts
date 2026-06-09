import { GenericContainer, StartedTestContainer } from "testcontainers";

let valkeyContainer: StartedTestContainer;

export default async function setup() {
  valkeyContainer = await new GenericContainer("valkey/valkey:latest")
    .withExposedPorts(6379)
    .start();

  process.env.VALKEY_HOST = valkeyContainer.getHost();
  process.env.VALKEY_PORT = String(
    valkeyContainer.getMappedPort(6379)
  );

  console.log(
    `Valkey started on ${process.env.VALKEY_HOST}:${process.env.VALKEY_PORT}`
  );

  return async () => {
    await valkeyContainer.stop();
  };
}