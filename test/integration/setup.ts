import { GenericContainer, StartedTestContainer } from "testcontainers";

let valkeyContainer: StartedTestContainer;

const VALKEY_PORT = 6379;
const VALKEY_PASSWORD = "test-secret";

export default async function setup() {
  valkeyContainer = await new GenericContainer("valkey/valkey:latest")
    .withExposedPorts(VALKEY_PORT)
    .withCommand([
        "valkey-server",
        "--requirepass",
        VALKEY_PASSWORD
    ])
    .start();

  process.env.DATA_STORE_HOST = valkeyContainer.getHost();
  process.env.DATA_STORE_PORT = String(
    valkeyContainer.getMappedPort(VALKEY_PORT)
  );
  process.env.DATA_STORE_PASSWORD=VALKEY_PASSWORD;

  console.log(
    `Valkey started on ${process.env.VALKEY_HOST}:${process.env.VALKEY_PORT}`
  );

  return async () => {
    await valkeyContainer.stop();
  };
}