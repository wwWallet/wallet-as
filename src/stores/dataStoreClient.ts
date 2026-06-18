import Valkey, { RedisOptions } from "iovalkey";
import config from "../config";

let valkeyConfigOptions: RedisOptions = {
  host: config.dataStoreHost,
  port: config.dataStorePort
}

if (config.dataStorePassword) {
  valkeyConfigOptions.password = config.dataStorePassword;
}

export const dataStoreClient = new Valkey(valkeyConfigOptions);
