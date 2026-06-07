import Valkey from "iovalkey";
import config from "../config";

export const dataStoreClient = new Valkey({
  host: config.dataStoreHost,
  port: config.dataStorePort
});
