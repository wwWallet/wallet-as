import * as oidc from "oidc-provider";
import config from "../config";

export function introspectionAllowedPolicy(
  ctx: oidc.KoaContextWithOIDC,
  client: oidc.Client,
  token: oidc.AccessToken | oidc.ClientCredentials | oidc.RefreshToken,
) {
  if (client.clientAuthMethod !== "client_secret_basic") {
    return false;
  }
  if ((token.clientId !== client?.clientId) && (client?.clientId !== config?.introspectionClient)) {
    return false;
  }
  return true;
}
