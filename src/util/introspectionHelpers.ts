import * as oidc from "oidc-provider";

export async function introspectionAllowedPolicy(
  ctx: oidc.KoaContextWithOIDC,
  client: oidc.Client,
  token: oidc.AccessToken | oidc.ClientCredentials | oidc.RefreshToken,
) {
  if (client.clientAuthMethod !== "client_secret_basic") {
    return false;
  }
  if (token.clientId !== ctx?.oidc?.client?.clientId) {
    return false;
  }
  return true;
}
