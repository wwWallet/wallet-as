import type {
  AuthorizationCode,
  BackchannelAuthenticationRequest,
  Client,
  DeviceCode,
  KoaContextWithOIDC,
  PreAuthorizedCode,
} from 'oidc-provider';

export async function issueRefreshToken(
  _ctx: KoaContextWithOIDC,
  _client: Client,
  _code: AuthorizationCode | DeviceCode | BackchannelAuthenticationRequest | PreAuthorizedCode,
) {
  return true;
}
