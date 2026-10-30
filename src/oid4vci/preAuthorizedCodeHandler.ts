import { calculateJwkThumbprint, type JWK } from 'jose';
import { errors, type TokenEndpointGrantContext } from 'oidc-provider';
import {
  consumePreAuthorizedCode,
  type PreAuthorizedCodeStoreItem,
} from '../services/preAuthorizedCodeService';

type PreAuthorizedCodeGrantParams = {
  'pre-authorized_code': string;
  tx_code?: string | number;
};

export default async function preAuthorizedCodeHandler(
  ctx: TokenEndpointGrantContext<PreAuthorizedCodeGrantParams>,
) {
  const { provider, params } = ctx.oidc;

  const pre_authorized_code = params['pre-authorized_code'];
  const tx_code = params['tx_code'];

  const grant = await consumePreAuthorizedCode(pre_authorized_code, tx_code);

  if ('error' in grant && grant.error) {
    console.log(`Error consuming pre-authorized code: ${grant.error_description}`);
    throw new errors.InvalidRequest(grant.error);
  }
  const consumedGrant = grant as PreAuthorizedCodeStoreItem;

  validatePreAuthorizedCodeGrant(consumedGrant, tx_code);

  const client = await provider.Client.find('__pre-authorized_code_client__');
  if (!client) {
    throw new errors.InvalidClient('Could not find pre-authorized_code client');
  }

  const scope = consumedGrant.scope;
  if (!scope) {
    throw new errors.InvalidGrant('Could not resolve scope from grant.');
  }

  const accountId = consumedGrant.account_id;
  if (!accountId) {
    throw new errors.AccessDenied('invalid account_id');
  }

  const token = new provider.AccessToken({
    accountId,
    client,
    scope,
    gty: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
  } as ConstructorParameters<typeof provider.AccessToken>[0]);

  const { jwk } = decodeHeader(ctx.request.header.dpop as string);
  const jkt = await calculateJwkThumbprint(jwk);
  token.setThumbprint('jkt', jkt);

  const accessToken = await token.save();

  const rt = new provider.RefreshToken({
    accountId,
    client,
    scope,
  } as ConstructorParameters<typeof provider.RefreshToken>[0]);

  const refreshToken = await rt.save();

  ctx.body = {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: token.expiration,
    refresh_token: refreshToken,
  };
}

function decodeHeader(jwt: string): { jwk: JWK } {
  const [header] = jwt.split('.');
  return JSON.parse(Buffer.from(header, 'base64url').toString('utf8')) as { jwk: JWK };
}

async function validatePreAuthorizedCodeGrant(
  grant: PreAuthorizedCodeStoreItem,
  txCodeReceived?: string | number,
) {
  if (!grant) {
    throw new errors.InvalidGrant('unknown pre-authorized code');
  }

  const expectedTxCodeStructure = grant?.tx_code;
  const expectedTxCodeValue = grant?.tx_value;
  const expectedExpDateMs = grant?.exp;

  if (expectedExpDateMs && expectedExpDateMs < Date.now()) {
    throw new errors.InvalidGrant('pre-authorized code has expired');
  }

  if (expectedTxCodeStructure) {
    if (!txCodeReceived) {
      throw new errors.InvalidRequest('tx_code required');
    }

    const txCodeValidationResult = String(txCodeReceived) === String(expectedTxCodeValue);

    if (txCodeValidationResult === false) {
      throw new errors.InvalidGrant('invalid tx_code');
    }
  }

  if (!expectedTxCodeStructure && txCodeReceived) {
    throw new errors.InvalidRequest('server does not expect tx_code');
  }
}
