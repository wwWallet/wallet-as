import * as oidc from 'oidc-provider';
import { createHash } from 'node:crypto';
import { dataStoreClient } from '../stores/dataStoreClient';

const KEY_PREFIX = 'wiaIssuanceProcess:';

const RESERVE_SCRIPT = `
local current = redis.call('GET', KEYS[1])
local route = ARGV[1]
local core = ARGV[2]
local fingerprint = ARGV[3]
local grant = ARGV[4]
local ttl = ARGV[5]
if route == 'par' then
  local desired = 'p|' .. core .. '|' .. fingerprint .. '|'
  if not current then
    redis.call('SET', KEYS[1], desired, 'EX', ttl, 'NX')
    return 1
  end
  if current == desired then return 1 end
  return 0
end
if not current then
  local desired = 't|' .. core .. '||' .. fingerprint
  redis.call('SET', KEYS[1], desired, 'EX', ttl, 'NX')
  return 1
end
local mode, savedCore, parFingerprint, tokenFingerprint = string.match(current, '^([^|]+)|([^|]+)|([^|]*)|([^|]*)$')
if savedCore ~= core then return 0 end
if mode == 't' then
  if tokenFingerprint == fingerprint then return 1 end
  if grant == 'refresh_token' then return 1 end
  return 0
end
if mode == 'p' then
  if grant ~= 'authorization_code' then return 0 end
  redis.call('SET', KEYS[1], 'pt|' .. core .. '|' .. parFingerprint .. '|' .. fingerprint, 'KEEPTTL')
  return 1
end
if mode == 'pt' and (tokenFingerprint == fingerprint or grant == 'refresh_token') then return 1 end
return 0
`;

export function requestFingerprint(ctx: oidc.KoaContextWithOIDC): string {
  const requestBody = (ctx.request as { body?: Record<string, unknown> } | undefined)?.body
    ?? (ctx.req as typeof ctx.req & { body?: Record<string, unknown> } | undefined)?.body
    ?? {};
  const params = { ...requestBody, ...(ctx.oidc.params ?? {}) } as Record<string, unknown>;
  const normalized = Object.entries(params)
    .filter(([key, value]) => !['client_attestation', 'client_attestation_pop'].includes(key) && ['string', 'number', 'boolean'].includes(typeof value))
    .sort(([left], [right]) => left.localeCompare(right));
  return createHash('sha256').update(JSON.stringify(normalized)).digest('hex');
}

export async function enforceWalletInstanceAttestationUse(
  ctx: oidc.KoaContextWithOIDC,
  payload: oidc.UnknownObject,
  confirmationKeyThumbprint: string,
): Promise<void> {
  if (typeof payload.jti !== 'string' || typeof payload.exp !== 'number') {
    throw new oidc.errors.InvalidClientAttestation('client attestation lifecycle identifier is invalid');
  }
  const ttlSeconds = Math.max(1, Math.floor(payload.exp) - Math.floor(Date.now() / 1000));
  const key = `${KEY_PREFIX}${payload.jti}`;
  const binding = createHash('sha256').update(JSON.stringify({
    confirmationKeyThumbprint,
    subject: payload.sub,
  })).digest('hex');
  const route = ctx.oidc.route === 'pushed_authorization_request' ? 'par' : 'token';
  const requestBody = (ctx.request as { body?: Record<string, unknown> } | undefined)?.body
    ?? (ctx.req as typeof ctx.req & { body?: Record<string, unknown> } | undefined)?.body;
  const grantType = ctx.oidc.params?.grant_type ?? requestBody?.grant_type;
  const reserved = await dataStoreClient.eval(
    RESERVE_SCRIPT,
    1,
    key,
    route,
    binding,
    requestFingerprint(ctx),
    typeof grantType === 'string' ? grantType : '',
    ttlSeconds.toString(),
  );
  if (reserved !== 1) {
    throw new oidc.errors.InvalidClientAttestation('client attestation is already bound to another issuance process');
  }
}
