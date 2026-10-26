import dotenv from 'dotenv';
import fs from 'node:fs';
import path from 'node:path';
import type * as oidc from 'oidc-provider';
import { z } from 'zod';
dotenv.config();

const serviceUrl = process.env.SERVICE_URL || 'http://localhost:6060';
const rawBasePath = process.env.BASE_PATH?.trim() || '';
const basePath = rawBasePath ? `/${rawBasePath.replace(/^\/+|\/+$/g, '')}` : '';
const oidcJwksPath = process.env.OIDC_JWKS_PATH || './keys/oidc.jwks.json';
let oidcJwks: oidc.JWKS | undefined;

try {
  const resolvedOidcJwksPath = path.resolve(process.cwd(), oidcJwksPath);
  if (fs.existsSync(resolvedOidcJwksPath)) {
    const oidcJwksSchema = z.object({
      keys: z.array(z.unknown()).min(1),
    });
    oidcJwks = oidcJwksSchema.parse(
      JSON.parse(fs.readFileSync(resolvedOidcJwksPath, 'utf-8')),
    ) as oidc.JWKS;
  } else if (process.env.NODE_ENV === 'production') {
    console.error(
      `FATAL: OIDC JWKS file not found at '${oidcJwksPath}'. From the repository root, run ./scripts/gen-oidc-jwks.sh or set OIDC_JWKS_PATH.`,
    );
    process.exit(1);
  } else {
    console.warn(
      `OIDC JWKS file not found at '${oidcJwksPath}'. wallet-as will use oidc-provider development signing keys.`,
    );
  }
} catch (err) {
  console.error(`FATAL: Failed to load OIDC JWKS from '${oidcJwksPath}':`, err);
  process.exit(1);
}

const dataStoreHost = process.env.DATA_STORE_HOST || 'localhost';
const dataStorePort = Number(process.env.DATA_STORE_PORT) || 6379;
const dataStorePassword = process.env.DATA_STORE_PASSWORD || null;

if (process.env.NODE_ENV === 'production' && !dataStorePassword) {
  console.error(`FATAL: Insecure data store found in production.`);

  process.exit(1);
}

const certsDir = path.resolve(process.cwd(), './certs');
let trustedRootCertificates: string[] = [];
try {
  if (fs.existsSync(certsDir)) {
    trustedRootCertificates = fs
      .readdirSync(certsDir)
      .filter((file) => file.toLowerCase().endsWith('.pem'))
      .map((file) => fs.readFileSync(path.join(certsDir, file), 'utf-8').toString())
      .filter((pem) => pem.trim().length > 0);
  }
} catch (err) {
  console.warn('Failed to load trusted root certificates:', err);
  trustedRootCertificates = [];
}

const authBrokerProviderUrl =
  process.env.AUTH_BROKER_PROVIDER_URL || process.env.AUTH_BROKER_ISSUER || null;
const authBrokerClientId = process.env.AUTH_BROKER_CLIENT_ID || null;
const authBrokerClientSecret = process.env.AUTH_BROKER_CLIENT_SECRET || null;
const authBrokerScope = process.env.AUTH_BROKER_SCOPE || 'openid';
const authBrokerRedirectUri =
  process.env.AUTH_BROKER_REDIRECT_URI || `${serviceUrl}/interaction/authBroker/callback`;
const authBrokerSkipLogout = process.env.AUTH_BROKER_SKIP_LOGOUT === 'true';
const authenticator = process.env.AUTHENTICATOR?.trim() || 'user-pass-pid';
const authBrokerConfigured = Boolean(authBrokerProviderUrl && authBrokerClientId);
const authBrokerRequestStoreTtlMs = Number(
  process.env.AUTH_BROKER_REQUEST_STORE_TTL_MS || 10 * 60 * 1000,
);
const preAuthorizedConsentClientIds = (
  process.env.PRE_AUTHORIZED_CONSENT_CLIENT_IDS || 'wallet_issuer'
)
  .split(',')
  .map((clientId) => clientId.trim())
  .filter(Boolean);

const clientMetadataSchema = z.looseObject({
  client_id: z.string().trim().min(1),
  client_secret: z.string().optional(),
  redirect_uris: z.array(z.string()).min(1),
  token_endpoint_auth_method: z.string().optional(),
  grant_types: z.array(z.string()).optional(),
  post_logout_redirect_uris: z.array(z.string()).optional(),
  logo_uri: z.string().optional(),
});

const clientsSchema = z.array(clientMetadataSchema);

function loadOAuth2Clients(): oidc.ClientMetadata[] {
  const clientsFile = path.join(process.cwd(), 'src/config/oauth2clients.json');

  let parsed: unknown;
  try {
    parsed = JSON.parse(fs.readFileSync(clientsFile, 'utf-8'));
  } catch (err) {
    throw new Error(`Failed to parse OAuth2 clients file '${clientsFile}': ${err}`);
  }

  return clientsSchema.parse(parsed) as oidc.ClientMetadata[];
}

const abcaChallengeSecretHex = process.env.ABCA_CHALLENGE_SECRET;
if (
  !abcaChallengeSecretHex ||
  abcaChallengeSecretHex.length !== 64 ||
  !/^[0-9a-fA-F]{64}$/.test(abcaChallengeSecretHex)
) {
  throw new Error(
    'ABCA_CHALLENGE_SECRET must contain exactly 64 hexadecimal characters (32 bytes).',
  );
}
const abcaChallengeSecret = Buffer.from(abcaChallengeSecretHex, 'hex');
const openid4vcProfile = z
  .enum(['DEFAULT', 'WEBUILD'])
  .default('DEFAULT')
  .parse(process.env.OPENID4VC_PROFILE);
const weBuildAbcaStatusListAllowedOrigins = (
  process.env.WEBUILD_ABCA_STATUS_LIST_ALLOWED_ORIGINS || ''
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);
if (openid4vcProfile === 'WEBUILD' && weBuildAbcaStatusListAllowedOrigins.length === 0) {
  throw new Error(
    'WEBUILD_ABCA_STATUS_LIST_ALLOWED_ORIGINS is required when OPENID4VC_PROFILE=WEBUILD.',
  );
}

export default {
  serviceUrl: serviceUrl,
  basePath: basePath,
  walletUrl: process.env.WALLET_URL || 'http://localhost:3000',
  oidcJwks: oidcJwks,
  dataStoreHost: dataStoreHost,
  dataStorePort: dataStorePort,
  dataStorePassword: dataStorePassword,
  oidClients: loadOAuth2Clients(),
  introspectionClient: process.env.INTROSPECTION_CLIENT || null,
  introspectionClientSecret: process.env.INTROSPECTION_CLIENT_SECRET || null,
  scopes: process.env.SCOPES ? process.env.SCOPES.split(',') : ['openid'],
  ttl: {
    accessToken: Number(process.env.ACCESS_TOKEN_TTL) || 30,
    refreshToken: Number(process.env.REFRESH_TOKEN_TTL) || 2592000,
    authorizationCode: Number(process.env.AUTHORIZATION_CODE_TTL) || 60,
    clientAttestation: Number(process.env.ABCA_CLIENT_ATTESTATION_MAX_AGE) || 86400,
    clientAttestationPoP: Number(process.env.ABCA_CLIENT_ATTESTATION_POP_MAX_AGE) || 60,
  },
  demoUsername: process.env.USER_PASS_PID_DEMO_USERNAME || null,
  demoPassword: process.env.USER_PASS_PID_DEMO_PASSWORD || null,
  trustedRootCertificates: trustedRootCertificates,
  trustedIssuers: process.env.TRUSTED_ISSUERS
    ? process.env.TRUSTED_ISSUERS.split(',')
    : ['http://localhost:8003/openid'],
  authBrokerProviderUrl: authBrokerProviderUrl,
  authBrokerClientId: authBrokerClientId,
  authBrokerClientSecret: authBrokerClientSecret,
  authBrokerScope: authBrokerScope,
  authBrokerRedirectUri: authBrokerRedirectUri,
  authBrokerSkipLogout: authBrokerSkipLogout,
  authBrokerRequestStoreTtlMs: authBrokerRequestStoreTtlMs,
  authBrokerConfigured: authBrokerConfigured,
  authenticator: authenticator,
  preAuthorizedConsentClientIds: preAuthorizedConsentClientIds,
  preAuthorizedCredentialIssuance:
    process.env.PRE_AUTHORIZED_CREDENTIAL_ISSUANCE === 'true' || false,
  preAuthorizedCodeApiUrl: process.env.PRE_AUTHORIZED_CODE_API_URL || '',
  preAuthorizedCodeApiBearerToken: process.env.PRE_AUTHORIZED_CODE_API_BEARER_TOKEN || '',
  abcaChallengeSecret,
  openid4vcProfile,
  weBuildAbcaStatusListAllowedOrigins,
};
