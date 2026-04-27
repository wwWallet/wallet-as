import dotenv from 'dotenv';
import fs from "node:fs";
import path from "node:path";
dotenv.config();

const serviceUrl = process.env.SERVICE_URL || "http://localhost:6060/as";

const certsDir = path.resolve(process.cwd(), "./certs");
let trustedRootCertificates: string[] = [];
try {
  if (fs.existsSync(certsDir)) {
    trustedRootCertificates = fs
      .readdirSync(certsDir)
      .filter((file) => file.toLowerCase().endsWith(".pem"))
      .map((file) => fs.readFileSync(path.join(certsDir, file), "utf-8").toString())
      .filter((pem) => pem.trim().length > 0);
  }
} catch (err) {
  console.warn("Failed to load trusted root certificates:", err);
  trustedRootCertificates = [];
}

const authBrokerProviderUrl =
  process.env.AUTH_BROKER_PROVIDER_URL || process.env.AUTH_BROKER_ISSUER || null;
const authBrokerClientId = process.env.AUTH_BROKER_CLIENT_ID || null;
const authBrokerClientSecret = process.env.AUTH_BROKER_CLIENT_SECRET || null;
const authBrokerScope = process.env.AUTH_BROKER_SCOPE || "openid";
const authBrokerRedirectUri =
  process.env.AUTH_BROKER_REDIRECT_URI ||
  `${serviceUrl}/interaction/authBroker/callback`;
const authBrokerSkipLogout =
  process.env.AUTH_BROKER_SKIP_LOGOUT === "true";
const authenticator = process.env.AUTHENTICATOR?.trim() || "user-pass-pid";
const authBrokerConfigured = Boolean(authBrokerProviderUrl && authBrokerClientId);

export default {
  serviceUrl: serviceUrl,
  walletUrl: process.env.WALLET_URL || "http://localhost:3000",
  introspectionClient: process.env.INTROSPECTION_CLIENT || null,
  introspectionClientSecret: process.env.INTROSPECTION_CLIENT_SECRET || null,
  scopes: process.env.SCOPES ? process.env.SCOPES.split(',') : ["openid"],
  ttl: {
    accessToken: Number(process.env.ACCESS_TOKEN_TTL) || 30,
    refreshToken: Number(process.env.REFRESH_TOKEN_TTL) || 2592000
  },
  demoUsername: process.env.USER_PASS_PID_DEMO_USERNAME || null,
  demoPassword: process.env.USER_PASS_PID_DEMO_PASSWORD || null,
  trustedRootCertificates: trustedRootCertificates,
  trustedIssuers: process.env.TRUSTED_ISSUERS
		? process.env.TRUSTED_ISSUERS.split(',')
		: ["http://localhost:8003/openid"],
  authBrokerProviderUrl: authBrokerProviderUrl,
  authBrokerClientId: authBrokerClientId,
  authBrokerClientSecret: authBrokerClientSecret,
  authBrokerScope: authBrokerScope,
  authBrokerRedirectUri: authBrokerRedirectUri,
  authBrokerSkipLogout: authBrokerSkipLogout,
  authBrokerConfigured: authBrokerConfigured,
  authenticator: authenticator,
}
