import dotenv from 'dotenv';
dotenv.config();

export default {
  serviceUrl: process.env.SERVICE_URL || "http://localhost:6060/as",
  walletUrl: process.env.WALLET_URL || "http://localhost:3000",
  introspectionClient: process.env.INTROSPECTION_CLIENT || null,
  introspectionClientSecret: process.env.INTROSPECTION_CLIENT_SECRET || null,
  scopes: process.env.SCOPES ? process.env.SCOPES.split(',') : ["openid"],
  ttl: {
    accessToken: process.env.ACCESS_TOKEN_TTL || 30,
    refreshToken: process.env.REFRESH_TOKEN_TTL || 2592000
  }
}
