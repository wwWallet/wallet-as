# wwWallet Authorization Server
wwWallet AS is a standalone OIDC/OAuth2 authorization server, typically combined with https://github.com/wwWallet/wallet-issuer for digital credential issuing purposes.

> [!NOTE]
> To quickly setup the **wwWallet** ecosystem see https://github.com/wwWallet/wwwallet

## How to run

Install dependencies
```
yarn install
```

Run in dev mode
```
yarn run dev
```

## Configuration
Configuration is loaded from `.env` (see `.env.template`). Values are read via `dotenv` in `src/config/index.ts`.

Environment variables and how they are used:

| Variable | Purpose | Default / Notes |
| --- | --- | --- |
| `SERVICE_URL` | Base URL for the AS | `http://localhost:6060/as` if unset. |
| `WALLET_URL` | Redirect URI registered for the wallet client. | `http://localhost:3000` if unset. |
| `INTROSPECTION_CLIENT` | Client ID allowed to introspect tokens. | If set with `INTROSPECTION_CLIENT_SECRET`, an extra client is registered. |
| `INTROSPECTION_CLIENT_SECRET` | Secret for the introspection client. | Required alongside `INTROSPECTION_CLIENT`. |
| `SCOPES` | Comma-separated list of supported scopes. | Split by `,` and passed to OIDC provider `scopes`. |
| `METADATA_URL` | Credential Issuer metadata URL. | Used during consent to fetch display metadata for requested scopes. |
| `ACCESS_TOKEN_TTL` | Access token TTL (seconds). | Default: `30`|
| `REFRESH_TOKEN_TTL` | Refresh token TTL (seconds). | Default: `2592000` |
| `DEMO_USERNAME` | Demo username for the login screen and demo account. | Enables demo mode; account is created with this username. |
| `DEMO_PASSWORD` | Demo password shown in the login form. | Only used to prefill the login form; authentication does not check the password. |
