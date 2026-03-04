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
| `AUTHENTICATOR` | Selected authenticator to load (single value). | Supported values: `user-pass-pid` or `auth-broker`. |
| `USER_PASS_PID_DEMO_USERNAME` | Demo username for the `user-pass-pid` login screen and demo account. | Used only when `AUTHENTICATOR=user-pass-pid`. |
| `USER_PASS_PID_DEMO_PASSWORD` | Demo password shown in `user-pass-pid` login form. | Used only for prefill; authentication does not check password. |
| `AUTH_BROKER_PROVIDER_URL` | External OIDC provider URL for the `auth-broker` authenticator. | Required when `auth-broker` is enabled. |
| `AUTH_BROKER_CLIENT_ID` | OIDC client ID for the `auth-broker` authenticator. | Required when `auth-broker` is enabled. |
| `AUTH_BROKER_CLIENT_SECRET` | OIDC client secret for the `auth-broker` authenticator. | Optional for public clients. |
| `AUTH_BROKER_SCOPE` | Space-separated scopes sent to external IdP authorize endpoint by `auth-broker`. | Default: `openid profile email`. |
| `AUTH_BROKER_REDIRECT_URI` | Redirect URI handled by wallet-as auth-broker callback route. | Default: `http://localhost:6060/as/interaction/authBroker/callback`. |

## Authenticators
`wallet-as` supports explicit authenticator loading at startup.

- Authenticator modules live in `src/authenticators/*`.
- Active authenticator is loaded from `AUTHENTICATOR` in `src/authenticators/index.ts`.
- Built-in authenticators are `user-pass-pid` (login form or PID presentation) and `auth-broker` (external OIDC IdP broker flow).

### Authenticator hooks
Authenticators implement the `Authenticator` interface from `src/authenticators/types.ts`:

- `getLoginInteractionUrl(interaction)`: Resolve login interaction URL for this authenticator.
- `registerRoutes(app, provider, accountSource)`: Register authenticator-owned routes.
- `shouldAutoApproveConsent(interaction)`: Optional consent skipping.

## Contributor Guide: Adding an Authenticator
1. Create a module under `src/authenticators/<your-authenticator>/`.
2. Export a factory returning `Authenticator`.
3. Implement route registration and hooks needed by your flow.
4. Register the factory in `src/authenticators/index.ts`.
5. Add your authenticator ID to `AUTHENTICATOR` documentation and `.env.template`.
6. Keep authenticator-specific logic outside core routes unless adding a generic hook.
