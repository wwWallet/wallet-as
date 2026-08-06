# wwWallet Authorization Server
wwWallet AS is a standalone OIDC/OAuth2 authorization server built around [panva/node-oidc-provider](https://github.com/panva/node-oidc-provider), typically combined with [wwWallet/wallet-issuer](https://github.com/wwWallet/wallet-issuer) for digital credential issuing purposes.

The Authorization Broker flow uses [panva/openid-client](https://github.com/panva/openid-client) as an OIDC client.

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
| `SERVICE_URL` | Full external URL for the AS (scheme/host and optional path prefix). | `http://localhost:6060` if unset. Example: If deployed under `/as`, set it to `https://issuer.example.com/as`. |
| `WALLET_URL` | Redirect URI registered for the wallet client. | `http://localhost:3000` if unset. |
| `OIDC_JWKS_PATH` | Optional override for the OIDC provider signing JWKS path used for ID tokens and JWT authorization responses. | Defaults to `./keys/oidc.jwks.json`|
| `INTROSPECTION_CLIENT` | Client ID allowed to introspect tokens. | If set with `INTROSPECTION_CLIENT_SECRET`, an extra client is registered. |
| `INTROSPECTION_CLIENT_SECRET` | Secret for the introspection client. | Required alongside `INTROSPECTION_CLIENT`. |
| `SCOPES` | Comma-separated list of supported scopes. | Split by `,` and passed to OIDC provider `scopes`. |
| `METADATA_URL` | Credential Issuer metadata URL. | Used during consent to fetch display metadata for requested scopes. |
| `ACCESS_TOKEN_TTL` | Access token TTL (seconds). | Default: `30`|
| `REFRESH_TOKEN_TTL` | Refresh token TTL (seconds). | Default: `2592000` |
| `BASE_PATH` | Optional base path for public, AS/OIDC, and related Express endpoints. | Empty by default. Supports values like `as` or `/as`; normalized to `/as`. |
| `AUTHENTICATOR` | Selected authenticator to load (single value). | Supported values: `user-pass-pid` or `auth-broker`. Defaults to `user-pass-pid` if unset. |
| `USER_PASS_PID_DEMO_USERNAME` | Demo username for the `user-pass-pid` login screen and demo account. | Used only when `AUTHENTICATOR=user-pass-pid`. |
| `USER_PASS_PID_DEMO_PASSWORD` | Demo password shown in `user-pass-pid` login form. | Used only for prefill; authentication does not check password. |
| `AUTH_BROKER_PROVIDER_URL` | External OIDC provider URL for the `auth-broker` authenticator. | Required when `auth-broker` is enabled. |
| `AUTH_BROKER_CLIENT_ID` | OIDC client ID for the `auth-broker` authenticator. | Required when `auth-broker` is enabled. |
| `AUTH_BROKER_CLIENT_SECRET` | OIDC client secret for the `auth-broker` authenticator. | Optional for public clients. |
| `AUTH_BROKER_SCOPE` | Space-separated scopes sent to external IdP authorize endpoint by `auth-broker`. | Default: `openid profile email`. |
| `AUTH_BROKER_REDIRECT_URI` | Redirect URI handled by wallet-as auth-broker callback route. | Default: `SERVICE_URL + /interaction/authBroker/callback`. |
| `AUTH_BROKER_SKIP_LOGOUT` | Skip external IdP logout even if IdP supports it in metadata in `auth-broker` callback flow. | Optional; set to `true` when logout should be skipped. |
| `CLIENT_ATTESTATION_SIGNING_ALGS` | Comma-separated allowlist for Wallet Instance Attestation JWT signatures. | Defaults to `ES256`; only algorithms explicitly supported by wallet-as are accepted. |
| `CLIENT_ATTESTATION_POP_SIGNING_ALGS` | Comma-separated allowlist for Client Attestation PoP JWT signatures. | Defaults to `ES256`; only algorithms explicitly supported by wallet-as are accepted. |
| `CLIENT_ATTESTATION_POP_MAX_AGE` | Maximum accepted Client Attestation PoP age in seconds. | Defaults to `300`. |
| `CLIENT_ATTESTATION_MAX_AGE` | Maximum accepted Wallet Instance Attestation age in seconds. | Defaults to `86400`. |
| `CLIENT_ATTESTATION_CLOCK_TOLERANCE` | Clock tolerance applied to attestation freshness checks, in seconds. | Defaults to `60`. |
| `CLIENT_ATTESTATION_TRUST_ANCHORS_DIR` | Directory containing PEM-encoded Wallet Provider trust anchors used to validate attestation `x5c` chains. | Defaults to `./certs`; use a dedicated trust store in production. |

### Wallet Provider trust anchors

Client attestations must contain an `x5c` JOSE header whose leaf certificate signs the attestation. Wallet Provider trust anchors are loaded from PEM files in `CLIENT_ATTESTATION_TRUST_ANCHORS_DIR`. The complete presented chain must validate to one of these anchors before wallet-as uses the leaf public key to verify the attestation JWT.

Only Wallet Provider trust anchors should be placed in this directory in production. Populate it from the applicable EUDI Wallet Provider Trusted List; do not add untrusted leaf certificates or use the certificate asserted by a client as its own trust anchor.

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
