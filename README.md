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

| Variable                                   | Purpose                                                                                                       | Default / Notes                                                                                                      |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `OPENID4VC_PROFILE`                        | Selects the ecosystem profile across wallet-as.                                                               | `DEFAULT` if unset. Supported values: `DEFAULT`, `WEBUILD`; see profiles below.                                      |
| `SERVICE_URL`                              | Full external URL for the AS (scheme/host and optional path prefix).                                          | `http://localhost:6060` if unset. Example: If deployed under `/as`, set it to `https://issuer.example.com/as`.       |
| `WALLET_URL`                               | Redirect URI registered for the wallet client.                                                                | `http://localhost:3000` if unset.                                                                                    |
| `OIDC_JWKS_PATH`                           | Optional override for the OIDC provider signing JWKS path used for ID tokens and JWT authorization responses. | Defaults to `./keys/oidc.jwks.json`                                                                                  |
| `INTROSPECTION_CLIENT`                     | Client ID allowed to introspect tokens.                                                                       | If set with `INTROSPECTION_CLIENT_SECRET`, an extra client is registered.                                            |
| `INTROSPECTION_CLIENT_SECRET`              | Secret for the introspection client.                                                                          | Required alongside `INTROSPECTION_CLIENT`.                                                                           |
| `SCOPES`                                   | Comma-separated list of supported scopes.                                                                     | Split by `,` and passed to OIDC provider `scopes`.                                                                   |
| `METADATA_URL`                             | Credential Issuer metadata URL.                                                                               | Used during consent to fetch display metadata for requested scopes.                                                  |
| `ACCESS_TOKEN_TTL`                         | Access token TTL (seconds).                                                                                   | Default: `30`                                                                                                        |
| `REFRESH_TOKEN_TTL`                        | Refresh token TTL (seconds).                                                                                  | Default: `2592000`                                                                                                   |
| `BASE_PATH`                                | Optional base path for public, AS/OIDC, and related Express endpoints.                                        | Empty by default. Supports values like `as` or `/as`; normalized to `/as`.                                           |
| `AUTHENTICATOR`                            | Selected authenticator to load (single value).                                                                | Supported values: `user-pass-pid` or `auth-broker`. Defaults to `user-pass-pid` if unset.                            |
| `USER_PASS_PID_DEMO_USERNAME`              | Demo username for the `user-pass-pid` login screen and demo account.                                          | Used only when `AUTHENTICATOR=user-pass-pid`.                                                                        |
| `USER_PASS_PID_DEMO_PASSWORD`              | Demo password shown in `user-pass-pid` login form.                                                            | Used only for prefill; authentication does not check password.                                                       |
| `AUTH_BROKER_PROVIDER_URL`                 | External OIDC provider URL for the `auth-broker` authenticator.                                               | Required when `auth-broker` is enabled.                                                                              |
| `AUTH_BROKER_CLIENT_ID`                    | OIDC client ID for the `auth-broker` authenticator.                                                           | Required when `auth-broker` is enabled.                                                                              |
| `AUTH_BROKER_CLIENT_SECRET`                | OIDC client secret for the `auth-broker` authenticator.                                                       | Optional for public clients.                                                                                         |
| `AUTH_BROKER_SCOPE`                        | Space-separated scopes sent to external IdP authorize endpoint by `auth-broker`.                              | Default: `openid profile email`.                                                                                     |
| `AUTH_BROKER_REDIRECT_URI`                 | Redirect URI handled by wallet-as auth-broker callback route.                                                 | Default: `SERVICE_URL + /interaction/authBroker/callback`.                                                           |
| `AUTH_BROKER_SKIP_LOGOUT`                  | Skip external IdP logout even if IdP supports it in metadata in `auth-broker` callback flow.                  | Optional; set to `true` when logout should be skipped.                                                               |
| `ABCA_CLIENT_ATTESTATION_MAX_AGE`          | Maximum attestation age in seconds under `DEFAULT`; if `iat` is absent, limits remaining validity instead.    | Defaults to `86400`. Ignored under `WEBUILD`.                                                                        |
| `ABCA_CLIENT_ATTESTATION_POP_MAX_AGE`      | Maximum PoP age in seconds under `DEFAULT`. Future PoP issuance times are rejected.                           | Defaults to `60`. Ignored under `WEBUILD`.                                                                           |
| `ABCA_CHALLENGE_SECRET`                    | Shared secret for Attestation-Based Client Authentication challenges.                                         | Required: exactly 64 hexadecimal characters encoding 32 random bytes.                                                |
| `WEBUILD_ABCA_STATUS_LIST_ALLOWED_ORIGINS` | Comma-separated trusted origins for WIA status list requests under the WE BUILD profile.                      | Required at startup only when `OPENID4VC_PROFILE=WEBUILD`. HTTPS required; HTTP loopback allowed outside production. |

Generate `ABCA_CHALLENGE_SECRET` once with `openssl rand -hex 32` and store it
in your local `.env` or deployment secret manager. Use the same value across all
AS replicas and restarts. Missing or malformed values prevent startup; there is
no generated fallback. Replacing the secret invalidates outstanding challenges,
so coordinate changes across replicas. Never commit the generated value.

### Profiles

Set `OPENID4VC_PROFILE` in `.env` to select the ecosystem requirements applied by wallet-as:

| Value     | Behavior                                                                                                                             |
| --------- | ------------------------------------------------------------------------------------------------------------------------------------ |
| `DEFAULT` | Default when unset. Applies the configurable attestation and PoP maximum ages, without WE BUILD checks or WIA status-list requests.  |
| `WEBUILD` | Adds required wallet fields, WIA lifetime below 24 hours when `iat` is present, WIA/DPoP key equality, and revocation-status checks. |

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

## Pre-commit Hook

We use [pre-commit](https://pre-commit.com/) to enforce `.editorconfig` before code is committed.

```sh
# Install pre-commit if needed, then install this repository's hooks.
pip install pre-commit       # or brew install pre-commit / pipx install pre-commit
pre-commit install

# Run all hooks, including the end-of-file auto-fixer.
pre-commit run --all-files
```

### Local checks without committing

Run only the EditorConfig check, without running auto-fixers:

```sh
pre-commit run editorconfig-checker --all-files
```

Omit `--all-files` to check only staged files. The first run installs the pinned native checker in pre-commit's cache. This check reports violations without changing or staging files.

### What happens on commit

- Auto-fixers run (e.g. add final newlines).
- After the auto-fixers, editorconfig-checker validates staged files.
- If violations remain, fix them manually until the commit passes.
