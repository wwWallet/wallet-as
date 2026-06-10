import express from "express";
import path from "path";
import * as oidc from "oidc-provider";
import interactions from "./routes/interactions";
import { DemoAccountSource } from "./account/DemoAccountSource";
import { FileAccountSource } from "./account/FileAccountSource";
import { introspectionAllowedPolicy } from "./util/introspectionHelpers";
import config from "./config";
import { interactionPolicies } from "./policies/interactionPolicies";
import { issueRefreshToken } from "./policies/issueRefreshToken";
import { loadAuthenticator } from "./authenticators";
import { randomBytes } from 'crypto';
import { exportJWK, importSPKI } from "jose";
import {
  consumeIssuerStateForAuthorizationCode,
  saveIssuerStateForAuthorizationCode,
} from "./util/issuerStateStore";

export function createApp() {
  const app = express();
  app.set('trust proxy', true);
  const authenticator = loadAuthenticator(config.authenticator);
  // Keep templates alongside source for both ts-node and compiled runs.
  const viewsPath = path.join(__dirname, "../src/views");

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.set("views", viewsPath);
  app.set("view engine", "pug");
  app.locals.baseUrl = config.serviceUrl;
  app.locals.demoMode = config.demoUsername || false;
  app.locals.demoUsername = config.demoUsername;
  app.locals.demoPassword = config.demoPassword;

  const oidClients: oidc.ClientMetadata[] = [
    {
      client_id: "test",
      client_secret: "test",
      redirect_uris: ["http://localhost:9876/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      logo_uri:
        "https://raw.githubusercontent.com/wwWallet/wallet-frontend/master/branding/default/logo/logo_dark.svg",
      token_endpoint_auth_method: config.attestationBasedClientAuthentication
        ? 'attest_jwt_client_auth' as any
        : 'client_secret_basic',
    },
    {
      client_id: "test2",
      client_secret: "test2",
      redirect_uris: ["http://localhost:9876/callback"],
      grant_types: ["authorization_code", "refresh_token"],
      logo_uri:
        "https://raw.githubusercontent.com/wwWallet/wallet-frontend/master/branding/default/logo/logo_dark.svg",
      token_endpoint_auth_method: config.attestationBasedClientAuthentication
        ? 'attest_jwt_client_auth' as any
        : 'client_secret_basic',
    },
    {
      client_id: "1233",
      client_secret: "1233",
      redirect_uris: [config.walletUrl],
      post_logout_redirect_uris: [config.walletUrl],
      grant_types: ["authorization_code", "refresh_token"],
      logo_uri:
        "https://raw.githubusercontent.com/wwWallet/wallet-frontend/master/branding/default/logo/logo_dark.svg",
      token_endpoint_auth_method: config.attestationBasedClientAuthentication
        ? 'attest_jwt_client_auth' as any
        : 'client_secret_basic',
    }
  ];

  if (config.introspectionClient && config.introspectionClientSecret) {
    console.log("Adding introspection client");
    oidClients.push({
      client_id: config.introspectionClient,
      client_secret: config.introspectionClientSecret,
      redirect_uris: ["http://localhost"],
    });
  }

  const provider = new oidc.Provider(config.serviceUrl, {
    clients: oidClients,

    scopes: config.scopes,
    interactions: {
      policy: interactionPolicies(),
      url(ctx, interaction) {
        if (interaction.prompt.name === "login") {
          const loginUrl = authenticator.getLoginInteractionUrl(interaction);
          if (loginUrl) {
            return loginUrl;
          }
          throw new Error("No login interaction URL could be resolved from configured authenticator");
        }
        return `${config.basePath}/interaction/${interaction.uid}`;
      }
    },
    features: {
      devInteractions: { enabled: false },
      introspection: {
        enabled: true,
        allowedPolicy: introspectionAllowedPolicy,
      },
      jwtResponseModes: {
        enabled: true,
      },
      pushedAuthorizationRequests: {
        enabled: true,
      },
      resourceIndicators: {
        enabled: true,
        async getResourceServerInfo(ctx, resourceIndicator, client) {

          if (!resourceIndicator || !config.trustedIssuers.includes(resourceIndicator)) {
            throw new oidc.errors.InvalidTarget();
          }

          const scope = ctx.oidc.params?.scope as string | undefined;
          if (scope) {
            const parsedScopes = scope.split(' ').filter(Boolean);
            for (const parsedScope of parsedScopes) {
              if (!config.scopes.includes(parsedScope)) {
                throw new oidc.errors.InvalidScope('Scope is not supported by resource server', parsedScope);
              }
            }
          }

          return {
            scope: scope,
            audience: resourceIndicator,
          } as unknown as oidc.ResourceServer;
        },
        async defaultResource(_ctx, _client, oneOf) {
          if (oneOf && oneOf.length > 0) {
            return oneOf[0];
          }

          if (config.trustedIssuers.length > 0) {
            return config.trustedIssuers[0];
          }

          return [];
        },
        async useGrantedResource(_ctx, _model) {
          return true;
        },
      },
      attestClientAuth: {
        enabled: true,
        challengeSecret: randomBytes(32),
        ack: 'draft-06',
        async getAttestationSignaturePublicKey(_ctx: any, iss: any, _header: any, _client: any) {
          if (!Object.keys(config.trustedClientAttesters).includes(iss)) {
            throw new Error('unknown attester');
          }

          return (
            await exportJWK(
              await importSPKI(
                config.trustedClientAttesters[iss],
                'ES256'
              )
            )
          );
        },

        async assertAttestationJwtAndPop(
          _ctx: any,
          _attestation: any,
          pop: any,
        ) {
          if (!pop.payload.cnf) {
            throw new Error('missing cnf');
          }
        },
      },
    },
    issueRefreshToken: issueRefreshToken,
    ttl: {
      AccessToken: config.ttl.accessToken,
      RefreshToken: config.ttl.refreshToken,
    },
    clientAuthMethods: [
      'client_secret_basic',
      'client_secret_jwt',
      'client_secret_post',
      'private_key_jwt',
      'attest_jwt_client_auth' as any,  // Attestation-based client authentication (ABCA) method is not supported by latest @types/oidc-provider yet.
      'none'
    ],
    discovery: {
      client_attestation_signing_alg_values_supported: ['ES256'],
      client_attestation_pop_signing_alg_values_supported: ['ES256']
    },
    extraParams: ['issuer_state'],
    async extraTokenClaims(ctx, _token) {
      const issuerState = await consumeIssuerStateForAuthorizationCode(
        (ctx.oidc.entities.AuthorizationCode as any)?.jti
      );
      return issuerState ? { issuer_state: issuerState } : undefined;
    },
  });
  provider.on("authorization_code.saved", (authorizationCode) => {
    const issuerState = (oidc.Provider.ctx?.oidc.params as any)?.issuer_state;
    void saveIssuerStateForAuthorizationCode(
      authorizationCode.jti,
      issuerState
    );
  });
  provider.proxy = true;
  const accountSource = config.demoUsername
    ? new DemoAccountSource()
    : new FileAccountSource();

  const routesRoot = express.Router();
  routesRoot.use(express.static(path.join(process.cwd(), "public")));
  routesRoot.get("/", (_req, res) => res.render("index"));
  authenticator.registerRoutes(routesRoot, provider, accountSource);
  interactions(routesRoot, provider, accountSource, authenticator);
  routesRoot.use(provider.callback());
  app.use(config.basePath || "/", routesRoot);

  return { app, provider };
}

if (require.main === module) {
  const { app } = createApp();
  const port = process.env.PORT || 6060;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}
