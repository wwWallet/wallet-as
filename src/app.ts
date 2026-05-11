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
import { getIssuerStateForGrant } from "./util/issuerStateStore";

export function createApp() {
  const app = express();
  app.set('trust proxy', true);
  const authenticator = loadAuthenticator(config.authenticator);
  // Keep templates alongside source for both ts-node and compiled runs.
  const viewsPath = path.join(__dirname, "../src/views");

  // Serve static files
  app.use(express.static(path.join(process.cwd(), "public")));

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.set("views", viewsPath);
  app.set("view engine", "pug");
  app.locals.baseUrl = config.serviceUrl;
  app.locals.demoMode = config.demoUsername || false;
  app.locals.demoUsername = config.demoUsername;
  app.locals.demoPassword = config.demoPassword;

  app.get("/", (_req, res) => res.render("index"));
  const oidClients: oidc.ClientMetadata[] = [
    {
      client_id: "test",
      client_secret: "test",
      redirect_uris: ["http://localhost:9876/callback"],
      logo_uri:
        "https://raw.githubusercontent.com/wwWallet/wallet-frontend/master/branding/default/logo/logo_dark.svg",
    },
    {
      client_id: "test2",
      client_secret: "test2",
      redirect_uris: ["http://localhost:9876/callback"],
      logo_uri:
        "https://raw.githubusercontent.com/wwWallet/wallet-frontend/master/branding/default/logo/logo_dark.svg",
    },
    {
      client_id: "1233",
      token_endpoint_auth_method: "none",
      redirect_uris: [config.walletUrl],
      logo_uri:
        "https://raw.githubusercontent.com/wwWallet/wallet-frontend/master/branding/default/logo/logo_dark.svg",
    },
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
        return `/interaction/${interaction.uid}`;
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
    },
    issueRefreshToken: issueRefreshToken,
    ttl: {
      AccessToken: config.ttl.accessToken,
      RefreshToken: config.ttl.refreshToken,
    },
    extraParams: ['issuer_state'],
    async extraTokenClaims(_ctx, token) {
      const issuerState = await getIssuerStateForGrant((token as any).grantId);
      return issuerState ? { issuer_state: issuerState } : undefined;
    },
  });
  provider.proxy = true;
  const accountSource = config.demoUsername
    ? new DemoAccountSource()
    : new FileAccountSource();

  authenticator.registerRoutes(app, provider, accountSource);
  interactions(app, provider, accountSource, authenticator);
  app.use(provider.callback());

  return { app, provider };
}

if (require.main === module) {
  const { app } = createApp();
  const port = process.env.PORT || 6060;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}
