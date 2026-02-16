import express from "express";
import path from "path";
import * as oidc from "oidc-provider";
import interactions from "./routes/interactions";
import pidAuth from "./routes/pidAuth";
import { DemoAccountSource } from "./account/DemoAccountSource";
import { FileAccountSource } from "./account/FileAccountSource";
import { introspectionAllowedPolicy } from "./util/introspectionHelpers";
import config from "./config";
import { interactionPolicies } from "./policies/interactionPolicies";
import { issueRefreshToken } from "./policies/issueRefreshToken";

export function createApp() {
  const app = express();
  app.set('trust proxy', true);
  // Keep templates alongside source for both ts-node and compiled runs.
  const viewsPath = path.join(__dirname, "../src/views");

  // Serve static files
  app.use("/as", express.static(path.join(process.cwd(), "public")));

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.set("views", viewsPath);
  app.set("view engine", "pug");
  app.locals.baseUrl = config.serviceUrl;
  app.locals.demoMode = config.demoUsername || false;
  app.locals.demoUsername = config.demoUsername;
  app.locals.demoPassword = config.demoPassword;

  app.get("/as", (_req, res) => res.render("index"));
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
          return `/as/interaction/${interaction.uid}`;
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
    }
  });
  provider.proxy = true;
  const demoAccountSource = new DemoAccountSource();
  const fileAccountSource = new FileAccountSource();

  interactions(app, provider, demoAccountSource);
  pidAuth(app, provider, fileAccountSource);
  app.use("/as", provider.callback());

  return { app, provider };
}

if (require.main === module) {
  const { app } = createApp();
  const port = process.env.PORT || 6060;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}
