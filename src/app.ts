import express from "express";
import path from "path";
import * as oidc from "oidc-provider";
import interactions from "./routes/interactions";
import { DemoAccountSource } from "./account/DemoAccountSource";
import { introspectionAllowedPolicy } from "./util/introspectionHelpers";
import config from "./config";

export function createApp() {
  const app = express();

  // Keep templates alongside source for both ts-node and compiled runs.
  const viewsPath = path.join(__dirname, "../src/views");

  // Serve static files
  app.use(express.static(path.join(process.cwd(), "public")));

  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));
  app.set("views", viewsPath);
  app.set("view engine", "pug");

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
      redirect_uris: ["http://localhost:3000/"],
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

  const provider = new oidc.Provider("http://localhost:6060", {
    clients: oidClients,
    scopes: config.scopes,
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
  });
  const acSource = new DemoAccountSource();

  interactions(app, provider, acSource);
  app.use("/", provider.callback());

  return { app, provider };
}

if (require.main === module) {
  const { app } = createApp();
  const port = process.env.PORT || 6060;
  app.listen(port, () => {
    console.log(`Server listening on http://localhost:${port}`);
  });
}
