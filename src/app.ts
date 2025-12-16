import express from "express";
import path from "path";
import * as oidc from "oidc-provider";
import interactions from "./routes/interactions";
import { DemoAccountSource } from "./account/DemoAccountSoure";

const app = express();
const port = process.env.PORT || 6060;

// Keep templates alongside source for both ts-node and compiled runs.
const viewsPath = path.join(__dirname, "../src/views");

// Serve static files
app.use(express.static(path.join(process.cwd(), "public")));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.set("views", viewsPath);
app.set("view engine", "pug");

app.get("/", (_req, res) => res.render("index"));

async function introspectionAllowedPolicy(
  ctx: oidc.KoaContextWithOIDC,
  client: oidc.Client,
  token: oidc.AccessToken | oidc.ClientCredentials | oidc.RefreshToken,
) {
  if (client.clientAuthMethod !== "client_secret_basic") {
    return false;
  }
  if (token.clientId !== ctx?.oidc?.client?.clientId) {
    return false;
  }
  return true;
}

const provider = new oidc.Provider("http://localhost:6060", {
  clients: [
    {
      "client_id": "test",
      "client_secret": "test",
      "redirect_uris": [
        "http://localhost:9876/callback"
      ],
      "logo_uri": "https://raw.githubusercontent.com/wwWallet/wallet-frontend/master/branding/default/logo/logo_dark.svg",
    }
  ],
  scopes: ['openid', 'pid:sd_jwt_dc'],
  features: {
    devInteractions: { enabled: false },
    introspection: {
      enabled: true,
      allowedPolicy: introspectionAllowedPolicy,
    },
  },
});
const acSource = new DemoAccountSource();

interactions(app, provider, acSource);
app.use("/", provider.callback());

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
