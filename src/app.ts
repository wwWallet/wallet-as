import express from "express";
import path from "path";
import * as oidc from "oidc-provider";

const app = express();
const port = process.env.PORT || 6060;

// Keep templates alongside source for both ts-node and compiled runs.
const viewsPath = path.join(__dirname, "../src/views");

app.use(express.json());
app.set("views", viewsPath);
app.set("view engine", "pug");

app.get("/", (_req, res) => res.render("index"));

const provider = new oidc.Provider("http://localhost:6060", {
  clients: [
    {
      "client_id": "test",
      "client_secret": "test",
      "redirect_uris": [
        "http://localhost:9876/callback"
      ]
    }
  ],
  scopes: ['openid', 'pid:sd_jwt_dc']
});

app.use("/", provider.callback());

app.listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});
