import { Authenticator } from "../types";
import pidAuth from "../../routes/pidAuth";
import { isPidAuthAllowed } from "../../util/pidAuthEligibility";

export const createUserPassPidAuthenticator = (): Authenticator => ({
  id: "user-pass-pid",
  getLoginInteractionUrl: (interaction) => {
    if (interaction.prompt.name !== "login") {
      return null;
    }
    return `/as/interaction/${interaction.uid}`;
  },
  registerRoutes: (app, provider, accountSource) => {
    app.get("/as/interaction/:uid", async (req, res, next) => {
      try {
        const interaction = await provider.interactionDetails(req, res);
        if (interaction.prompt.name !== "login") {
          return next();
        }
        if (interaction.uid !== req.params.uid) {
          return res.sendStatus(404);
        }

        const client = await provider.Client.find(interaction.params.client_id as string);
        return res.render("login", {
          client,
          uid: interaction.uid,
          details: interaction.prompt.details,
          params: interaction.params,
          allowPidAuth: isPidAuthAllowed(interaction.params.scope as string),
        });
      } catch (err) {
        next(err);
        return undefined;
      }
    });

    app.post("/as/interaction/:uid/login", async (req, res, next) => {
      try {
        const interaction = await provider.interactionDetails(req, res);
        if (interaction.prompt.name !== "login") {
          return res.sendStatus(404);
        }
        if (interaction.uid !== req.params.uid) {
          return res.sendStatus(404);
        }

        const account = await accountSource.authenticate(req.body.login, req.body.password);
        if (!account) {
          const client = await provider.Client.find(interaction.params.client_id as string);
          return res.status(401).render("login", {
            client,
            uid: interaction.uid,
            details: interaction.prompt.details,
            params: interaction.params,
            allowPidAuth: isPidAuthAllowed(interaction.params.scope as string),
            error: "Invalid credentials",
            login: req.body.login,
          });
        }

        const result = {
          login: {
            accountId: account.sub,
            remember: false,
          },
        };
        await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
        return undefined;
      } catch (err) {
        next(err);
        return undefined;
      }
    });

    pidAuth(app, provider, accountSource);
  },
});
