import Express from "express";
import Provider from "oidc-provider";
import config from "../config";
import { OpenidForVPService } from "../services/OpenidForVPService";
import { generateRandomIdentifier } from "../util/generateRandomIdentifier";

const pidPresentationRequest = {
  id: "PID",
  title: "PID",
  description: "Present your PID to sign in",
  dcql_query: {
    credentials: [
      {
        id: "PID",
        format: "dc+sd-jwt",
        meta: {
          vct_values: ["urn:eudi:pid:1"]
        },
        claims: [{ path: ["given_name"] }],
      },
    ],
  },
};

export default (app: Express.Application, provider: Provider) => {
  const openidForVPService = new OpenidForVPService({
    baseUrl: config.serviceUrl,
    redirectUri: config.serviceUrl + "/verification/direct_post",
  });

  app.post("/as/interaction/:uid/pid", async (req, res, next) => {
    try {
      const interaction = await provider.interactionDetails(req, res);
      if (interaction.prompt.name !== "login") {
        return res.sendStatus(404);
      }

      const sessionId = generateRandomIdentifier(12);
      const { url } = await openidForVPService.generateAuthorizationRequestURL(
        pidPresentationRequest,
        sessionId,
        `${config.serviceUrl}/interaction/${interaction.uid}/pid/callback`
      );

      const wwwalletOrigin = new URL(config.walletUrl).origin;
      const modifiedUrl = url.toString().replace("openid4vp://cb", wwwalletOrigin);
      console.log("Redirecting to wallet with URL:", modifiedUrl);
      return res.redirect(modifiedUrl);
    } catch (err) {
      next(err);
    }
  });

  app.get("/as/interaction/:uid/pid/callback", async (_req, res) => {
    res.render("pid-callback")
  });

  app.post("/as/interaction/:uid/pid/callback", async (req, res, next) => {
    try {
      const responseCode = req.body.response_code as string | undefined;
      if (!responseCode) {
        return res.status(400).send({ error: "Missing response_code" });
      }

      const rpState = await openidForVPService.openid4vpClient.getRPStateByResponseCode(responseCode);
      if (!rpState) {
        return res.status(400).send({ error: "Invalid response_code" });
      }

      // TODO map claims -> accountId
      const accountId = "test";
      const result = {
        login: { accountId, remember: false },
      };

      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  app.get("/as/verification/request-object", async (req, res) => {
    return openidForVPService.getSignedRequestObject({ req, res });
  });

  app.post("/as/verification/direct_post", async (req, res) => {
    return openidForVPService.responseHandler({ req, res });
  });
};
