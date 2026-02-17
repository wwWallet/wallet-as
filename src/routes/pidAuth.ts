import Express from "express";
import Provider from "oidc-provider";
import config from "../config";
import { OpenID4VPService } from "../services/OpenID4VPService";
import { generateRandomIdentifier } from "wallet-common";
import IAccountSource from "../interfaces/IAccountSource";

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
        claims: [
          { path: ["family_name"] },
          { path: ["given_name"] },
          { path: ["birthdate"] },
        ],
      },
    ],
  },
};

const extractClaims = (claims: Record<string, Array<{ key: string; value: string }>> | null) => {
  if (!claims) {
    return {};
  }
  const entries = Object.entries(claims);
  if (entries.length === 0) {
    return {};
  }
  const preferred = claims["PID"] ?? entries[0][1];
  return Object.fromEntries(preferred.map((c) => [c.key, c.value]));
};

export default (app: Express.Application, provider: Provider, accountSource: IAccountSource) => {
  const openID4VPService = new OpenID4VPService({
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
      const { url } = await openID4VPService.generateAuthorizationRequestURL(
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

      let sessionId: string | undefined;
      const rpState = await openID4VPService.openid4vpClient.getRPStateByResponseCode(responseCode);
      if (rpState?.session_id) {
        sessionId = rpState.session_id;
      }
      if (!sessionId) {
        return res.status(400).send({ error: "Invalid response_code" });
      }

      const presentationResult = await openID4VPService.openid4vpClient.getPresentationBySessionId(
        sessionId,
        true
      );
      if (
        presentationResult.status === false ||
        presentationResult.rpState.vp_token == null ||
        presentationResult.rpState.claims == null
      ) {
        return res.status(400).send({
          error: presentationResult.status === false ? presentationResult.error.message : "Invalid presentation",
        });
      }

      const claimMap = extractClaims(presentationResult.rpState.claims);
      if (!accountSource.matchClaims) {
        return res.status(500).send({ error: "Account source does not support claim matching" });
      }
      const account = await accountSource.matchClaims(claimMap);
      if (!account) {
        return res.status(401).send({ error: "No matching account" });
      }
      const accountId = account.sub;
      const result = {
        login: { accountId, remember: false },
      };

      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      next(err);
    }
  });

  app.get("/as/verification/request-object", async (req, res) => {
    return openID4VPService.getSignedRequestObject({ req, res });
  });

  app.post("/as/verification/direct_post", async (req, res) => {
    return openID4VPService.responseHandler({ req, res });
  });
};
