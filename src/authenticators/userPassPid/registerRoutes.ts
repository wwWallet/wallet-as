import Express from "express";
import Provider from "oidc-provider";
import config from "../../config";
import { OpenID4VPService } from "../../services/OpenID4VPService";
import { generateRandomIdentifier } from "wallet-common";
import IAccountSource from "../../interfaces/IAccountSource";
import { isPidAuthAllowed } from "../../util/pidAuthEligibility";

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

export const registerUserPassPidRoutes = (
  app: Express.Router,
  provider: Provider,
  accountSource: IAccountSource
) => {
  app.get("/interaction/:uid", async (req, res, next) => {
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

  app.post("/interaction/:uid/login", async (req, res, next) => {
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

  const openID4VPService = new OpenID4VPService({
    baseUrl: config.serviceUrl,
    redirectUri: `${config.serviceUrl}/verification/direct_post`,
  });

  app.post("/interaction/:uid/pid", async (req, res, next) => {
    try {
      const interaction = await provider.interactionDetails(req, res);
      if (interaction.prompt.name !== "login") {
        return res.sendStatus(404);
      }
      if (!isPidAuthAllowed(interaction.params.scope as string)) {
        await provider.interactionFinished(
          req,
          res,
          { error: "access_denied", error_description: "PID authentication not allowed for requested scope" },
          { mergeWithLastSubmission: false }
        );
        return;
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
      return undefined;
    }
  });

  app.get("/interaction/:uid/pid/callback", async (_req, res) => {
    res.render("pid-callback");
  });

  app.post("/interaction/:uid/pid/callback", async (req, res) => {
    try {
      const responseCode = req.body.response_code as string | undefined;
      if (!responseCode) {
        await provider.interactionFinished(
          req,
          res,
          { error: "invalid_request", error_description: "Missing response_code" },
          { mergeWithLastSubmission: false }
        );
        return;
      }

      let sessionId: string | undefined;
      const rpState = await openID4VPService.openid4vpClient.getRPStateByResponseCode(responseCode);
      if (rpState?.session_id) {
        sessionId = rpState.session_id;
      }
      if (!sessionId) {
        await provider.interactionFinished(
          req,
          res,
          { error: "invalid_request", error_description: "Invalid response_code" },
          { mergeWithLastSubmission: false }
        );
        return;
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
        const result = {
          error: "access_denied",
          error_description: "Failed to present required claims",
        };
        await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
        return;
      }

      const claimMap = extractClaims(presentationResult.rpState.claims);
      if (!accountSource.matchClaims) {
        await provider.interactionFinished(
          req,
          res,
          { error: "server_error", error_description: "Account source does not support claim matching" },
          { mergeWithLastSubmission: false }
        );
        return;
      }
      const account = await accountSource.matchClaims(claimMap);
      if (!account) {
        await provider.interactionFinished(
          req,
          res,
          { error: "access_denied", error_description: "No matching account" },
          { mergeWithLastSubmission: false }
        );
        return;
      }
      const result = {
        login: { accountId: account.sub, remember: false },
      };
      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    } catch (err) {
      const result = {
        error: "access_denied",
        error_description: err instanceof Error ? err.message : "Authentication failed: Invalid presentation",
      };
      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
    }
  });

  app.get("/verification/request-object", async (req, res) => {
    return openID4VPService.getSignedRequestObject({ req, res });
  });

  app.post("/verification/direct_post", async (req, res) => {
    return openID4VPService.responseHandler({ req, res });
  });
};
