import Express from "express";
import Provider from "oidc-provider";
import config from "../../config";
import IAccountSource from "../../interfaces/IAccountSource";
import * as openidClient from "openid-client";
import { DataStore } from "../../stores/DataStore";
import { dataStoreClient } from "../../app";

type PendingBrokerRequest = {
  state: string;
  uid: string;
  createdAt: number;
};

const requestStore = new DataStore<PendingBrokerRequest>(dataStoreClient, "brokerRequestStore");
let brokerConfigurationPromise: Promise<openidClient.Configuration> | null = null;

const getBrokerConfiguration = async () => {
  const authBrokerProviderUrl = config.authBrokerProviderUrl;
  if (!authBrokerProviderUrl || !config.authBrokerClientId) {
    throw new Error("AUTH_BROKER_PROVIDER_URL and AUTH_BROKER_CLIENT_ID are required");
  }
  if (!brokerConfigurationPromise) {
    const clientMetadata: Partial<openidClient.ClientMetadata> = {
      redirect_uris: [config.authBrokerRedirectUri],
      response_types: ["code"],
    };
    if (config.authBrokerClientSecret) {
      clientMetadata.client_secret = config.authBrokerClientSecret;
    } else {
      clientMetadata.token_endpoint_auth_method = "none";
    }

    brokerConfigurationPromise = openidClient.discovery(
      new URL(authBrokerProviderUrl),
      config.authBrokerClientId,
      clientMetadata
    );
  }
  return brokerConfigurationPromise;
};

const logoutAndFinishUrl = (brokerConfiguration: openidClient.Configuration, finishUrl: string, idToken: string | undefined) => {
  if (config.authBrokerSkipLogout || !brokerConfiguration.serverMetadata().end_session_endpoint || !idToken) {
    return finishUrl;
  }

  try {
    return openidClient.buildEndSessionUrl(brokerConfiguration, {
      post_logout_redirect_uri: finishUrl,
      id_token_hint: idToken,
      client_id: config.authBrokerClientId || ""
    }).toString();
  } catch(e) {
    console.error(e);
    return finishUrl;
  }
}

export const registerAuthBrokerRoutes = (app: Express.Router, provider: Provider, _accountSource: IAccountSource) => {
  const startAuthBroker = async (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {
    try {
      const interaction = await provider.interactionDetails(req, res);
      if (interaction.prompt.name !== "login") {
        return res.sendStatus(404);
      }

      const brokerConfiguration = await getBrokerConfiguration();

      const state = openidClient.randomState();
      await requestStore.set(state, {
        state,
        uid: interaction.uid,
        createdAt: Date.now(),
      }, config.authBrokerRequestStoreTtlMs);

      const authorizationUrl = openidClient.buildAuthorizationUrl(brokerConfiguration, {
        scope: config.authBrokerScope,
        response_type: "code",
        redirect_uri: config.authBrokerRedirectUri,
        state,
      });
      return res.redirect(authorizationUrl.toString());
    } catch (err) {
      next(err);
      return undefined;
    }
  };

  app.get("/interaction/:uid/authBroker", startAuthBroker);
  app.post("/interaction/:uid/authBroker", startAuthBroker);

  app.get("/interaction/authBroker/callback", async (req, res) => {
    const state = req.query.state as string | undefined;
    if (!state) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing state in broker callback",
      });
    }

    const requestState = await requestStore.get(state);
    if (!requestState) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Invalid or expired auth broker request",
      });
    }

    const callbackUrl = new URL(req.originalUrl, `${req.protocol}://${req.get("host")}`);
    const query = callbackUrl.search;
    return res.redirect(
      `${config.basePath}/interaction/${encodeURIComponent(requestState.uid)}/authBroker/callback${query}`
    );
  });

  app.get("/interaction/:uid/authBroker/callback", async (req, res) => {
    let state: string | undefined;
    try {
      const interaction = await provider.interactionDetails(req, res);
      if (interaction.prompt.name !== "login") {
        return res.sendStatus(404);
      }
      if (interaction.uid !== req.params.uid) {
        return res.sendStatus(404);
      }

      const error = req.query.error as string | undefined;
      if (error) {
        const errorDescription = (req.query.error_description as string | undefined) ?? "Authentication was rejected by external IdP";
        await provider.interactionFinished(
          req,
          res,
          { error: "access_denied", error_description: errorDescription },
          { mergeWithLastSubmission: false }
        );
        return;
      }

      state = req.query.state as string | undefined;
      if (!state) {
        await provider.interactionFinished(
          req,
          res,
          { error: "invalid_request", error_description: "Missing state in broker callback" },
          { mergeWithLastSubmission: false }
        );
        return;
      }

      const authorizationCode = req.query.code as string | undefined;
      if (!authorizationCode) {
        await provider.interactionFinished(
          req,
          res,
          { error: "invalid_request", error_description: "Missing authorization code in broker callback" },
          { mergeWithLastSubmission: false }
        );
        return;
      }

      const requestState = await requestStore.get(state);
      if (!requestState || requestState.uid !== interaction.uid) {
        await provider.interactionFinished(
          req,
          res,
          { error: "invalid_request", error_description: "Invalid or expired auth broker request" },
          { mergeWithLastSubmission: false }
        );
        return;
      }

      const brokerConfiguration = await getBrokerConfiguration();
      const incoming = new URL(req.originalUrl, `${req.protocol}://${req.get("host")}`);
      const grantUrl = new URL(config.authBrokerRedirectUri);
      grantUrl.search = incoming.search;
      const tokenSet = await openidClient.authorizationCodeGrant(
        brokerConfiguration,
        grantUrl,
        { expectedState: state }
      );

      const idTokenClaims = tokenSet.claims();
      const externalSubject = idTokenClaims?.sub as string | undefined;
      if (!externalSubject) {
        const interactionFinishUri = await provider.interactionResult(
          req,
          res,
          { error: "access_denied", error_description: "Missing subject in IdP token response" },
          { mergeWithLastSubmission: false }
        );
        return res.redirect(logoutAndFinishUrl(brokerConfiguration, interactionFinishUri, tokenSet.id_token));
      }

      const result = {
        login: { accountId: externalSubject, remember: false },
      };

      const interactionFinishUri = await provider.interactionResult(req, res, result, { mergeWithLastSubmission: false })
      return res.redirect(logoutAndFinishUrl(brokerConfiguration, interactionFinishUri, tokenSet.id_token));
    } catch (err) {
      const errorDescription = err instanceof Error ? err.message : "External authentication failed";
      try {
        await provider.interactionFinished(
          req,
          res,
          { error: "access_denied", error_description: errorDescription },
          { mergeWithLastSubmission: false }
        );
      } catch {
        if (!res.headersSent) {
          res.status(500).json({
            error: "access_denied",
            error_description: errorDescription,
            err: JSON.stringify(errorDescription)
          });
        }
      }
    } finally {
      if (state) {
        await requestStore.delete(state);
      }
    }
  });
};
