import Express from "express";
import Provider from "oidc-provider";
import config from "../config";
import IAccountSource from "../interfaces/IAccountSource";
import * as openidClient from "openid-client";
import { MemoryStore } from "wallet-common";

type PendingBrokerRequest = {
  state: string;
  uid: string;
  createdAt: number;
};

const requestStore = new MemoryStore<string, PendingBrokerRequest>();
const REQUEST_TTL_MS = 10 * 60 * 1000;
let brokerConfigurationPromise: Promise<openidClient.Configuration> | null = null;

const cleanupExpiredRequests = async () => {
  const now = Date.now();
  const allRequests = await requestStore.getAll();
  await Promise.all(allRequests.map(async (value) => {
    if (now - value.createdAt > REQUEST_TTL_MS) {
      await requestStore.delete(value.state);
    }
  }));
};

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

export default (app: Express.Application, provider: Provider, _accountSource: IAccountSource) => {
  const startAuthBroker = async (req: Express.Request, res: Express.Response, next: Express.NextFunction) => {
    try {
      if (!config.authBrokerEnabled) {
        await provider.interactionFinished(
          req,
          res,
          { error: "server_error", error_description: "Configuration Error" },
          { mergeWithLastSubmission: false }
        );
        return;
      }

      const interaction = await provider.interactionDetails(req, res);
      if (interaction.prompt.name !== "login") {
        return res.sendStatus(404);
      }

      const brokerConfiguration = await getBrokerConfiguration();
      await cleanupExpiredRequests();

      const state = openidClient.randomState();
      await requestStore.set(state, {
        state,
        uid: interaction.uid,
        createdAt: Date.now(),
      });

      const authorizationUrl = openidClient.buildAuthorizationUrl(brokerConfiguration, {
        scope: config.authBrokerScope,
        response_type: "code",
        redirect_uri: config.authBrokerRedirectUri,
        state,
      });
      return res.redirect(authorizationUrl.toString());
    } catch (err) {
      next(err);
    }
  };

  app.get("/as/interaction/:uid/authBroker", startAuthBroker);
  app.post("/as/interaction/:uid/authBroker", startAuthBroker);

  app.get("/as/interaction/authBroker/callback", async (req, res) => {
    const state = req.query.state as string | undefined;
    if (!state) {
      return res.status(400).json({
        error: "invalid_request",
        error_description: "Missing state in broker callback",
      });
    }

    await cleanupExpiredRequests();
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
      `/as/interaction/${encodeURIComponent(requestState.uid)}/authBroker/callback${query}`
    );
  });

  app.get("/as/interaction/:uid/authBroker/callback", async (req, res) => {
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

      // TODO: check if there is a better way to do this without cleaning up every time
      // before access
      await cleanupExpiredRequests();
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
      const tokenSet = await openidClient.authorizationCodeGrant(
        brokerConfiguration,
        new URL(config.authBrokerRedirectUri),
        {
          expectedState: state,
        }
      );

      const idTokenClaims = tokenSet.claims();
      // TODO: use idToken.sub for now but consider fetching profile
      const externalSubject = idTokenClaims?.sub as string | undefined;
      if (!externalSubject) {
        await provider.interactionFinished(
          req,
          res,
          { error: "access_denied", error_description: "Missing subject in IdP token response" },
          { mergeWithLastSubmission: false }
        );
        return;
      }

      const result = {
        login: { accountId: externalSubject, remember: false },
      };
      await provider.interactionFinished(req, res, result, { mergeWithLastSubmission: false });
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
