import config from "../../config";
import { Authenticator, AuthenticatorFactory } from "../types";
import { registerAuthBrokerRoutes } from "./registerRoutes";

const createAuthenticator = (): Authenticator => {
  if (!config.authBrokerConfigured) {
    throw new Error(
      "auth-broker authenticator selected but AUTH_BROKER_PROVIDER_URL and AUTH_BROKER_CLIENT_ID are not configured"
    );
  }

  return {
    id: "auth-broker",
    getLoginInteractionUrl: (interaction) => {
      if (interaction.prompt.name !== "login") {
        return null;
      }
      return `${config.basePath}/interaction/${interaction.uid}/authBroker`;
    },
    shouldAutoApproveConsent: (interaction) => interaction.prompt.name === "consent",
    registerRoutes: registerAuthBrokerRoutes,
  };
};

export const factory: AuthenticatorFactory = {
  id: "auth-broker",
  create: createAuthenticator,
};
