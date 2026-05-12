import { Authenticator, AuthenticatorFactory } from "../types";
import { registerUserPassPidRoutes } from "./registerRoutes";
import config from "../../config";

const createAuthenticator = (): Authenticator => ({
  id: "user-pass-pid",
  getLoginInteractionUrl: (interaction) => {
    if (interaction.prompt.name !== "login") {
      return null;
    }
    return `${config.basePath}/interaction/${interaction.uid}`;
  },
  registerRoutes: registerUserPassPidRoutes,
});

export const factory: AuthenticatorFactory = {
  id: "user-pass-pid",
  create: createAuthenticator,
};
