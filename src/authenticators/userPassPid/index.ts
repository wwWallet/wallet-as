import { Authenticator, AuthenticatorFactory } from "../types";
import { registerUserPassPidRoutes } from "./registerRoutes";

const createAuthenticator = (): Authenticator => ({
  id: "user-pass-pid",
  getLoginInteractionUrl: (interaction) => {
    if (interaction.prompt.name !== "login") {
      return null;
    }
    return `/interaction/${interaction.uid}`;
  },
  registerRoutes: registerUserPassPidRoutes,
});

export const factory: AuthenticatorFactory = {
  id: "user-pass-pid",
  create: createAuthenticator,
};
