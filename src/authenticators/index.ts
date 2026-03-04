import { createAuthBrokerAuthenticator } from "./authBroker";
import { createUserPassPidAuthenticator } from "./userPassPid";
import { Authenticator } from "./types";

const AUTHENTICATOR_FACTORIES: Record<string, () => Authenticator> = {
  "user-pass-pid": createUserPassPidAuthenticator,
  "auth-broker": createAuthBrokerAuthenticator,
};

export const loadAuthenticator = (id: string): Authenticator => {
  if (!id) {
    throw new Error(
      "No authenticator configured. Set AUTHENTICATOR to one value, e.g. AUTHENTICATOR=user-pass-pid"
    );
  }

  if (id.includes(",") || id.includes("|")) {
    throw new Error(
      "AUTHENTICATOR must be a single value, not a list"
    );
  }

  const factory = AUTHENTICATOR_FACTORIES[id];
  if (!factory) {
    throw new Error(
      `Unknown authenticator '${id}'. Supported authenticators: ${Object.keys(AUTHENTICATOR_FACTORIES).join(", ")}`
    );
  }
  return factory();
};

export type { Authenticator, InteractionDetails } from "./types";
