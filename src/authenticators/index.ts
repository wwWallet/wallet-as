import { factory as authBrokerFactory } from "./authBroker";
import { factory as userPassPidFactory } from "./userPassPid";
import { Authenticator, AuthenticatorFactory } from "./types";

const AUTHENTICATOR_FACTORIES: AuthenticatorFactory[] = [userPassPidFactory, authBrokerFactory];
const AUTHENTICATOR_FACTORY_MAP = new Map(
  AUTHENTICATOR_FACTORIES.map((factory) => [factory.id, factory])
);

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

  const factory = AUTHENTICATOR_FACTORY_MAP.get(id);
  if (!factory) {
    throw new Error(
      `Unknown authenticator '${id}'. Supported authenticators: ${AUTHENTICATOR_FACTORIES.map((entry) => entry.id).join(", ")}`
    );
  }
  return factory.create();
};

export type { Authenticator, AuthenticatorFactory, InteractionDetails } from "./types";
