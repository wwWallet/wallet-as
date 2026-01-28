import { interactionPolicy } from "oidc-provider";
import { alwaysLoginCheck } from "./alwaysLoginCheck";
import { alwaysConsentCheck } from "./alwaysConsentCheck";

const { base } = interactionPolicy;

export const interactionPolicies = () => {
  const policy = base();

  const login = policy.get("login");
  const consent = policy.get("consent");

  if (login) {
    login.checks.add(alwaysLoginCheck())
  }
  if (consent) {
    consent.checks.add(alwaysConsentCheck())
  }
  return policy;
};
