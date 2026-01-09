import { interactionPolicy } from "oidc-provider";
import { alwaysLoginCheck } from "./alwaysLoginCheck";

const { base } = interactionPolicy;

export const interactionPolicies = () => {
  const policy = base();

  const login = policy.get("login");
  if (login) {
    login.checks.add(alwaysLoginCheck())
  }
  return policy;
};
