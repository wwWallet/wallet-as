import { interactionPolicy } from "oidc-provider";

const { Check } = interactionPolicy;

export const alwaysConsentCheck = () => {
  return new Check("always", "End-User consent is required", (ctx) => {
    if (ctx.oidc.result?.consent) {
      return Check.NO_NEED_TO_PROMPT;
    }
    return Check.REQUEST_PROMPT;
  });
};
