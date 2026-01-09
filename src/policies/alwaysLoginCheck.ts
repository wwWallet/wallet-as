import { interactionPolicy } from "oidc-provider";

const { Check } = interactionPolicy;

export const alwaysLoginCheck = () => {
  return new Check("always", "End-User authentication is required", (ctx) => {
    if (ctx.oidc.result?.login) {
      return Check.NO_NEED_TO_PROMPT;
    }
    return Check.REQUEST_PROMPT;
  });
};
