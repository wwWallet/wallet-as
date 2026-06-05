import { MemoryStore } from "wallet-common";

const issuerStateByAuthorizationCodeId = new MemoryStore<string, string>();

export const saveIssuerStateForAuthorizationCode = async (
  authorizationCodeId: string,
  issuerState: unknown
) => {
  if (typeof issuerState !== "string" || issuerState.length === 0) {
    return;
  }
  await issuerStateByAuthorizationCodeId.set(authorizationCodeId, issuerState);
};

export const consumeIssuerStateForAuthorizationCode = async (
  authorizationCodeId: unknown
) => {
  if (
    typeof authorizationCodeId !== "string" ||
    authorizationCodeId.length === 0
  ) {
    return undefined;
  }
  const issuerState = await issuerStateByAuthorizationCodeId.get(
    authorizationCodeId
  );
  await issuerStateByAuthorizationCodeId.delete(authorizationCodeId);
  return issuerState;
};
