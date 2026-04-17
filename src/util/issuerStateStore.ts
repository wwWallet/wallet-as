import { MemoryStore } from "wallet-common";

const issuerStateByGrantId = new MemoryStore<string, string>();

export const saveIssuerStateForGrant = async (
  grantId: string,
  issuerState: unknown
) => {
  if (typeof issuerState !== "string" || issuerState.length === 0) {
    return;
  }
  await issuerStateByGrantId.set(grantId, issuerState);
};

export const getIssuerStateForGrant = async (grantId: unknown) => {
  if (typeof grantId !== "string" || grantId.length === 0) {
    return undefined;
  }
  return issuerStateByGrantId.get(grantId);
};
