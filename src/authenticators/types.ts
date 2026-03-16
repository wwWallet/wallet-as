import type Express from "express";
import type Provider from "oidc-provider";
import type IAccountSource from "../interfaces/IAccountSource";

export type InteractionDetails = Awaited<ReturnType<Provider["interactionDetails"]>>;

export interface Authenticator {
  id: string;
  getLoginInteractionUrl: (interaction: InteractionDetails) => string | null;
  shouldAutoApproveConsent?: (interaction: InteractionDetails) => boolean;
  registerRoutes: (
    app: Express.Application,
    provider: Provider,
    accountSource: IAccountSource
  ) => void;
}

export interface AuthenticatorFactory {
  id: string;
  create: () => Authenticator;
}
