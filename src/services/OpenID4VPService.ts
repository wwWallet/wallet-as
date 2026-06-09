import { Request, Response } from "express";
import { MemoryStore, OpenID4VPClientErrors, OpenID4VPClientAPI, OpenID4VPResponseMode, RPState } from "wallet-common";
import { defaultHttpClient } from "wallet-common";
import { webcrypto } from "node:crypto";
import { pemToBase64 } from "../util/pemToBase64";
import { decodeBase64Url } from "../util/decodeBase64Url";
import config from "../config";
import fs from 'fs';
import path from "path";

const privateKeyPem = fs.readFileSync(path.join(__dirname, "../../keys/pem.key"), 'utf-8').toString();
const leafCert = fs.readFileSync(path.join(__dirname, "../../keys/pem.crt"), 'utf-8').toString();
const x5c = [
	pemToBase64(leafCert),
];

export type OpenidForPresentationsConfiguration = {
  baseUrl: string;
  redirectUri: string;
};

export class OpenID4VPService {
  private static rpStateKV: MemoryStore<string, RPState | string> = new MemoryStore();
  public openid4vpClient: OpenID4VPClientAPI;

  private privateKeyPem: string = privateKeyPem;
  private x5c: string[] = x5c;
  private responseMode: OpenID4VPResponseMode;
  constructor(
    private configuration: OpenidForPresentationsConfiguration,
    opts?: {
      privateKeyPem?: string;
      x5c?: string[];
      responseMode?: OpenID4VPResponseMode;
      trustedCertificates?: string[];
      trustedCredentialIssuerIdentifiers?: string[];
    }
  ) {
    this.privateKeyPem = opts?.privateKeyPem ?? privateKeyPem;
    this.x5c = opts?.x5c ?? x5c;
    this.responseMode = opts?.responseMode ?? OpenID4VPResponseMode.DIRECT_POST_JWT;
    this.openid4vpClient = new OpenID4VPClientAPI(
      OpenID4VPService.rpStateKV,
      {
        redirectUri: this.configuration.redirectUri,
        credentialEngineOptions: {
          // @ts-ignore
          clockTolerance: 60,
          subtle: webcrypto.subtle as SubtleCrypto,
          lang: "en-US",
          trustedCertificates: [...config.trustedRootCertificates] as string[],
          trustedCredentialIssuerIdentifiers: config.trustedIssuers as string[] | undefined,
        },
      },
      defaultHttpClient
    );
  }

  public async getSignedRequestObject(ctx: { req: Request; res: Response }): Promise<any> {
    if (!ctx.req.query["id"] || typeof ctx.req.query["id"] !== "string") {
      return ctx.res.status(500).send({ error: "id does not exist on query params" });
    }

    const signedRequestResult = await this.openid4vpClient.getSignedRequestObject(ctx.req.query["id"]);
    if (!signedRequestResult.ok) {
      const { error, error_description } = signedRequestResult;
      if (error === OpenID4VPClientErrors.MissingRPState) {
        return ctx.res.status(500).send({ error, error_description });
      }
      if (error === OpenID4VPClientErrors.SignedRequestObjectInvalidated) {
        return ctx.res.status(500).send({ error, error_description });
      }
      return ctx.res.status(500).send({ error: "unknown error" });
    }
    const signedRequest = signedRequestResult.value;
    return ctx.res.send(signedRequest.toString());
  }

  public async generateAuthorizationRequestURL(
    presentationRequest: any,
    sessionId: string,
    callbackEndpoint?: string
  ): Promise<{ url: URL; stateId: string }> {
    const generated = await this.openid4vpClient.generateAuthorizationRequestURL(
      presentationRequest,
      sessionId,
      this.configuration.redirectUri,
      this.configuration.baseUrl,
      this.privateKeyPem,
      this.x5c,
      this.responseMode,
      callbackEndpoint
    );
    return { url: generated.url, stateId: generated.stateId };
  }

  public async responseHandler(ctx: { req: Request; res: Response }): Promise<void> {
    let vp_token = ctx.req.body?.vp_token;
    let state = ctx.req.body?.state;
    let presentation_submission = ctx.req.body.presentation_submission
      ? JSON.parse(decodeURI(ctx.req.body.presentation_submission))
      : null;

    if (ctx.req.body.response) {
      const { kid } = JSON.parse(decodeBase64Url(ctx.req.body.response.split(".")[0])) as {
        kid: string | undefined;
      };
      if (!kid) {
        throw new Error("Could not extract kid");
      }

      const rpStateResult = await this.openid4vpClient.handleEncryptedAuthorizationResponse(ctx.req.body.response, kid);
      if (!rpStateResult.ok) {
        const { error, error_description } = rpStateResult;
        if (error === OpenID4VPClientErrors.JWEDecryptionFailure) {
          ctx.res.status(500).send({ error, error_description });
          return;
        }
        throw new Error(error_description ?? error);
      }
      const rpState = rpStateResult.value;
      ctx.res.send({ redirect_uri: rpState.callback_endpoint + "#response_code=" + rpState.response_code });
      return;
    }

    if (!state) {
      ctx.res.status(401).send({ error: "Missing state param" });
      return;
    }

    if (!vp_token) {
      ctx.res.status(401).send({ error: "Missing vp_token" });
      return;
    }

    const rpStateResult = await this.openid4vpClient.handleResponseDirectPost(
      state,
      vp_token,
      presentation_submission
    );

    if (!rpStateResult.ok) {
      const { error, error_description } = rpStateResult;
      throw new Error(error_description ?? error);
    }

    const rpState = rpStateResult.value;
    ctx.res.send({ redirect_uri: rpState.callback_endpoint + "#response_code=" + rpState.response_code });
  }
}
