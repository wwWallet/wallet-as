import {
  CredentialRenderingService,
  defaultHttpClient,
  CustomCredentialSvg,
  dataUriResolver,
  getSdJwtVcMetadata,
} from 'wallet-common';
import type {
  CredentialConfigurationSupported,
  TypeMetadata as TypeMetadataSchema,
  VctDocumentProvider,
} from 'wallet-common';

const sdJwtVcRenderer = CredentialRenderingService();
const customRenderer = CustomCredentialSvg({ httpClient: defaultHttpClient });

export type IssuerDisplay = NonNullable<
  NonNullable<CredentialConfigurationSupported['credential_metadata']>['display']
>;

export async function getConsentPreviewDataUri(opts: {
  vctEngine: VctDocumentProvider;
  vct?: string | null;
  issuerDisplayArray?: IssuerDisplay | null;
  langs?: string[];
}): Promise<{ dataUri: string | null; credentialMetadata?: TypeMetadataSchema }> {
  const { vctEngine, vct, issuerDisplayArray, langs = ['en-US'] } = opts;

  if (!issuerDisplayArray?.length) return { dataUri: null };

  let credentialMetadata: TypeMetadataSchema | undefined;

  if (vct) {
    const r = await getSdJwtVcMetadata(vctEngine, crypto.subtle, defaultHttpClient, vct, undefined);
    if (r && !('error' in r)) credentialMetadata = r.credentialMetadata;
  }

  const resolve = dataUriResolver({
    httpClient: defaultHttpClient,
    customRenderer,
    sdJwtVcRenderer,
    issuerDisplayArray,
    credentialDisplayArray: credentialMetadata?.display,
    fallbackName: 'Credential',
  });

  const dataUri = await resolve(undefined, langs);
  return { dataUri };
}
