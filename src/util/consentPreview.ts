import { defaultHttpClient } from "wallet-common/dist/defaultHttpClient";
import { OpenID4VCICredentialRendering } from "wallet-common/dist/functions/openID4VCICredentialRendering";
import { dataUriResolver } from "wallet-common/dist/resolvers";
import { getSdJwtVcMetadata } from "wallet-common/dist/utils";
import { CredentialRenderingService } from "wallet-common";
import type { TypeMetadata as TypeMetadataSchema } from "wallet-common/dist/schemas/SdJwtVcTypeMetadataSchema";

const sdJwtVcRenderer = CredentialRenderingService();
const customRenderer = OpenID4VCICredentialRendering({ httpClient: defaultHttpClient });

export async function getConsentPreviewDataUri(opts: {
    vctEngine: any;
    vct?: string | null;
    issuerDisplayArray?: any;
    langs?: string[];
}): Promise<{ dataUri: string | null; credentialMetadata?: TypeMetadataSchema }> {
    const { vctEngine, vct, issuerDisplayArray, langs = ["en-US"] } = opts;

    if (!issuerDisplayArray?.length) return { dataUri: null };

    let credentialMetadata: TypeMetadataSchema | undefined;

    if (vct) {
        const r = await getSdJwtVcMetadata(vctEngine, crypto.subtle, defaultHttpClient, vct, undefined);
        if (r && !("error" in r)) credentialMetadata = r.credentialMetadata;
    }

    const resolve = dataUriResolver({
        httpClient: defaultHttpClient,
        customRenderer,
        sdJwtVcRenderer,
        issuerDisplayArray,
        credentialDisplayArray: credentialMetadata?.display,
        fallbackName: "Credential",
    });

    const dataUri = await resolve(undefined, langs);
    return { dataUri, credentialMetadata };
}
