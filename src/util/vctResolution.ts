import { createVctDocumentResolutionEngine, VctDocumentProvider, VctResolutionErrors, ok, err } from "wallet-common";

export function createVctProviderFromEnv(): ReturnType<typeof createVctDocumentResolutionEngine> {
    const provider: VctDocumentProvider = {
        getVctMetadataDocument: async (vct: string) => {
            try {
                const base = process.env.VCT_REGISTRY_URL;
                if (!base) return err(VctResolutionErrors.NotFound);

                const url = new URL(base);
                url.searchParams.set("vct", vct);

                const res = await fetch(url);
                if (!res.ok) return err(VctResolutionErrors.NotFound);

                const json = await res.json();
                return ok(json as any);
            } catch {
                return err(VctResolutionErrors.NotFound);
            }
        },
    };

    return createVctDocumentResolutionEngine([provider]);
}
