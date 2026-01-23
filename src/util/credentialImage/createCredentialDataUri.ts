import axios from "axios";
import { credentialRendering } from "./credentialRendering";

type DisplayWithLocale = { locale?: string };

function matchDisplayByLocale<T extends DisplayWithLocale>(
	arr: T[] | undefined,
	preferredLangs: string[]
): T | null {
	if (!Array.isArray(arr)) return null;

	for (const lang of preferredLangs) {
		const match = arr.find(d =>
			d.locale === lang ||
			d.locale?.startsWith(lang + '-') ||
			lang?.startsWith(d.locale + '-')
		);
		if (match) return match;
	}
	return arr[0] ?? null;
}

export function createCredentialDataUri() {

	const renderer = credentialRendering();

	return async function dataUri(
		params: {
			credentialMetadata?: any;
			credentialIssuerMetadata?: any;
			preferredLangs?: string[];
		}
	): Promise<string | null> {
		const {
			credentialMetadata,
			credentialIssuerMetadata,
			preferredLangs = ['en-US'],
		} = params;

		// 1. Localized displays
		const credentialDisplayLocalized = matchDisplayByLocale(
			credentialMetadata?.display,
			preferredLangs
		);
		const issuerDisplayLocalized = matchDisplayByLocale(
			credentialIssuerMetadata?.display,
			preferredLangs
		);

		const svgTemplateUri =
			credentialDisplayLocalized?.rendering?.svg_templates?.[0]?.uri || null;
		const simpleDisplayConfig =
			credentialDisplayLocalized?.rendering?.simple || null;

		// 1. SVG template rendering
		if (svgTemplateUri) {
			const svgResponse = await axios.get(svgTemplateUri)
				.catch(() => null);

			if (svgResponse && svgResponse.status === 200) {
				const rendered = svgResponse.data as string;

				if (rendered) return rendered;
			}
		}

		// 2. Simple credential display
		if (simpleDisplayConfig && credentialDisplayLocalized) {
			const rendered = await renderer.renderCustomSvgTemplate({
				displayConfig: {
					...credentialDisplayLocalized,
					...simpleDisplayConfig,
				},
			})
				.catch(() => null);

			if (rendered) return rendered;
		}

		// 3. Issuer display fallback
		if (issuerDisplayLocalized) {
			const rendered = await renderer
				.renderCustomSvgTemplate({
					displayConfig: issuerDisplayLocalized,
				})
				.catch(() => null);

			if (rendered) return rendered;
		}

		// 4. Final fallback
		const rendered = await renderer
			.renderCustomSvgTemplate({
				displayConfig: { name: 'Credential' },
			})
			.catch(() => null);

		return rendered ?? null;
	};
}
