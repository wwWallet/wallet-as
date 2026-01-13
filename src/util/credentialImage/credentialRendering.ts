import axios from "axios";
import type { AxiosInstance } from "axios";
import { escapeSVG } from "./escapeSVG";

export type CredentialRendering = {
	renderCustomSvgTemplate: ({ displayConfig }: { displayConfig: any }) => Promise<string>;
};

export function credentialRendering(args?: {
	axiosInstance?: AxiosInstance;
}): CredentialRendering {
	const ax = args?.axiosInstance ?? axios;

	const defaultBackgroundColor = "#D3D3D3";
	const defaultTextColor = "#000000";
	const defaultName = "Credential";

	const svgTemplate =
		`<svg
			xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"
			width="829" height="504" version="1.1">
			<rect width="100%" height="100%" fill="{{backgroundColor}}" />
			{{backgroundImageBase64}}
			{{logoBase64}}
			<text x="50" y="80" font-family="Arial, Helvetica, sans-serif"
				font-size="35" fill="{{textColor}}">{{name}}</text>
			<text x="50" y="120" font-family="Arial, Helvetica, sans-serif"
				font-size="20" fill="{{textColor}}">{{description}}</text>
		</svg>`;

	function isDataUri(s?: string | null): s is string {
		return typeof s === "string" && s.startsWith("data:");
	}

	async function getBase64DataUri(url: string): Promise<string | null> {
		if (!url) return null;
		if (isDataUri(url)) return url;

		try {
			const res = await ax.get<ArrayBuffer>(url, { responseType: "arraybuffer" });

			const contentType =
				(res.headers?.["content-type"] as string | undefined) ||
				"application/octet-stream";

			let base64: string;

			if (typeof Buffer !== "undefined") {
				base64 = Buffer.from(res.data as any).toString("base64");
			} else {
				const bytes = new Uint8Array(res.data);
				let binary = "";
				for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
				base64 = btoa(binary);
			}

			return `data:${contentType};base64,${base64}`;
		} catch (e) {
			console.error("Failed to load image", url, e);
			return null;
		}
	}

	async function renderCustomSvgTemplate({ displayConfig }: { displayConfig: any }): Promise<string> {
		const name = displayConfig?.name ? escapeSVG(displayConfig.name) : defaultName;
		const description = displayConfig?.description
			? escapeSVG(displayConfig.description)
			: "";

		const backgroundColor =
			displayConfig?.background_color || defaultBackgroundColor;
		const textColor = displayConfig?.text_color || defaultTextColor;

		const bgUri = displayConfig?.background_image?.uri as string | undefined;
		const logoUri = displayConfig?.logo?.uri as string | undefined;

		const backgroundImageBase64 = bgUri ? await getBase64DataUri(bgUri) : null;
		const logoBase64 = logoUri ? await getBase64DataUri(logoUri) : null;

		const replacedSvgText = svgTemplate
			.replace(/{{backgroundColor}}/g, backgroundColor)
			.replace(
				/{{backgroundImageBase64}}/g,
				backgroundImageBase64
					? `<image xlink:href="${backgroundImageBase64}" x="0" y="0" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" />`
					: ""
			)
			.replace(
				/{{logoBase64}}/g,
				logoBase64
					? `<image xlink:href="${logoBase64}" x="50" y="380" height="20%"><title>${escapeSVG(displayConfig?.logoAltText || "Logo")}</title></image>`
					: ""
			)
			.replace(/{{name}}/g, name)
			.replace(/{{textColor}}/g, textColor)
			.replace(/{{description}}/g, description);

		return `data:image/svg+xml;utf8,${encodeURIComponent(replacedSvgText)}`;
	}

	return { renderCustomSvgTemplate };
}
