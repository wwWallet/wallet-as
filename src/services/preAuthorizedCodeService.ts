import { PreAuthorizedCodeGrant } from "wallet-common";
import config from "../config";

export interface PreAuthorizedCodeStoreItem extends PreAuthorizedCodeGrant {
	exp?: number;
	tx_value?: string | number;
    credential_configuration_ids?: string[];
    account_id?: string;
    scope?: string;
};

export async function consumePreAuthorizedCode(code: string, token?: string | number): Promise<PreAuthorizedCodeStoreItem> {

    const grantResponse = await fetch(`${config.preAuthorizedCodeApiUrl}/pre-authorized-code`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": `Bearer ${config.preAuthorizedCodeApiBearerToken}`
        },
        body: JSON.stringify({
            "pre-authorized_code": code,
            "tx_code": token
        })
    });

    if (!grantResponse.ok) {
        throw new Error("Requested pre-authorized code is invalid.");
    }

    let responseBody: unknown;
    try {
        responseBody = await grantResponse.json();
    } catch (_err) {
        throw new Error("Pre-authorized code API returned an invalid response.");
    }

    if (!responseBody || typeof responseBody !== "object") {
        throw new Error("Pre-authorized code API returned an invalid response.");
    }

    return responseBody as PreAuthorizedCodeStoreItem;

}
