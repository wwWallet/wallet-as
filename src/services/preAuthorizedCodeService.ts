import type { PreAuthorizedCodeGrant } from "wallet-common";
import config from "../config";

export interface PreAuthorizedCodeStoreItem extends PreAuthorizedCodeGrant {
	exp?: number;
	tx_value?: string | number;
    credential_configuration_ids?: string[];
    account_id?: string;
    scope?: string;
};

export interface PreAuthorizedCodeError {
	error: string;
	error_description?: string;
}

export type ConsumePreAuthorizedCodeResult =
	| PreAuthorizedCodeStoreItem
	| PreAuthorizedCodeError;

export async function consumePreAuthorizedCode(code: string, token?: string | number): Promise<ConsumePreAuthorizedCodeResult> {

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

    if (!grantResponse) {
        throw new Error("Requested pre-authorized code is invalid.");
    }

    return grantResponse.json() as Promise<ConsumePreAuthorizedCodeResult>;

}
