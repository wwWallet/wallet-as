import { calculateJwkThumbprint } from 'jose';
import { consumePreAuthorizedCode, PreAuthorizedCodeStoreItem } from './services/preAuthorizedCodeService';
import config from './config';
import { OpenidCredentialIssuerMetadata, prependToPath } from 'wallet-common';

export default async function preAuthorizedCodeHandler(ctx: any) {

	const {
		provider,
		params,
	} = ctx.oidc;

	const pre_authorized_code = params["pre-authorized_code"];
	const tx_code = params["tx_code"];

	const grant = await consumePreAuthorizedCode(pre_authorized_code, tx_code);

	if (!grant) {
		throw new provider.errors.InvalidGrant(
			'unknown pre-authorized code',
		);
	}

	if (grant.exp && grant.exp < Date.now()) {
		throw new provider.errors.InvalidGrant(
			'pre-authorized code has expired',
		);
	}

	if (grant.tx_code) {
		if (!tx_code) {
			throw new provider.errors.InvalidRequest(
				'tx_code required',
			);
		}

		const txCodeValidationResult = String(tx_code) === String(grant.tx_value);

		if (txCodeValidationResult === false) {
			throw new provider.errors.InvalidGrant(
				'invalid tx_code',
			);
		}
	}

	if (!grant.tx_code && tx_code) {
		throw new provider.errors.InvalidRequest(
			'server does not expect tx_code'
		)
	}

	const client = await provider.Client.find('__pre-authorized_code_client__');
	if (!client) {
		throw new Error('invalid client');
	}

	const scope = await getScopeFromGrant(grant);

	const accountId = grant.account_id;
	if (!accountId) {
		throw new Error('invalid account')
	}

	const token = new provider.AccessToken({
		accountId,
		client,
		scope,
		gty: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
	});

	const { jwk } = decodeHeader(ctx.request.header.dpop);
	const jkt = await calculateJwkThumbprint(jwk);
	token.setThumbprint('jkt', jkt);

	const accessToken = await token.save();

	let refreshToken;
	if (grant.allow_refresh_token) {
		const rt = new provider.RefreshToken({
			accountId,
			client,
			scope
		});

		refreshToken = await rt.save();
	}

	ctx.body = {
		access_token: accessToken,
		token_type: 'Bearer',
		expires_in: token.expiration,
		...(refreshToken && {
			refresh_token: refreshToken,
		}),
	};

}

function decodeHeader(jwt: string) {
	const [header] = jwt.split('.');
	return JSON.parse(
		Buffer.from(header, 'base64url').toString('utf8')
	);
}

async function mapCredentialConfigurationIdToScope(credential_configuration_id: string) {

	try {

		const credentialIssuerMetadataUrl = prependToPath(config.trustedIssuers[0], '.well-known/openid-credential-issuer') ?? "";

		const issuerMetadataResponse = await fetch(credentialIssuerMetadataUrl, {
			method: "GET",
			headers: {
				"Accept": "application/json"
			}
		});

		const issuerMetadata: OpenidCredentialIssuerMetadata = await issuerMetadataResponse.json();

		return issuerMetadata.credential_configurations_supported[credential_configuration_id].scope;
	} catch (error) {
		console.log('error fetching scope: ', error);
		return "";
	}
}

async function getScopeFromGrant(grant: PreAuthorizedCodeStoreItem) {
	const credential_configuration_id = grant.credential_configuration_ids ? grant.credential_configuration_ids[0] : "";
	const scopeFromCredentialConfigurationId = await mapCredentialConfigurationIdToScope(credential_configuration_id);
	return scopeFromCredentialConfigurationId;
}