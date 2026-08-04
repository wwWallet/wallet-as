import { calculateJwkThumbprint, decodeProtectedHeader, importJWK, jwtVerify, type JWK } from 'jose';
import { errors } from 'oidc-provider';
import { consumePreAuthorizedCode, PreAuthorizedCodeStoreItem } from '../services/preAuthorizedCodeService';

export default async function preAuthorizedCodeHandler(ctx: any): Promise<void> {

	const {
		provider,
		params,
	} = ctx.oidc;

	const pre_authorized_code = params["pre-authorized_code"];
	const tx_code = params["tx_code"];

	const grant = await consumePreAuthorizedCode(pre_authorized_code, tx_code);

	if ("error" in grant) {
		console.log(`Error consuming pre-authorized code: ${grant.error_description}`);
		throw new errors.InvalidRequest(grant.error);
	}

	validatePreAuthorizedCodeGrant(grant, tx_code);

	const client = ctx.oidc.client ?? await provider.Client.find('__pre-authorized_code_client__');
	if (!client) {
		throw new errors.InvalidClient('Could not find pre-authorized_code client');
	}

	const scope = grant.scope;
	if (!scope) {
		throw new errors.InvalidGrant('Could not resolve scope from grant.');
	}

	const accountId = grant.account_id;
	if (!accountId) {
		throw new errors.AccessDenied('invalid account_id')
	}

	const dpop = await validateDpopProof(ctx);
	const token = new provider.AccessToken({
		accountId,
		client,
		scope,
		gty: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
	});

	token.setThumbprint('jkt', dpop.jkt);

	const accessToken = await token.save();

	const rt = new provider.RefreshToken({
		accountId,
		client,
		scope
	});
	rt.setThumbprint('jkt', dpop.jkt);

	const refreshToken = await rt.save();

	ctx.body = {
		access_token: accessToken,
		token_type: token.tokenType,
		expires_in: token.expiration,
		refresh_token: refreshToken,
	};

}

export async function validateDpopProof(ctx: any): Promise<{ jkt: string }> {
	const proof = ctx.get?.('DPoP') || ctx.request?.header?.dpop;
	if (typeof proof !== 'string' || proof.length === 0) {
		throw new errors.InvalidDpopProof('DPoP proof JWT not provided');
	}

	try {
		const header = decodeProtectedHeader(proof);
		const jwk = header.jwk as JWK | undefined;
		if (header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || !jwk || jwk.d) {
			throw new Error('invalid DPoP JOSE header');
		}
		const expectedHtu = new URL(ctx.oidc.urlFor('token'));
		expectedHtu.search = '';
		expectedHtu.hash = '';
		const { payload } = await jwtVerify(proof, await importJWK(jwk, 'ES256'), {
			algorithms: ['ES256'],
			typ: 'dpop+jwt',
			requiredClaims: ['iat', 'jti'],
		});
		const now = Math.floor(Date.now() / 1000);
		if (
			payload.htm !== 'POST'
			|| payload.htu !== expectedHtu.toString()
			|| typeof payload.iat !== 'number'
			|| Math.abs(now - payload.iat) > 300
			|| typeof payload.jti !== 'string'
		) {
			throw new Error('invalid DPoP claims');
		}
		const unique = await ctx.oidc.provider.ReplayDetection.unique(
			ctx.oidc.client.clientId,
			payload.jti,
			now + 300,
		);
		if (!unique) {
			throw new Error('DPoP proof replay detected');
		}
		return { jkt: await calculateJwkThumbprint(jwk) };
	} catch (err) {
		if (err instanceof errors.InvalidDpopProof) {
			throw err;
		}
		throw new errors.InvalidDpopProof('invalid DPoP proof');
	}
}

async function validatePreAuthorizedCodeGrant(grant: PreAuthorizedCodeStoreItem, txCodeReceived: string | number ) {

	if (!grant) {
		throw new errors.InvalidGrant(
			'unknown pre-authorized code',
		);
	}

	const expectedTxCodeStructure = grant?.tx_code;
	const expectedTxCodeValue = grant?.tx_value;
	const expectedExpDateMs = grant?.exp;

	if (expectedExpDateMs && expectedExpDateMs < Date.now()) {
		throw new errors.InvalidGrant(
			'pre-authorized code has expired',
		);
	}

	if (expectedTxCodeStructure) {
		if (!txCodeReceived) {
			throw new errors.InvalidRequest(
				'tx_code required',
			);
		}

		const txCodeValidationResult = String(txCodeReceived) === String(expectedTxCodeValue);

		if (txCodeValidationResult === false) {
			throw new errors.InvalidGrant(
				'invalid tx_code',
			);
		}
	}

	if (!expectedTxCodeStructure && txCodeReceived) {
		throw new errors.InvalidRequest(
			'server does not expect tx_code'
		)
	}
}
