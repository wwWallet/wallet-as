import crypto from 'node:crypto';
import { calculateJwkThumbprint, EmbeddedJWK, jwtVerify, type JWK } from 'jose';
import { errors } from 'oidc-provider';
import { consumePreAuthorizedCode, PreAuthorizedCodeStoreItem } from '../services/preAuthorizedCodeService';
import config from '../config';

const PRE_AUTHORIZED_CODE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
const DPOP_SIGNING_ALG_VALUES = ['ES256'];
const DPOP_PROOF_MAX_AGE_SECONDS = 300;

export default async function preAuthorizedCodeHandler(ctx: any) {

	const {
		provider,
		params,
	} = ctx.oidc;

	validateTokenRequestParams(params);

	const pre_authorized_code = params["pre-authorized_code"] as string;
	const tx_code = params["tx_code"] as string | undefined;

	let grant: PreAuthorizedCodeStoreItem;
	try {
		grant = await consumePreAuthorizedCode(pre_authorized_code, tx_code);
	} catch (err) {
		console.log(`Error consuming pre-authorized code: ${err instanceof Error ? err.message : err}`);
		throw new errors.InvalidGrant('invalid pre-authorized code');
	}

	if((grant as any).error) {
		console.log(`Error consuming pre-authorized code: ${(grant as any).error_description}`);
		throw new errors.InvalidGrant((grant as any).error);
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
	validateScope(scope);

	const accountId = grant.account_id;
	if (!accountId) {
		throw new errors.AccessDenied('invalid account_id')
	}

	const dpop = await validateDpopProof(ctx, client.clientId);

	const token = new provider.AccessToken({
		accountId,
		client,
		scope,
		gty: PRE_AUTHORIZED_CODE_GRANT_TYPE,
	});

	token.setThumbprint('jkt', dpop.thumbprint);

	const accessToken = await token.save();

	ctx.body = {
		access_token: accessToken,
		token_type: 'DPoP',
		expires_in: token.expiration,
	};

}

function validateTokenRequestParams(params: Record<string, unknown>) {
	if (params.grant_type !== PRE_AUTHORIZED_CODE_GRANT_TYPE) {
		throw new errors.InvalidGrant('unsupported grant_type');
	}

	if (typeof params["pre-authorized_code"] !== 'string' || params["pre-authorized_code"].trim() === '') {
		throw new errors.InvalidRequest('pre-authorized_code required');
	}

	if (params.tx_code !== undefined && typeof params.tx_code !== 'string') {
		throw new errors.InvalidRequest('tx_code must be a string');
	}
}

function validateScope(scope: string) {
	const requestedScopes = scope.split(' ').filter(Boolean);
	if (requestedScopes.length === 0) {
		throw new errors.InvalidGrant('Could not resolve scope from grant.');
	}

	for (const requestedScope of requestedScopes) {
		if (!config.scopes.includes(requestedScope)) {
			throw new errors.InvalidScope('Scope is not supported', requestedScope);
		}
	}
}

async function validateDpopProof(ctx: any, clientId: string): Promise<{ thumbprint: string; jti: string; }> {
	const proof = ctx.get('DPoP');
	if (!proof) {
		throw new errors.InvalidGrant('DPoP proof JWT not provided');
	}

	try {
		const { protectedHeader, payload } = await jwtVerify(proof, EmbeddedJWK, {
			algorithms: DPOP_SIGNING_ALG_VALUES,
			typ: 'dpop+jwt',
		});

		if (typeof payload.iat !== 'number' || !payload.iat) {
			throw new errors.InvalidDpopProof('DPoP proof must have a iat number property');
		}

		const nowSeconds = Math.floor(Date.now() / 1000);
		if (Math.abs(nowSeconds - payload.iat) > DPOP_PROOF_MAX_AGE_SECONDS) {
			throw new errors.InvalidDpopProof('DPoP proof iat is not recent enough');
		}

		if (typeof payload.jti !== 'string' || !payload.jti) {
			throw new errors.InvalidDpopProof('DPoP proof must have a jti string property');
		}

		if (payload.htm !== ctx.method) {
			throw new errors.InvalidDpopProof('DPoP proof htm mismatch');
		}

		const expectedHtu = new URL(ctx.oidc.urlFor(ctx.oidc.route)).href;
		const actualHtu = typeof payload.htu === 'string' ? new URL(payload.htu) : null;
		if (!actualHtu) {
			throw new errors.InvalidDpopProof('DPoP proof htu must be a string');
		}
		actualHtu.hash = '';
		actualHtu.search = '';
		if (actualHtu.href !== expectedHtu) {
			throw new errors.InvalidDpopProof('DPoP proof htu mismatch');
		}

		const jwk = protectedHeader.jwk as JWK | undefined;
		if (!jwk) {
			throw new errors.InvalidDpopProof('DPoP proof must include a public jwk header');
		}

		if ('d' in jwk || 'k' in jwk) {
			throw new errors.InvalidDpopProof('DPoP proof jwk must not contain private or symmetric key material');
		}

		const unique = await ctx.oidc.provider.ReplayDetection.unique(
			clientId,
			payload.jti,
			nowSeconds + DPOP_PROOF_MAX_AGE_SECONDS,
		);
		if (!unique) {
			throw new errors.InvalidGrant('DPoP proof JWT Replay detected');
		}

		return {
			thumbprint: await calculateJwkThumbprint(jwk),
			jti: payload.jti,
		};
	} catch (err) {
		if (err instanceof errors.InvalidDpopProof || err instanceof errors.InvalidGrant) {
			throw err;
		}

		throw new errors.InvalidDpopProof(
			'invalid DPoP key binding',
			err instanceof Error ? err.message : undefined,
		);
	}
}

async function validatePreAuthorizedCodeGrant(grant: PreAuthorizedCodeStoreItem, txCodeReceived?: string | number ) {

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
		if (txCodeReceived === undefined || txCodeReceived === null) {
			throw new errors.InvalidRequest(
				'tx_code required',
			);
		}

		validateTxCodeShape(expectedTxCodeStructure, txCodeReceived);

		const txCodeValidationResult = constantTimeEqual(String(txCodeReceived), String(expectedTxCodeValue));

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

function constantTimeEqual(received: string, expected: string) {
	const receivedBuffer = Buffer.from(received);
	const expectedBuffer = Buffer.from(expected);

	if (receivedBuffer.length !== expectedBuffer.length) {
		return false;
	}

	return crypto.timingSafeEqual(receivedBuffer, expectedBuffer);
}

function validateTxCodeShape(txCodeStructure: PreAuthorizedCodeStoreItem['tx_code'], txCodeReceived: string | number) {
	if (!txCodeStructure || typeof txCodeStructure !== 'object') {
		return;
	}

	const txCode = String(txCodeReceived);

	if (txCodeStructure.length !== undefined && txCode.length !== txCodeStructure.length) {
		throw new errors.InvalidGrant('invalid tx_code');
	}

	if (txCodeStructure.input_mode === 'numeric' && !/^[0-9]+$/.test(txCode)) {
		throw new errors.InvalidGrant('invalid tx_code');
	}
}
