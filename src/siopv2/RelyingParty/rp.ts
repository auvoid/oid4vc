import { objectToSnakeCaseQueryString } from '../../utils/query';
import {
    CreateRequestOptions,
    RPOptions,
    AuthResponse,
    SiopRequestResult,
    SigningAlgs,
} from './index.types';
import * as didJWT from 'did-jwt';
import { PEX } from '@sphereon/pex';
import { PresentationDefinitionV2 } from '@sphereon/pex-models';
import { buildSigner } from '../../utils/signer';
import { Resolvable } from 'did-resolver';
import { camelToSnakeRecursive } from '../../utils/object';
import { nanoid } from 'nanoid';
import { normalizePresentationDefinition } from '../../utils/definition';

export class RelyingParty {
    private metadata: RPOptions;
    private did: string;
    private kid: string;
    private privKeyHex: string;
    private signer: didJWT.Signer;
    private resolver: Resolvable;
    private alg: SigningAlgs;

    /**
     * Create a new instance of the Relying Party class
     *
     * @param {RPOptions} args
     */

    constructor(args: RPOptions) {
        this.metadata = args;
        this.did = args.did;
        this.kid = args.kid;
        this.privKeyHex = args.privKeyHex;
        this.signer = args.signer ?? buildSigner(this.privKeyHex);
        this.resolver = args.resolver;
        this.alg = args.signingAlgorithm;
    }

    /**
     * Create a new SIOP Request
     */

    async createRequest(
        args: CreateRequestOptions,
    ): Promise<SiopRequestResult> {
        const { requestBy, ...requestOptions } = args;
        const { privKeyHex, did, kid, ...metadata } = this.metadata;
        const requestData = {
            ...requestOptions,
            ...metadata,
            clientMetadata: {
                ...metadata.clientMetadata,
                ...args.clientMetadata,
            },
            scope: 'openid',
            responseMode: 'post',
        };

        const nonce = nanoid();
        const { clientId, ...rest } = requestData;

        const requestParams = camelToSnakeRecursive({
            ...rest,
            clientId,
            nonce,
        });
        let requestQuery: {
            clientId: string;
            request?: string;
            requestUri?: string;
        } = {
            clientId,
        };

        const request = await didJWT.createJWT(
            { ...requestParams },
            { issuer: this.did, signer: this.signer },
            { kid: this.kid, alg: this.alg },
        );

        requestBy === 'value'
            ? (requestQuery.request = request)
            : (requestQuery.requestUri = args.requestUri);

        return {
            uri: encodeURI(
                `siopv2://idtoken${objectToSnakeCaseQueryString(requestQuery)}`,
            ) as `siopv2://idtoken${string}`,
            request: request,
            requestOptions: requestParams,
        };
    }

    async validateJwt(jwt: string): Promise<Record<string, any>> {
        const result = await didJWT.verifyJWT(jwt, {
            resolver: this.resolver,
            policies: {
                aud: false,
            },
        });
        if (!result.verified) throw new Error('Invalid JWT');
        return result.payload;
    }

    async verifyAuthResponse(
        authResponse: AuthResponse,
        presentationDefinition?: PresentationDefinitionV2,
    ) {
        if (
            !(
                authResponse.id_token ||
                (authResponse.vp_token && authResponse.presentation_submission)
            )
        )
            throw new Error('Bad response');
        if (authResponse.id_token) {
            await this.validateJwt(authResponse.id_token);
            return;
        } else if (
            authResponse.vp_token &&
            authResponse.presentation_submission
        ) {
            const pex = new PEX();
            const result = pex.evaluatePresentation(
                normalizePresentationDefinition(presentationDefinition),
                authResponse.vp_token,
                {
                    generatePresentationSubmission: true,
                },
            );

            if (result.areRequiredCredentialsPresent === 'error')
                throw new Error('Invalid Credentials Shared');
        }
    }

    async createAuthToken(did: string) {
        const token = await didJWT.createJWT(
            {
                aud: did,
                exp: Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60,
                iat: Math.floor(Date.now() / 1000),
                iss: this.did,
            },
            { issuer: this.did, signer: this.signer },
            { alg: this.alg, kid: this.kid },
        );
        return token;
    }
}

export * from './index.types';
