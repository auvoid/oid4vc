import { PEX } from '@sphereon/pex';
import { parseQueryStringToJson } from '../../utils/query';
import { OPOptions } from './index.types';
import * as didJWT from 'did-jwt';
import { PresentationDefinitionV2 } from '@sphereon/pex-models';
import axios from 'axios';
import { buildSigner } from '../../utils/signer';
import { Resolvable } from 'did-resolver';
import { SiopRequest } from '../index.types';
import { snakeToCamelRecursive } from '../../utils/object';
import { normalizePresentationDefinition } from '../../utils/definition';
import { SigningAlgs } from '../siop';
import qs from 'querystring';

export class OpenidProvider {
    private did: string;
    private kid: string;
    private privKeyHex: string;
    private signer: didJWT.Signer;
    private resolver: Resolvable;
    private alg: SigningAlgs;

    constructor(args: OPOptions) {
        this.did = args.did;
        this.kid = args.kid;
        this.privKeyHex = args.privKeyHex;
        this.signer = args.signer ?? buildSigner(this.privKeyHex);
        this.resolver = args.resolver;
        this.alg = args.signingAlgorithm;
    }

    async createIDTokenResponse(request: SiopRequest) {
        const jwt = await didJWT.createJWT(
            {
                aud: request.clientId,
                iat: undefined,
                sub: this.did,
                exp: Math.floor(Date.now() / 1000) + 365 * 24 * 60 * 60,
                state: request.state,
                nonce: request.nonce,
            },
            {
                issuer: this.did,
                signer: this.signer,
            },
            { alg: this.alg, kid: this.kid },
        );

        return { id_token: jwt };
    }

    async getRequestFromOffer(request: string): Promise<SiopRequest> {
        const url = new URL(request);
        const requestRaw = parseQueryStringToJson(decodeURI(url.search));

        let requestJwt: string;
        if (requestRaw.requestUri) {
            const { data } = await axios.get(requestRaw.requestUri);

            requestJwt = data;
        } else {
            requestJwt = requestRaw.request;
        }

        const requestOptions = snakeToCamelRecursive(
            await didJWT
                .verifyJWT(requestJwt, {
                    resolver: this.resolver,
                })
                .catch((e) => {
                    console.error(e);
                    throw e;
                }),
        ).payload as SiopRequest;
        return requestOptions;
    }

    private async encodeJwtVp(
        vp: Record<string, any>,
        request: SiopRequest,
    ): Promise<string> {
        const vpToken = await didJWT.createJWT(
            {
                sub: this.did,
                aud: request.clientId,
                vp: { ...vp },
                nonce: request.nonce,
            },
            { issuer: this.did, signer: this.signer },
            { alg: this.alg, kid: this.kid },
        );
        return vpToken;
    }

    private async decodeVcJwt(jwt: string) {
        const { payload } = didJWT.decodeJWT(jwt);
        return payload;
    }

    async getCredentialsFromRequest(
        request: string,
        credentials: any[],
    ): Promise<string[]> {
        const pex = new PEX();

        const requestOptions = await this.getRequestFromOffer(request);

        if (requestOptions.responseType !== 'vp_token')
            throw new Error('invalid response type');

        const selected = pex.selectFrom(
            normalizePresentationDefinition(
                requestOptions.presentationDefinition,
            ),
            credentials,
        );
        if (selected.areRequiredCredentialsPresent === 'error')
            throw new Error('credentials not found');

        return selected.verifiableCredential as string[];
    }

    async createVPTokenResponse(
        presentationDefinition: PresentationDefinitionV2,
        credentials: string[],
        request: SiopRequest,
    ) {
        const pex = new PEX();
        console.log('CREDENTIALS', credentials);
        const evaluation = pex.evaluateCredentials(
            presentationDefinition,
            credentials,
        );
        console.log(evaluation);
        if (evaluation.areRequiredCredentialsPresent === 'error')
            throw new Error('credentials are not present');
        const { presentation, presentationSubmission } = pex.presentationFrom(
            presentationDefinition,
            credentials,
            { holderDID: this.did },
        );

        const vp_token = await this.encodeJwtVp(presentation, request);
        return {
            vp_token,
            presentation_submission: JSON.stringify(presentationSubmission),
        };
    }

    async sendAuthResponse(request: string, credentials?: any[]) {
        const requestOptions = await this.getRequestFromOffer(request);
        let response: Record<string, any>;
        if (requestOptions.responseType === 'id_token') {
            response = await this.createIDTokenResponse(requestOptions);
        } else if (requestOptions.responseType === 'vp_token') {
            if (!credentials) throw new Error('credentials not passed');
            const selected = await this.getCredentialsFromRequest(
                request,
                credentials,
            );
            response = await this.createVPTokenResponse(
                normalizePresentationDefinition(
                    requestOptions.presentationDefinition,
                ),
                selected,
                requestOptions,
            );
        }
        response = {
            ...response,
            state: requestOptions.state,
        };

        console.log('SENDING RESPONSE: ', response);
        await axios
            .post(requestOptions.redirectUri, qs.stringify(response), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            })
            .catch((e) => {
                throw new Error('unable to send response');
            });

        return response;
    }
}

export * from './index.types';
