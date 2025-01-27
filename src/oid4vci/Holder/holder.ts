import axios from 'axios';
import { parseQueryStringToJson } from '../../utils/query';
import { CreateTokenRequestOptions } from './index.types';
import { KeyPairRequirements } from '../../common/index.types';
import * as didJWT from 'did-jwt';
import { buildSigner, snakeToCamelRecursive } from '../../utils/utils';
import { joinUrls } from '../../utils/url';
import qs from 'querystring';

export class VcHolder {
    private holderKeys: KeyPairRequirements;
    private signer: didJWT.Signer;

    constructor(args: KeyPairRequirements) {
        this.holderKeys = args;
        this.signer = args.signer ?? buildSigner(args.privKeyHex);
    }

    async createTokenRequest(args: CreateTokenRequestOptions) {
        const response = {
            grant_type: 'urn:ietf:params:oauth:grant-type:pre-authorized_code',
            'pre-authorized_code': args.preAuthCode,
        };
        // @ts-ignore
        if (args.userPin) response.user_pin = args.userPin;
        return response;
    }

    async parseCredentialOffer(offer: string): Promise<Record<string, any>> {
        const decodedUri = decodeURI(offer);
        const search = new URL(decodedUri).search;
        const rawOffer = parseQueryStringToJson(search);
        let credentialOffer;
        if (rawOffer.credentialOfferUri) {
            const { data } = await axios.get(rawOffer.credentialOfferUri);
            credentialOffer = snakeToCamelRecursive(data);
        } else {
            credentialOffer = snakeToCamelRecursive(rawOffer.credentialOffer);
        }

        return credentialOffer;
    }

    async retrieveMetadata(credentialOffer: string) {
        const offerRaw = await this.parseCredentialOffer(credentialOffer);
        const metadataEndpoint = joinUrls(
            offerRaw.credentialIssuer,
            '.well-known/openid-credential-issuer',
        );
        const oauthMetadataUrl = joinUrls(
            offerRaw.credentialIssuer,
            '.well-known/oauth-authorization-server',
        );
        const { data } = await axios.get(metadataEndpoint);
        const { data: oauthServerMetadata } = await axios.get(oauthMetadataUrl);
        const metadata = {
            ...snakeToCamelRecursive(data),
            ...snakeToCamelRecursive(oauthServerMetadata),
        };

        const display =
            metadata.display &&
            metadata.display.find((d: any) => d.locale === 'en-US');
        metadata.display = display;

        return metadata;
    }

    constructPayload(
        credentials: string[],
        conf: Record<string, any>,
        proof: string,
    ) {
        let payload;
        if (credentials.length > 1) {
            payload = {
                credential_requests: [
                    ...credentials.map((c) => {
                        const format = conf[c].format;
                        let p: Record<string, any> = {
                            format,
                            proof: {
                                proof_type: 'jwt',
                                jwt: proof,
                            },
                            credential_definition:
                                conf[c].credential_definition,
                        };
                        if (format === 'vc+sd-jwt') p.vct = conf[c].vct;
                        return p;
                    }),
                ],
            };
        } else {
            payload = {
                format: conf[credentials[0]].format,
                credential_definition:
                    conf[credentials[0]].credential_definition,
                proof: {
                    proof_type: 'jwt',
                    jwt: proof,
                },
            };
        }
        return payload;
    }

    async retrieveCredential(
        path: string,
        accessToken: string,
        credentials: string[],
        proof: string,
        conf: Record<string, any> = null,
    ): Promise<string[]> {
        const payload = this.constructPayload(credentials, conf, proof);

        const { data } = await axios.post(path, payload, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
            },
        });
        const response =
            Object.keys(credentials).length > 1
                ? data.credential_responses.map(
                      (c: { format: string; credential: string }) =>
                          c.credential,
                  )
                : [data.credential];
        return response;
    }

    private checkArrayOverlap(items: string[], haystack: string[]) {
        return items.every((i) => haystack.includes(i));
    }

    async getCredentialFromOffer(credentialOffer: string, pin?: number) {
        const offer = await this.parseCredentialOffer(credentialOffer);
        const { grants, credentialIssuer, credentialConfigurationIds } = offer;
        const metadata = await this.retrieveMetadata(credentialOffer);

        const credentialConfigsExist = this.checkArrayOverlap(
            credentialConfigurationIds,
            Object.keys(metadata.credentialConfigurationsSupported),
        );

        if (!credentialConfigsExist)
            throw new Error('unsupported_credential_type');

        const createTokenPayload: { preAuthCode: any; userPin?: number } = {
            preAuthCode:
                grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
                    'pre-authorized_code'
                ],
        };

        if (
            grants['urn:ietf:params:oauth:grant-type:pre-authorized_code'][
                'user_pin_required'
            ]
        )
            createTokenPayload.userPin = Number(pin);

        const tokenRequest = await this.createTokenRequest(createTokenPayload);

        const tokenResponse = await axios.post(
            metadata.tokenEndpoint,
            qs.stringify(tokenRequest),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
            },
        );

        const token = await didJWT.createJWT(
            {
                aud: credentialIssuer,
                nonce: tokenResponse.data.c_nonce,
            },
            { signer: this.signer, issuer: this.holderKeys.did },
            { alg: this.holderKeys.signingAlgorithm, kid: this.holderKeys.kid },
        );

        const endpoint =
            Object.keys(credentialConfigurationIds).length > 1
                ? metadata.batchCredentialEndpoint
                : metadata.credentialEndpoint;

        return this.retrieveCredential(
            endpoint,
            tokenResponse.data.access_token,
            credentialConfigurationIds,
            token,
            metadata.credentialConfigurationsSupported,
        );
    }
}

export * from './index.types';
