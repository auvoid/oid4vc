import { nanoid } from 'nanoid';
import {
    camelToSnakeCaseRecursive,
    objectToSnakeCaseQueryString,
} from '../../utils/query';
import {
    CreateCredentialOfferOptions,
    IIssuerStore,
    IssuerStoreData,
    SupportedCredentials,
    VcIssuerOptions,
    CredentialFormat,
} from './index.types';
import { generatePin } from '../../utils/pin';
import { TokenRequest } from '../Holder/index.types';
import * as didJWT from 'did-jwt';
import { buildSigner } from '../../utils/signer';
import { Resolvable } from 'did-resolver';
import { SigningAlgs } from '../../siopv2/siop';

export class VcIssuer {
    metadata: Omit<VcIssuerOptions, 'store' | 'did' | 'kid' | 'privKeyHex'>;
    store: IIssuerStore<IssuerStoreData>;
    signer: didJWT.Signer;
    did: string;
    kid: string;
    alg: SigningAlgs;
    resolver: Resolvable;

    constructor(options: VcIssuerOptions) {
        const { store, did, privKeyHex, kid, ...others } = options;
        const proofTypes = this.transformProofs(
            others.proofTypesSupported,
            others.credentialSigningAlgValuesSupported,
        );
        this.metadata = others;
        // @ts-ignore
        this.metadata.proofTypesSupported = proofTypes;
        this.store = store;
        this.signer = options.signer ?? buildSigner(options.privKeyHex);
        this.did = did;
        this.kid = kid;
        this.resolver = options.resolver;
        this.alg = options.signingAlgorithm;
    }

    transformProofs(proofs: string[], algValues: string[]) {
        const proofsMap = {};
        proofs.forEach(
            (p) =>
                // @ts-ignore
                (proofsMap[p] = {
                    proof_signing_alg_values_supported: algValues,
                }),
        );
        return proofsMap;
    }

    getIssuerMetadata(credentials: SupportedCredentials[] = []) {
        const supportedCredentialsArray = [
            ...(this.metadata.supportedCredentials ?? []),
            ...credentials,
        ];
        const credential_configurations_supported: Record<
            string,
            Record<string, any>
        > = {};
        supportedCredentialsArray.forEach(
            (cred) =>
                (credential_configurations_supported[cred.name] = {
                    format: cred.format,
                    cryptographic_binding_methods_supported:
                        this.metadata.cryptographicBindingMethodsSupported,
                    credential:
                        this.metadata.credentialSigningAlgValuesSupported,
                    proof_types_supported: this.metadata.proofTypesSupported,
                    credential_definition: {
                        type: ['VerifiableCredential', ...cred.type],
                    },
                    scope: cred.name,
                    display: cred.display,
                }),
        );
        const metadata = {
            credential_issuer: this.metadata.credentialIssuer,
            credential_endpoint: this.metadata.credentialEndpoint,
            batch_credential_endpoint: this.metadata.batchCredentialEndpoint,
            credential_configurations_supported,
        };

        if (this.metadata.clientName || this.metadata.logoUri)
            // @ts-ignore
            metadata.display = [
                {
                    locale: 'en-US',
                    logo_uri: this.metadata.logoUri,
                    client_name: this.metadata.clientName,
                },
            ];
        return metadata;
    }

    getOauthServerMetadata() {
        return {
            issuer: this.metadata.credentialIssuer,
            token_endpoint: this.metadata.tokenEndpoint,
        };
    }

    async createCredentialOffer(
        args: CreateCredentialOfferOptions,
        extras: Record<string, any> = {},
    ): Promise<{
        uri: string;
        pin?: number;
        offer: Record<string, any>;
    }> {
        // @ts-ignore
        const { credentials, requestBy, credentialOfferUri, ...options } = args;
        const pinNeeded = !!args.pinRequired;

        const id = nanoid();

        const expiresIn = args.expiresIn ?? 24 * 60 * 60;

        const code = await didJWT.createJWT(
            { id, iat: Math.floor(Date.now() / 1000), ...extras },
            {
                issuer: this.did,
                signer: this.signer,
                expiresIn,
            },
            { alg: this.alg, kid: this.kid },
        );

        const offer = camelToSnakeCaseRecursive({
            credentialIssuer: this.metadata.credentialIssuer,
            ...options,
            credentialConfigurationIds: [...credentials],
            grants: {
                'urn:ietf:params:oauth:grant-type:pre-authorized_code': {
                    'pre-authorized_code': code,
                },
            },
        });
        if (pinNeeded)
            offer.grants.tx_code = {
                length: 6,
                input_mode: 'numeric',
            };
        const pin = args.pinRequired ? generatePin() : null;
        const jsonEmbed =
            requestBy === 'value'
                ? { credential_offer: offer }
                : { credential_offer_uri: credentialOfferUri };

        await this.store.create({ id, pin });
        const uri = encodeURI(
            `openid-credential-offer://${objectToSnakeCaseQueryString({
                ...jsonEmbed,
            })}`,
        );
        return { uri, pin, offer };
    }

    async createTokenResponse(request: TokenRequest) {
        if (!request.grant_type || !request['pre-authorized_code'])
            throw new Error('invalid_request');
        const { signer, payload } = await didJWT
            .verifyJWT(request['pre-authorized_code'], {
                resolver: this.resolver,
                policies: { aud: false },
            })
            .catch((e) => {
                console.error(e);
                throw new Error('invalid_request');
            });
        const { pin } = await this.store.getById(payload.id);
        const { iat, aud, iss, ...extrasRaw } = payload;
        const extras = extrasRaw ?? {};

        if (pin && pin !== request.user_pin) throw new Error('invalid_grant');
        if (signer.controller !== this.did) throw new Error('invalid_token');
        const access_token = await didJWT.createJWT(
            {
                aud: payload.aud,
                iat: Math.floor(Date.now() / 1000),
                ...extras,
            },
            {
                issuer: this.did,
                signer: this.signer,
                expiresIn: 24 * 60 * 60,
            },
            { alg: this.alg, kid: this.kid },
        );

        return {
            access_token,
            token_type: 'bearer',
            expires_in: 86400,
            c_nonce: nanoid(),
            c_nonce_expires_in: 86400,
        };
    }

    async validateCredentialsResponse({
        token,
        proof,
    }: {
        token?: string;
        proof?: string;
    }) {
        if (!token || !proof) throw new Error('invalid_request');
        const { payload, signer } = await didJWT.verifyJWT(token, {
            policies: { aud: false },
            resolver: this.resolver,
        });
        if (
            signer.controller !== this.did ||
            payload.exp < Math.floor(Date.now() / 1000)
        )
            throw new Error('invalid_token');
        const { signer: didSigner } = await didJWT.verifyJWT(proof, {
            policies: { aud: false },
            resolver: this.resolver,
        });

        return didSigner.controller;
    }

    async createSendCredentialsResponse({
        credentials,
        format,
    }: {
        credentials: string[];
        format: CredentialFormat;
    }) {
        let response;
        if (credentials.length > 1) {
            // @ts-ignore
            response = { credential_responses: [] };
            response.credential_responses = credentials.map((credential) => ({
                format,
                credential,
            }));
        } else {
            response = {
                format: 'jwt_vc_json',
                credential: credentials[0],
            };
        }

        return response;
    }
}

export * from './index.types';
