import { readFile, writeFile } from 'fs/promises';
import {
    IssuerStoreData,
    OpenidProvider,
    RelyingParty,
    SigningAlgs,
    SimpleStore,
    VcHolder,
    VcIssuer,
    buildSigner,
} from '../..';
import { resolver } from './iota-resolver';
import { testingKeys } from './keys.mock';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const file = path.resolve(__dirname, './store.test-mock');

class Store {
    create(payload: { id: string; pin: number }) {
        return { id: payload.id, pin: null } as {
            id: string;
            pin: number | null;
        };
    }
    getAll: () =>
        | { id: string; pin: number }[]
        | Promise<{ id: string; pin: number }[]>;
    getById(id: string) {
        return { id, pin: null } as { id: string; pin: number | null };
    }
    updateById: (
        id: string,
        payload: Partial<{ id: string; pin: number }>,
    ) => { id: string; pin: number } | Promise<{ id: string; pin: number }>;
    deleteById: (id: string) => Promise<{ id: string; pin: number }>;
}

const baseIssuerConfig = {
    batchCredentialEndpoint: 'http://localhost:5999/api/credentials',
    credentialEndpoint: 'http://localhost:5999/api/credential',
    credentialIssuer: 'http://localhost:5999/',
    proofTypesSupported: ['jwt'],
    cryptographicBindingMethodsSupported: ['did:key'],
    credentialSigningAlgValuesSupported: ['ES256'],
    resolver,
    tokenEndpoint: 'http://localhost:5999/token',
    store: new Store(),
    supportedCredentials: {},
};

const baseRpConfig = {
    clientId: 'tanglelabs.io',
    redirectUri: 'http://localhost:5999/api/auth',
    clientMetadata: {
        idTokenSigningAlgValuesSupported: [SigningAlgs.ES256],
        subjectSyntaxTypesSupported: ['did:iota'],
        vpFormats: {
            jwt_vc_json: {
                alg: ['EdDSA'],
            },
        },
    },
    resolver,
};

export const rp = new RelyingParty({
    ...testingKeys.rp,
    ...baseRpConfig,
});

export const op = new OpenidProvider({
    ...testingKeys.op,
    resolver,
});

const externalOpSigner = buildSigner(testingKeys.op.privKeyHex);
const externalRpSigner = buildSigner(testingKeys.rp.privKeyHex);

// @ts-ignore
export const issuer = new VcIssuer({
    ...testingKeys.rp,
    ...baseIssuerConfig,
    supportedCredentials: [
        {
            name: 'wa_driving_license',
            type: ['wa_driving_license'],
            display: [
                {
                    name: 'Washington Driving License',
                },
            ],
            format: 'jwt_vc_json',
        },
    ],
});

export const holder = new VcHolder({
    ...testingKeys.op,
});

export const externalOp = new OpenidProvider({
    did: testingKeys.op.did,
    kid: testingKeys.op.kid,
    signer: externalOpSigner,
    signingAlgorithm: SigningAlgs.ES256,
    resolver,
});

export const externalRp = new RelyingParty({
    did: testingKeys.rp.did,
    kid: testingKeys.rp.kid,
    signer: externalRpSigner,
    signingAlgorithm: SigningAlgs.ES256,
    ...baseRpConfig,
});

// @ts-ignore
export const externalIssuer = new VcIssuer({
    did: testingKeys.rp.did,
    kid: testingKeys.rp.kid,
    signer: externalRpSigner,
    signingAlgorithm: SigningAlgs.ES256,
    ...baseIssuerConfig,
});

export const externalHolder = new VcHolder({
    did: testingKeys.op.did,
    kid: testingKeys.op.kid,
    signer: externalOpSigner,
    signingAlgorithm: SigningAlgs.ES256,
});
