import { Resolvable } from "did-resolver";
import { KeyPairRequirements } from "../../common/index.types";

type CryptographicSuites = "EdDSA" | "ES256";
type ProofTypes = "jwt";

export type SupportedCredentials = {
    name: string;
    type: string[];
    display?: {
        name?: string;
        locale?: string;
        logo?: {
            uri: string;
            alt_text?: string;
        };
    }[];
    raw?: Record<string, any>;
};

export type VcIssuerOptions = {
    credentialEndpoint: string;
    tokenEndpoint: string;
    batchCredentialEndpoint: string;
    credentialIssuer: string;
    cryptographicBindingMethodsSupported: string[];
    credentialSigningAlgValuesSupported: CryptographicSuites[];
    proofTypesSupported: ProofTypes[];
    store: IIssuerStore<IssuerStoreData>;
    logoUri?: string;
    clientName?: string;
    supportedCredentials?: SupportedCredentials[];
    resolver: Resolvable;
} & KeyPairRequirements;

export type IssuerStoreData = { id: string; pin: number };

type CreateCredentialOfferByValue = {
    requestBy: "value";
    credentials: string[];
    pinRequired?: boolean;
    expiresIn?: number;
};

type CreateCredentialOfferByReference = {
    requestBy: "reference";
    credentialOfferUri: string;
    credentials: string[];
    pinRequired?: boolean;
    expiresIn?: number;
};

export type CreateCredentialOfferOptions =
    | CreateCredentialOfferByReference
    | CreateCredentialOfferByValue;

export interface IIssuerStore<T> {
    create: (payload: T) => Promise<T> | T;
    getAll: () => Promise<T[]> | T[];
    getById: (id: string) => Promise<T> | T;
    updateById: (id: string, payload: Partial<T>) => Promise<T> | T;
    deleteById: (id: string) => Promise<T>;
}
