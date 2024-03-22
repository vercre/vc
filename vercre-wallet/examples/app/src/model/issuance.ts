import { CredentialConfiguration } from './credential';

export type IssuanceViewModel = {
    issuer: string,
    offered: Map<string, CredentialConfiguration>,
    status: string,
};
