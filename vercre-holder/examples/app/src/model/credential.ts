type Issuer = {
    id: string,
    extra?: object,
};

type Proof = {
    id?: string,
    type: string,
    cryptosuite?: string,
    proofPurpose: string,
    verificationMethod: string,
    created?: string,
    expires?: string,
    domain?: string[],
    challenge?: string,
    proofValue: string,
    previousProof?: string[],
    nonce?: string,
};

type CredentialStatus = {
    id: string,
    type: string,
};

type CredentialSchema = {
    id: string,
    type: string,
};

type RefreshService = {
    id: string,
    type: string,
};

type Policy = {
    assigner: string,
    assignee: string,
    target: string,
    action: string[],
}

type Term = {
    type: string,
    id: string,
    profile: string,
    obligation?: Policy[],
    prohibition?: Policy[],
    permission?: Policy[],
}

type Evidence = {
    id?: string,
    type: string[],
    verifier: string,
    evidenceDocument: string,
    subjectPresence: string,
    documentPresence: string,
}

type VerifiableCredential = {
    '@context': string[],
    id: string,
    type: string[],
    issuer: Issuer,
    issuanceDate: string,
    credentialSubject: object, // Generic map of <string, object>
    proof?: Proof[],
    expirationDate?: string,
    credentialStatus?: CredentialStatus,
    credentialSchema?: CredentialSchema[],
    refreshService?: RefreshService,
    termsOfUse?: Term[],
    evidence?: Evidence[],
};

type ProofTypesSupported = {
    proof_signing_alg_values_supported: string[],
};

type Image = {
    uri?: string,
    alt_text?: string,
}

type CredentialDisplay = {
    name: string,
    locale?: string,
    logo?: Image,
    description?: string,
    background_color?: string,
    background_image?: Image,
    text_color?: string,
};

type Display = {
    name: string,
    locale?: string,
};

type Claim = {
    mandatory?: boolean,
    value_type?: string,
    display?: Display[],
    claim_nested?: Map<string, Claim>,
};

type CredentialDefinition = {
    '@context'?: string[],
    type?: string[],
    credentialSubject?: Map<string, Claim>,
}

export type CredentialConfiguration = {
    format: string,
    scope?: string,
    crytpographic_binding_methods_supported?: string[],
    credential_signing_alg_values_supported?: string[],
    proof_types_supported?: Map<string, ProofTypesSupported>,
    display?: CredentialDisplay[],
    credential_definition: CredentialDefinition,
};

export type Logo = {
    image: string,
    mediaType: string,
};

export type Credential = {
    id: string,
    issuer: string,
    vc: VerifiableCredential,
    metadata: CredentialConfiguration,
    issued: string,
    logo?: Logo,
};

export type CredentialViewModel = {
    credentials: Credential[],
};
