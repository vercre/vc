import {
    Claim,
    Credential,
    CredentialConfiguration,
    CredentialDefinition,
    CredentialDisplay,
    CredentialSubject,
    Display,
    EncodedLogo,
    FormatVariantJwtVcJson,
    Image,
    ProofTypesSupported,
    StoreRequest,
    StoreRequestVariantAdd,
    StoreRequestVariantDelete,
    StoreRequestVariantList,
    StoreResponseVariantErr,
    StoreResponseVariantList,
    StoreResponse,
    VerifiableCredential,
    ValueTypeVariantnumber,
    ValueTypeVariantstring,
} from 'shared_types/types/shared_types';
import { Seq, uint8 } from 'shared_types/serde/types';

export const store = async (request: StoreRequest): Promise<StoreResponse> => {
    console.log('store', request);

    switch (request.constructor) {
        case StoreRequestVariantAdd: {
            const addRequest = request as StoreRequestVariantAdd;
            return add(addRequest.field0, addRequest.field1);
        }
        case StoreRequestVariantDelete: {
            const deleteRequest = request as StoreRequestVariantDelete;
            return remove(deleteRequest.value);
        }
        case StoreRequestVariantList: {
            return list();
        }
        default: {
            return new StoreResponseVariantErr('invalid request');
        }
    }
};

const add = async (id: string, value: Seq<uint8>): Promise<StoreResponse> => {
    console.log('store add', id, value);

    // TODO: Call the store API to add the value to the store.
    const err = new StoreResponseVariantErr('not implemented');
    return err;
}

const remove = async (id: string): Promise<StoreResponse> => {
    console.log('store remove', id);

    // TODO: Call the store API to delete the value from the store.
    const err = new StoreResponseVariantErr('not implemented');
    return err;
}

const hardCoded = (): Seq<uint8> => {
    const credentials = new Array<Credential>();

    const cs0 = new CredentialSubject(
        'did:jwk:eyJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AiLCJ1c2UiOiJlbmMiLCJ4IjoiMWRyenR0My11ckxOUTQ4ZmgzX0ZnbWxBZHF0Z3RoUHN0S0hLUzR6d0ZPYyJ9', // id
        new Map<string, string>([
            [ 'familyName', 'Person' ],
            [ 'givenName', 'Normal' ],
            [ 'proficiency', '3' ],
        ]), // claims
    );
    const vc0 = new VerifiableCredential(
        ['https://www.w3.org/2018/credentials/v1', 'http://credibil.io/credentials/v1'], // context
        'http://credibil.io/credentials/DeveloperCredential', // id
        ['VerifiableCredential', 'DeveloperCredential'], // type
        'http://credibil.io', // issuer
        '2024-02-20T04:07:51.616251Z', // issuanceDate
        cs0, // credentialSubject
        null, // proof
        null,  // expirationDate
        null, // credentialStatus
        null, // credentialSchema
        null, // refreshService
        null, // termsOfUse
        null, // evidence
    )
    const jwt_pts0 = new ProofTypesSupported([ 'ES256K', 'EdDSA' ]);
    const pts0 = new Map<string, ProofTypesSupported>();
    pts0.set('jwt', jwt_pts0);
    const display0 = new CredentialDisplay(
        'Developer', // name
        'en-NZ', // locale
        new Image('https://credibil.github.io/assets/propellerhead-logo-reversed.png', 'Propellerhead Logo'), // logo
        'Propellerhead certified developer credential', // description
        '#010100', // background_color
        null, // background_image
        '#ffffff', // text_color
    )
    const credentialDefSubject0 = new Map<string, Claim>();
    credentialDefSubject0.set('familyName', new Claim(
        true, // mandatory
        new ValueTypeVariantstring(), // value_type,
        [ new Display('Family Name', 'en-NZ')]
    ));
    credentialDefSubject0.set('givenName', new Claim(
        true, // mandatory
        new ValueTypeVariantstring(), // value_type,
        [ new Display('Given Name', 'en-NZ')]
    ));
    credentialDefSubject0.set('proficiency', new Claim(
        true, // mandatory
        new ValueTypeVariantnumber(), // value_type,
        [ new Display('Proficiency', 'en-NZ')],
    ));
    const cd0 = new CredentialDefinition(
        [ 'https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1' ], // context
        [ 'VerifiableCredential', 'DeveloperCredential' ], // type
        credentialDefSubject0, // credentialSubject
    );
    const md0 = new CredentialConfiguration(
        new FormatVariantJwtVcJson(),  // format
        'DeveloperCredential', // scope
        [ 'did:jwk', 'did:ion' ], // cryptographic_binding_methods_supported
        [ 'ES256K', 'EdDSA'], // credential_signing_alg_values_supported
        pts0, // proof_types_supported
        [ display0 ], // display
        cd0, // credential_definition
    );
    const logo0 = new EncodedLogo(
        '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',
        'image/png',
    );
    const c0 = new Credential(
        'http://credibil.io/credentials/DeveloperCredential', // id
        'http://localhost:8080', // issuer
        vc0, // vc
        md0, // metadata
        'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSNwdWJsaWNLZXlNb2RlbDFJZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6andrOmV5SmpjbllpT2lKWU1qVTFNVGtpTENKcmRIa2lPaUpQUzFBaUxDSjFjMlVpT2lKbGJtTWlMQ0o0SWpvaU1XUnllblIwTXkxMWNreE9VVFE0Wm1nelgwWm5iV3hCWkhGMFozUm9VSE4wUzBoTFV6UjZkMFpQWXlKOSIsIm5iZiI6MTcwODQwMjA3MSwiaXNzIjoiaHR0cDovL2NyZWRpYmlsLmlvIiwiaWF0IjoxNzA4NDAyMDcxLCJqdGkiOiJodHRwOi8vY3JlZGliaWwuaW8vY3JlZGVudGlhbHMvRGV2ZWxvcGVyQ3JlZGVudGlhbCIsInZjIjp7IkBjb250ZXh0IjpbImh0dHBzOi8vd3d3LnczLm9yZy8yMDE4L2NyZWRlbnRpYWxzL3YxIiwiaHR0cDovL2NyZWRpYmlsLmlvL2NyZWRlbnRpYWxzL3YxIl0sImlkIjoiaHR0cDovL2NyZWRpYmlsLmlvL2NyZWRlbnRpYWxzL0RldmVsb3BlckNyZWRlbnRpYWwiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiRGV2ZWxvcGVyQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vY3JlZGliaWwuaW8iLCJpc3N1YW5jZURhdGUiOiIyMDI0LTAyLTIwVDA0OjA3OjUxLjYxNjI1MVoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpqd2s6ZXlKamNuWWlPaUpZTWpVMU1Ua2lMQ0pyZEhraU9pSlBTMUFpTENKMWMyVWlPaUpsYm1NaUxDSjRJam9pTVdSeWVuUjBNeTExY2t4T1VUUTRabWd6WDBabmJXeEJaSEYwWjNSb1VITjBTMGhMVXpSNmQwWlBZeUo5IiwiZ2l2ZW5OYW1lIjoiTm9ybWFsIiwiZmFtaWx5TmFtZSI6IlBlcnNvbiIsInByb2ZpY2llbmN5IjoiMyJ9fX0.eWtHbx68cPc9weSpp4FMboPshZhgZjmifHHz9P7r4O8J__wBDCZgl5S1DP-WcsMRqpaLWELiHcGqNbTN62RN9Q', // issued
        logo0, // logo
    )
    credentials.push(c0);
    
    const cs1 = new CredentialSubject(
        'did:jwk:eyJjcnYiOiJYMjU1MTkiLCJrdHkiOiJPS1AiLCJ1c2UiOiJlbmMiLCJ4IjoiMWRyenR0My11ckxOUTQ4ZmgzX0ZnbWxBZHF0Z3RoUHN0S0hLUzR6d0ZPYyJ9', // id
        new Map<string, string>([
            [ 'email',  'normal.user@example.com' ],
            [ 'familyName',  'Person' ],
            [ 'givenName',  'Normal' ],
        ]), // claims
    )
    const vc1 = new VerifiableCredential(
        ['https://www.w3.org/2018/credentials/v1', 'http://credibil.io/credentials/v1'], // context
        'http://credibil.io/credentials/EmployeeIDCredential', // id
        ['VerifiableCredential', 'DeveloperCredential'], // type
        'http://credibil.io', // issuer
        '2024-02-22T22:26:02.205718Z', // issuanceDate
        cs1, // credentialSubject
        null, // proof
        null,  // expirationDate
        null, // credentialStatus
        null, // credentialSchema
        null, // refreshService
        null, // termsOfUse
        null, // evidence
    );
    const jwt_pts1 = new ProofTypesSupported([ 'ES256K', 'EdDSA' ]);
    const pts1 = new Map<string, ProofTypesSupported>();
    pts1.set('jwt', jwt_pts1);
    const display1 = new CredentialDisplay(
        'Employee ID', // name
        'en-NZ', // locale
        new Image('https://credibil.github.io/assets/credibil-logo-reversed.png', 'Credibil Logo'), // logo
        'Credibil employee ID credential', // description
        '#323ed2', // background_color
        new Image('https://credibil.github.io/assets/credibil-background.png', 'Credibil Background'), // background_image
        '#ffffff', // text_color
    )
    const credentialDefSubject1 = new Map<string, Claim>();
    credentialDefSubject0.set('email', new Claim(
        true, // mandatory
        new ValueTypeVariantstring(), // value_type,
        [ new Display('Email', 'en-NZ')]
    ));
    credentialDefSubject0.set('familyName', new Claim(
        true, // mandatory
        new ValueTypeVariantstring(), // value_type,
        [ new Display('Family Name', 'en-NZ')]
    ));
    credentialDefSubject1.set('givenName', new Claim(
        true, // mandatory
        new ValueTypeVariantstring(), // value_type,
        [ new Display('Given Name', 'en-NZ')]
    ));
    const cd1 = new CredentialDefinition(
        [ 'https://www.w3.org/2018/credentials/v1', 'https://www.w3.org/2018/credentials/examples/v1' ], // context
        [ 'VerifiableCredential', 'EmployeeIDCredential' ], // type
        credentialDefSubject1, // credentialSubject
    );
    const md1 = new CredentialConfiguration(
        new FormatVariantJwtVcJson(), // format
        'EmployeeIDCredential', // scope
        [ 'did:jwk', 'did:ion' ], // cryptographic_binding_methods_supported
        [ 'ES256K', 'EdDSA'], // credential_signing_alg_values_supported
        pts1, // proof_types_supported
        [ display1 ], // display
        cd1, // credential_definition
    )
    const logo1 = new EncodedLogo(
        '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', // image
        'image/png', // media_type
    );
    const c1 = new Credential(
        'http://credibil.io/credentials/EmployeeIDCredential', // id
        'http://localhost:8080', // issuer
        vc1, // vc
        md1, // metadata
        'eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aW9uOkVpRHlPUWJiWkFhM2FpUnplQ2tWN0xPeDNTRVJqakg5M0VYb0lNM1VvTjRvV2c6ZXlKa1pXeDBZU0k2ZXlKd1lYUmphR1Z6SWpwYmV5SmhZM1JwYjI0aU9pSnlaWEJzWVdObElpd2laRzlqZFcxbGJuUWlPbnNpY0hWaWJHbGpTMlY1Y3lJNlczc2lhV1FpT2lKd2RXSnNhV05MWlhsTmIyUmxiREZKWkNJc0luQjFZbXhwWTB0bGVVcDNheUk2ZXlKamNuWWlPaUp6WldOd01qVTJhekVpTENKcmRIa2lPaUpGUXlJc0luZ2lPaUowV0ZOTFFsOXlkV0pZVXpkelEycFljWFZ3VmtwRmVsUmpWek5OYzJwdFJYWnhNVmx3V0c0NU5scG5JaXdpZVNJNkltUlBhV05ZY1dKcVJuaHZSMG90U3pBdFIwb3hhMGhaU25GcFkxOUVYMDlOZFZWM2ExRTNUMncyYm1zaWZTd2ljSFZ5Y0c5elpYTWlPbHNpWVhWMGFHVnVkR2xqWVhScGIyNGlMQ0pyWlhsQlozSmxaVzFsYm5RaVhTd2lkSGx3WlNJNklrVmpaSE5oVTJWamNESTFObXN4Vm1WeWFXWnBZMkYwYVc5dVMyVjVNakF4T1NKOVhTd2ljMlZ5ZG1salpYTWlPbHQ3SW1sa0lqb2ljMlZ5ZG1salpURkpaQ0lzSW5ObGNuWnBZMlZGYm1Sd2IybHVkQ0k2SW1oMGRIQTZMeTkzZDNjdWMyVnlkbWxqWlRFdVkyOXRJaXdpZEhsd1pTSTZJbk5sY25acFkyVXhWSGx3WlNKOVhYMTlYU3dpZFhCa1lYUmxRMjl0YldsMGJXVnVkQ0k2SWtWcFJFdEphM2R4VHpZNVNWQkhNM0JQYkVoclpHSTRObTVaZERCaFRuaFRTRnAxTW5JdFltaEZlbTVxWkVFaWZTd2ljM1ZtWm1sNFJHRjBZU0k2ZXlKa1pXeDBZVWhoYzJnaU9pSkZhVU5tUkZkU2JsbHNZMFE1UlVkQk0yUmZOVm94UVVoMUxXbFpjVTFpU2psdVptbHhaSG8xVXpoV1JHSm5JaXdpY21WamIzWmxjbmxEYjIxdGFYUnRaVzUwSWpvaVJXbENaazlhWkUxMFZUWlBRbmM0VUdzNE56bFJkRm90TWtvdE9VWmlZbXBUV25sdllVRmZZbkZFTkhwb1FTSjlmUSNwdWJsaWNLZXlNb2RlbDFJZCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJkaWQ6andrOmV5SmpjbllpT2lKWU1qVTFNVGtpTENKcmRIa2lPaUpQUzFBaUxDSjFjMlVpT2lKbGJtTWlMQ0o0SWpvaU1XUnllblIwTXkxMWNreE9VVFE0Wm1nelgwWm5iV3hCWkhGMFozUm9VSE4wUzBoTFV6UjZkMFpQWXlKOSIsIm5iZiI6MTcwODY0MDc2MiwiaXNzIjoiaHR0cDovL2NyZWRpYmlsLmlvIiwiaWF0IjoxNzA4NjQwNzYyLCJqdGkiOiJodHRwOi8vY3JlZGliaWwuaW8vY3JlZGVudGlhbHMvRW1wbG95ZWVJRENyZWRlbnRpYWwiLCJ2YyI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHA6Ly9jcmVkaWJpbC5pby9jcmVkZW50aWFscy92MSJdLCJpZCI6Imh0dHA6Ly9jcmVkaWJpbC5pby9jcmVkZW50aWFscy9FbXBsb3llZUlEQ3JlZGVudGlhbCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJFbXBsb3llZUlEQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOiJodHRwOi8vY3JlZGliaWwuaW8iLCJpc3N1YW5jZURhdGUiOiIyMDI0LTAyLTIyVDIyOjI2OjAyLjIwNTcxOFoiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpqd2s6ZXlKamNuWWlPaUpZTWpVMU1Ua2lMQ0pyZEhraU9pSlBTMUFpTENKMWMyVWlPaUpsYm1NaUxDSjRJam9pTVdSeWVuUjBNeTExY2t4T1VUUTRabWd6WDBabmJXeEJaSEYwWjNSb1VITjBTMGhMVXpSNmQwWlBZeUo5IiwiZmFtaWx5TmFtZSI6IlBlcnNvbiIsImVtYWlsIjoibm9ybWFsLnVzZXJAZXhhbXBsZS5jb20iLCJnaXZlbk5hbWUiOiJOb3JtYWwifX19.jnp1U8pVsxAcaeny5IV_WJgqRlQBI-myswLkIxt7OV0fp97oChfrWlZ-vYL6iGdboku9w2afQiyahsmTxw3Zwg', // issued
        logo1, // logo
    );
    credentials.push(c1);

    let bytes: number[] = JSON.parse(JSON.stringify(credentials));
    return bytes;
};

const list = async (): Promise<StoreResponse> => {
    console.log('store list');

    // TODO: Call the store API to list the values in the store.

    // This is a hard-coded response for now.
    const list = hardCoded();
    return new StoreResponseVariantList(list);
};

