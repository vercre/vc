// IMPORTANT! This example is for demonstration purposes only. Do not use browser local storage to
// store credentials in production. A secure remote service should be used which implies an
// authentication layer in the wallet which is not implemented in this simple example.
//
import { BincodeSerializer } from 'shared_types/bincode/mod';
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
    StoreEntry,
    StoreRequest,
    StoreRequestVariantAdd,
    StoreRequestVariantDelete,
    StoreRequestVariantList,
    StoreResponse,
    StoreResponseVariantErr,
    StoreResponseVariantList,
    StoreResponseVariantOk,
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

    // HACK: Store the bytes in local storage. For production call a store API.
    try {
        window.localStorage.setItem(id, JSON.stringify(value));
        return new StoreResponseVariantOk();
    } catch (err) {
        console.error('store add', err);
        return new StoreResponseVariantErr('failed to store');
    }
}

const remove = async (id: string): Promise<StoreResponse> => {
    console.log('store remove', id);

    // HACK: Delete the bytes from local storage. For production call a store API.
    try {
        window.localStorage.removeItem(id);
        return new StoreResponseVariantOk();
    } catch (err) {
        console.error('store remove', err);
        return new StoreResponseVariantErr('failed to remove');
    }
}

const list = async (): Promise<StoreResponse> => {
    console.log('store list');

    // HACK: Get all the things from local storage. For production call a store API.
    try {
        let entries: StoreEntry[] = [];
        const keys = Object.keys(window.localStorage);
        for (let i = 0; i < keys.length; i++) {
            const key = keys[i];
            const value = window.localStorage.getItem(key);
            if (value === null) {
                continue;
            }
            entries.push(new StoreEntry(JSON.parse(value)));
        }
        return new StoreResponseVariantList(entries);
    } catch (err) {
        console.error('store list', err);
        return new StoreResponseVariantErr('failed to list');
    }
};

