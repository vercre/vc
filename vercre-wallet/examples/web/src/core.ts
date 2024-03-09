// These functions provide the interface between Crux and the React shell.
import { Dispatch, SetStateAction } from 'react';

import { BincodeSerializer, BincodeDeserializer } from 'shared_types/bincode/mod';
import {
    Effect,
    EffectVariantHttp,
    EffectVariantRender,
    // EffectVariantDelay,
    // EffectVariantHttp,
    // EffectVariantSigner,
    EffectVariantStore,
    Event,
    HttpResponse,
    Request,
    StoreResponse,
    ViewModel
} from 'shared_types/types/shared_types';
import { handle_response, process_event, view } from 'vercre-wallet';
import { request as http } from './capabilities/http';
import { store } from './capabilities/store';

type Response = HttpResponse | StoreResponse;

export const update = (event: Event, callback: Dispatch<SetStateAction<ViewModel>>): void => {
    console.log('update', event);

    const serializer = new BincodeSerializer();
    event.serialize(serializer);

    const effects = process_event(serializer.getBytes());

    const requests = deserializeRequests(effects);
    for (const request of requests) {
        processEffect(request.uuid, request.effect, callback);
    }
};

const processEffect = async (
    uuid: number[],
    effect: Effect,
    callback: Dispatch<SetStateAction<ViewModel>>): Promise<void> => {
    console.log('processEffect', effect);

    switch (effect.constructor) {
        case EffectVariantRender: {
            callback(deserializeView(view()));
            break;
        }
        case EffectVariantHttp: {
            const request = (effect as EffectVariantHttp).value;
            const response = await http(request);
            respond(uuid, response, callback);
            break;
        }
        case EffectVariantStore: {
            const request = (effect as EffectVariantStore).value;
            const response = await store(request);
            respond(uuid, response, callback);
            break;
        }
    }
};

const respond = (
    uuid: number[],
    response: Response,
    callback: Dispatch<SetStateAction<ViewModel>>): void => {
    const serializer = new BincodeSerializer();
    response.serialize(serializer);

    const effects = handle_response(new Uint8Array(uuid), serializer.getBytes());

    const requests = deserializeRequests(effects);
    for (const request of requests) {
        processEffect(request.uuid, request.effect, callback);
    }
};

const deserializeRequests = (bytes: Uint8Array): Request[] => {
    const deserializer = new BincodeDeserializer(bytes);
    const len = deserializer.deserializeLen();
    const requests: Request[] = [];
    for (let i = 0; i < len; i++) {
        requests.push(Request.deserialize(deserializer));
    }
    return requests;
};

const deserializeView = (bytes: Uint8Array): ViewModel => {
    return ViewModel.deserialize(new BincodeDeserializer(bytes));
};
