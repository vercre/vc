import { createContext, ReactNode, useCallback, useContext, useReducer } from 'react';

import { BincodeSerializer, BincodeDeserializer } from 'shared_types/bincode/mod';
import {
    CredentialConfiguration,
    CredentialView,
    Effect,
    EffectVariantHttp,
    EffectVariantRender,
    // EffectVariantDelay,
    // EffectVariantHttp,
    // EffectVariantSigner,
    EffectVariantStore,
    Event,
    HttpResponse,
    IssuanceStatusVariantInactive,
    IssuanceView,
    PresentationStatusVariantInactive,
    PresentationView,
    Request,
    StoreResponse,
    ViewModel,
    ViewVariantSplash,
} from 'shared_types/types/shared_types';
import { handle_response, process_event, view } from 'vercre-wallet/vercre_wallet';
import { request as http } from './capabilities/http';
import { store } from './capabilities/store';

type Response = HttpResponse | StoreResponse;

const initView = (): ViewModel => {
    return new ViewModel(
        new CredentialView([]),
        new IssuanceView('', new Map<string, CredentialConfiguration>(), new IssuanceStatusVariantInactive()),
        new PresentationView([], new PresentationStatusVariantInactive()),
        null,
        new ViewVariantSplash(),
    );
};

export type ViewState = {
    viewModel: ViewModel,
};

export type Action = {
    type: 'set',
    payload: ViewModel,
};

type Dispatch = (action: Action) => void;

export const ViewContext = createContext<{ state: ViewState; dispatch: Dispatch} | undefined>(undefined);

const reducer = (_state: ViewState, action: Action): ViewState => {
    return { viewModel: action.payload };
};

export type ViewProviderProps = {
    children: ReactNode,
};

export const ViewStateProvider = (props: ViewProviderProps) => {
    const { children } = props;
    const [state, dispatch] = useReducer(reducer, { viewModel: initView() });
    const value = { state, dispatch };

    return (
        <ViewContext.Provider value={value}>
            {children}
        </ViewContext.Provider>
    );
};

export const useViewState = () => {
    const context = useContext(ViewContext);
    if (!context) {
        throw new Error('useViewState must be used within a ViewStateProvider');
    }
    const { dispatch } = context;

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

    const respond = (
        uuid: number[],
        response: Response,
        dispatch: Dispatch): void => {
        const serializer = new BincodeSerializer();
        response.serialize(serializer);
    
        const effects = handle_response(new Uint8Array(uuid), serializer.getBytes());
    
        const requests = deserializeRequests(effects);
        for (const request of requests) {
            processEffect(request.uuid, request.effect, dispatch);
        }
    };    

    const processEffect = async (
        uuid: number[],
        effect: Effect,
        dispatch: Dispatch): Promise<void> => {
        console.log('processEffect', effect);
    
        switch (effect.constructor) {
            case EffectVariantRender: {
                dispatch({ type: 'set', payload: deserializeView(view())});
                break;
            }
            case EffectVariantHttp: {
                const request = (effect as EffectVariantHttp).value;
                const response = await http(request);
                respond(uuid, response, dispatch);
                break;
            }
            case EffectVariantStore: {
                const request = (effect as EffectVariantStore).value;
                const response = await store(request);
                respond(uuid, response, dispatch);
                break;
            }
        }
    };

    const update = useCallback((event: Event) => {
        console.log('update', event);

        const serializer = new BincodeSerializer();
        event.serialize(serializer);

        const effects = process_event(serializer.getBytes());

        const requests = deserializeRequests(effects);
        for (const request of requests) {
            processEffect(request.uuid, request.effect, dispatch);
        }
    }, [dispatch]);

    return {
        viewModel: context.state.viewModel,
        update,
    };
};
