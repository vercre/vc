import {
    createContext,
    ReactNode,
    useContext,
    useEffect,
    useReducer,
    useRef,
    useState
} from 'react';

import * as bin from 'shared_types/bincode/mod';
import * as st from 'shared_types/types/shared_types';
import init_core, { handle_response, process_event, view } from 'vercre-wallet/vercre_holder';

import { request as http } from './capabilities/http';
import { signer } from './capabilities/signer';
import { store } from './capabilities/store';
import { localView, LocalViewModel } from './model';
import { CredentialConfiguration } from './model/credential';

type Response = st.HttpResponse | st.StoreResponse;

const deserializeView = (bytes: Uint8Array): st.ViewModel => {
    console.log("attempt to deserialize view", Array.from(bytes));
    const vm = st.ViewModel.deserialize(new bin.BincodeDeserializer(bytes));
    console.log("deserialised:", vm);
    return vm;
};

const deserializeRequests = (bytes: Uint8Array): st.Request[] => {
    const deserializer = new bin.BincodeDeserializer(bytes);
    const len = deserializer.deserializeLen();
    const requests: st.Request[] = [];
    for (let i = 0; i < len; i++) {
        requests.push(st.Request.deserialize(deserializer));
    }
    return requests;
};

const respond = (
    uuid: number[],
    response: Response,
    dispatch: Dispatch): void => {
    const serializer = new bin.BincodeSerializer();
    response.serialize(serializer);

    const effects = handle_response(new Uint8Array(uuid), serializer.getBytes());

    const requests = deserializeRequests(effects);
    for (const request of requests) {
        processEffect(request.uuid, request.effect, dispatch);
    }
};

const processEffect = async (
    uuid: number[],
    effect: st.Effect,
    dispatch: Dispatch): Promise<void> => {
    console.log('processEffect', effect);

    switch (effect.constructor) {
        case st.EffectVariantRender: {
            const vm = deserializeView(view());
            dispatch({ type: 'set', payload: localView(vm)});
            break;
        }
        case st.EffectVariantHttp: {
            const request = (effect as st.EffectVariantHttp).value;
            const response = await http(request);
            respond(uuid, response, dispatch);
            break;
        }
        case st.EffectVariantStore: {
            const request = (effect as st.EffectVariantStore).value;
            const response = await store(request);
            respond(uuid, response, dispatch);
            break;
        }
        case st.EffectVariantSigner: {
            const request = (effect as st.EffectVariantSigner).value;
            const response = await signer(request);
            respond(uuid, response, dispatch);
            break;
        }
        case st.EffectVariantDelay: {
            const request = (effect as st.EffectVariantDelay).value;
            break;
        }
    }
};

const processEvent = (event: st.Event, dispatch: Dispatch) => {
    const serializer = new bin.BincodeSerializer();
    event.serialize(serializer);

    const effects = process_event(serializer.getBytes());

    const requests = deserializeRequests(effects);
    for (const request of requests) {
        processEffect(request.uuid, request.effect, dispatch);
    }
};

const initView = (): LocalViewModel => {
    return {
        credential: {
            credentials: [],
        },
        issuance: {
            issuer: '',
            offered: new Map<string, CredentialConfiguration>(),
            status: '',
        },
        presentation: {
            credentials: [],
            status: '',
        },
        view: 'Splash',
    };
};

export type ViewState = {
    viewModel: LocalViewModel,
};

export type Action = {
    type: 'set',
    payload: LocalViewModel,
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
    const start = useRef<boolean>(true);
    const [ready, setReady] = useState<boolean>(false);
    const { children } = props;
    const [state, dispatch] = useReducer(reducer, { viewModel: initView() });
    const value = { state, dispatch };

    useEffect(() => {
        if (!start.current) {
            return;
        }
        start.current = false;
        const initWasm = async () => {
            await init_core();
            setReady(true);
            // Send a cancel event to the core to get the initial view.
            processEvent(new st.EventVariantCancel(), dispatch);
            console.log('wasm initialized');
        };
        initWasm().catch(console.error);
    }, [])

    return (
        <ViewContext.Provider value={value}>
            {ready && children}
        </ViewContext.Provider>
    );
};

export const useViewState = () => {
    const context = useContext(ViewContext);
    if (!context) {
        throw new Error('useViewState must be used within a ViewStateProvider');
    }
    const { dispatch } = context;

    const update = (event: st.Event) => {
        console.log('update', event);
        processEvent(event, dispatch);
    };

    return {
        viewModel: context.state.viewModel,
        update,
    };
};
