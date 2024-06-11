import { atom } from "recoil";

import { ViewModel } from "../types/generated";

export type AppState = {
    started: boolean,
    viewModel?: ViewModel;
};

const appState = atom<AppState>({
    key: "appState",
    default: {
        started: false,
        viewModel: undefined,
    },
});

export {
    appState,
};
