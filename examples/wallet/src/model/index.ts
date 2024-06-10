import { atom } from "recoil";

import { ViewModel } from "../types/generated";

export type AppState = {
    started: boolean,
    subApp: "credential" | "issuance" | "presentation" | "splash",
    viewModel?: ViewModel;
};

const appState = atom<AppState>({
    key: "appState",
    default: {
        started: false,
        subApp: "splash",
        viewModel: undefined,
    },
});

export {
    appState,
};
