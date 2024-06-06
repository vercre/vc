import { atom } from "recoil";

export type AppState = {
    started: boolean,
    subApp: "credential" | "issuance" | "presentation" | "splash",
};

const appState = atom<AppState>({
    key: "appState",
    default: {
        started: false,
        subApp: "splash",
    },
});

export {
    appState,
};
