import { ReactNode, useEffect, useRef, useState } from "react";

import CssBaseline from "@mui/material/CssBaseline";
import { ThemeProvider } from "@mui/material/styles";
import { invoke } from "@tauri-apps/api/core";
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { ViewModel } from "shared_types/types/shared_types";

import Credentials from "./Credentials";
import Issuance from "./Issuance";
import { LocalViewModel, localView } from "./model";
import Presentation from "./Presentation";
import Shell from './Shell';
import { ShellStateProvider } from './Shell/Context';
import Splash from "./Splash";
import { theme } from "./theme";

const App = () => {
    const [viewModel, setViewModel] = useState<LocalViewModel>();
    const start = useRef<boolean>(true);

    // register listener for Crux render events
    useEffect(() => {
        if (!start.current) {
            return;
        }
        start.current = false;
        invoke("start");

        let unlisten: UnlistenFn;
        const init = async () => {
            unlisten = await listen<ViewModel>("render", ({ payload }) => {
                setViewModel(localView(payload));
            });
        }
        init();

        return () => {
            unlisten?.();
        };
    }, []);

    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            <ShellStateProvider>
                {String(viewModel?.view) === 'Splash'
                    ? <Splash />
                    : <Shell>
                        {view(viewModel)}
                    </Shell>
                }
            </ShellStateProvider>
        </ThemeProvider>
    );
}

export default App;

const view = (viewModel: LocalViewModel | undefined): ReactNode => {
    const viewName = viewModel?.view || "Credential";

    switch (viewName) {
        case "Issuance":
            if (viewModel?.issuance) {
                return <Issuance model={viewModel?.issuance} />
            }
            break;
        case "Presentation":
            if (viewModel?.presentation) {
                return <Presentation model={viewModel?.presentation} />
            }
            break;
    }
    return <Credentials model={viewModel?.credential} />
};

