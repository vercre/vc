import { useEffect, useRef, useState } from 'react';

import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from "@mui/material/styles";
import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';

import Credential from './Credential';
import Layout from './Layout';
import Splash from './Splash';
import { theme } from "./theme";
import { ViewModel } from './types/generated';

const App = () => {
    const [view, setView] = useState<ViewModel | undefined>(undefined);
    const init = useRef<boolean>(false);

    // register listener for Tauri events
    useEffect(() => {
        if (init.current) {
            return;
        }
        init.current = true;
        
        let unlisten: UnlistenFn;
        const statusListener = async () => {
            unlisten = await listen<ViewModel>("state_updated", ({ payload }) => {
                const model = payload as ViewModel;
                console.log("state_updated", model);
                setView(model);
            });
        }
        statusListener();

        return () => {
            unlisten?.();
        };
    }, [setView]);

    // Invoke start if view is not set
    useEffect(() => {
        if (!view) {
            console.log("invoking start");
            invoke("start");
        }
    }, [view])

    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            {view?.sub_app === "Splash"
                ? <Splash />
                : <Layout>
                {view?.sub_app === "Credential" && <Credential model={view.credential}  /> }
                </Layout>
            }
        </ThemeProvider>
    );
}

export default App
