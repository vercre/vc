import { useEffect, useRef, useState } from 'react';

import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from "@mui/material/styles";
import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';

import Credential from './Credential';
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

    invoke("start");

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
  }, [setView, view]);

  return (
    <ThemeProvider theme={theme}>
        <CssBaseline />
          {view?.sub_app === "Splash" && <Splash />}
          {view?.sub_app === "Credential" && <Credential model={view.credential}  />}
    </ThemeProvider>
  );
}

export default App
