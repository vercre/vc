import { useEffect, useRef } from 'react';

import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from '@mui/material/styles';
import * as st from 'shared_types/types/shared_types';
import init_core from 'vercre-wallet/vercre_wallet';

import Credentials from './Credentials';
import Issuance from './Issuance';
import Presentation from './Presentation';
import Shell from './Shell';
import { ShellStateProvider } from './Shell/Context';
import { theme } from './theme';
import { useViewState } from './ViewState';

const App = () => {
    const start = useRef<boolean>(true);
    const { viewModel, update } = useViewState();

    console.log('viewModel', viewModel);

    useEffect(() => {
        if (!start.current) {
            return;
        }
        start.current = false;
        init_core().then(() => {
            update(new st.EventVariantCancel());
        });
    }, [])

    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            <ShellStateProvider>
                <Shell>
                    {viewModel.view === 'Credential' && (
                        <Credentials />
                    )}
                    {viewModel.view === 'Issuance' && (
                        <Issuance />                    
                    )}
                    {viewModel.view === 'Presentation' && (
                        <Presentation />
                    )}
                </Shell>
            </ShellStateProvider>
        </ThemeProvider>
    );
}

export default App;
