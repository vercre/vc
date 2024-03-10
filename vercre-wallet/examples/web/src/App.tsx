import { useEffect, useRef, useState } from 'react';

import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from '@mui/material/styles';
import {
    EventVariantCancel,
    ViewModel,
    ViewVariantCredential,
    ViewVariantIssuance,
    ViewVariantPresentation,
} from 'shared_types/types/shared_types';
import init_core from 'vercre-wallet/vercre_wallet';

import { update, initView } from './core';
import Credentials from './Credentials';
import Shell from './Shell';
import { ShellStateProvider } from './Shell/Context';
import { theme } from './theme';

const App = () => {
    const start = useRef<boolean>(true);
    const [viewModel, setViewModel] = useState<ViewModel>(initView());

    console.log('viewModel', viewModel);

    useEffect(() => {
        if (!start.current) {
            return;
        }
        start.current = false;
        init_core().then(() => {
            update(new EventVariantCancel(), setViewModel);
        });
    }, [])

    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            <ShellStateProvider>
                <Shell>
                    {viewModel.view.constructor === ViewVariantCredential && (
                        <Credentials credentials={viewModel.credential.credentials} />
                    )}
                    {viewModel.view.constructor === ViewVariantIssuance && (
                        <div>Issuance</div>
                    
                    )}
                    {viewModel.view.constructor === ViewVariantPresentation && (
                        <div>Presentation</div>
                    )}
                </Shell>
            </ShellStateProvider>
        </ThemeProvider>
    );
}

export default App;
