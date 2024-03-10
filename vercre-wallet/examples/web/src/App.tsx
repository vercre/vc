import { useEffect, useRef, useState } from 'react';

import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from '@mui/material/styles';
import {
    EventVariantCancel,
    ViewModel,
} from 'shared_types/types/shared_types';
import init_core from 'vercre-wallet/vercre_wallet';

import { update, initView } from './core';
import { theme } from './theme';

const App = () => {
    const start = useRef<boolean>(true);
    const [viewModel, setViewModel] = useState<ViewModel>(initView());

    console.log('viewModel', viewModel);

    // register listener for Crux render events
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
                <div>Credential</div>
        </ThemeProvider>
    );
}

export default App;
