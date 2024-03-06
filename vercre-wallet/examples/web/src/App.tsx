import { useEffect, useRef } from 'react';

import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from '@mui/material/styles';

import { theme } from './theme';
import init_core from 'vercre-wallet';

const App = () => {
    const start = useRef<boolean>(true);

    // register listener for Crux render events
    useEffect(() => {
        if (!start.current) {
            return;
        }
        start.current = false;
    }, [])

    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            <div>Hello</div>
        </ThemeProvider>
    );
}

export default App;
