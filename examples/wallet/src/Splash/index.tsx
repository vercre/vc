import { useEffect, useRef } from 'react';

import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import { invoke } from '@tauri-apps/api/core';
import { useRecoilValue } from 'recoil';

import { appState } from '../model';

const Splash = () => {
    const view = useRecoilValue(appState);
    const init = useRef<boolean>(false);

    useEffect(() => {
        if (init.current) {
            return;
        }
        init.current = true;

        if (view.started) {
            return;
        }
        setTimeout(() => {
            console.log("invoking started");
            invoke("started");
        }, 1500);
    }, [view]);

    return (
        <Container
            maxWidth={false}
            sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                backgroundColor: theme => theme.palette.primary.main,
                color: theme => theme.palette.primary.contrastText,
                height: '100vh',
                overflow: 'hidden',
            }}
        >
            <Typography variant="h1">Vercre Wallet</Typography>
        </Container>
    );
};

export default Splash;
