import { useEffect } from 'react';

import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import { useRecoilState } from 'recoil';

import { appState } from '../model';

const Splash = () => {
    const [view, setView] = useRecoilState(appState);

    useEffect(() => {
        if (view.started) {
            return;
        }
        setTimeout(() => {
            setView({
                started: true,
                subApp: 'credential',
            });
        }, 3000);
    }, [view, setView]);

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
