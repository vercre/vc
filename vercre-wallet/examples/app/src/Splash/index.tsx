import Container from "@mui/material/Container";

import LogoLockup from './LogoLockup';
import Watermark from './Watermark';

const Splash = () => {
    return (
        <Container
            maxWidth={false}
            sx={{
                backgroundColor: theme => theme.palette.primary.main,
                height: '100vh',
                overflow: 'hidden',
            }}
        >
            <LogoLockup />
            <Watermark />
        </Container>
    );
};

export default Splash;
