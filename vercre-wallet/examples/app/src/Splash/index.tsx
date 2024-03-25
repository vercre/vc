import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';

const Splash = () => {
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
