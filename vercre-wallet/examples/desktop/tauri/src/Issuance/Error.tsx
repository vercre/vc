import Alert from '@mui/material/Alert';
import Stack from '@mui/material/Stack';

const Error = () => {

    return (
        <Stack spacing={2} sx={{ my: 2 }}>
            <Alert severity="error">
                An error occurred. Please try again or contact the credential issuer.
            </Alert>
        </Stack>
    );
};

export default Error;
