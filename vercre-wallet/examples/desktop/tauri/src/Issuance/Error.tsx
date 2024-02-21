import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import { invoke } from '@tauri-apps/api/core';

const Error = () => {

    const handleReload = () => {
        invoke("clear_error");
    };

    return (
        <Stack spacing={2} sx={{ my: 2 }}>
            <Alert severity="error">
                An error occurred. Please try again or contact the credential issuer.
            </Alert>
            <Box sx={{ display: 'flex', justifyContent: 'center' }}>
                <Button
                    onClick={handleReload}
                    variant="contained"
                >
                    Reload
                </Button>
            </Box>
        </Stack>
    );
};

export default Error;