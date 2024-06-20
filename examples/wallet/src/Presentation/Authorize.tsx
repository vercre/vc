import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import Typography from "@mui/material/Typography";
import { invoke } from '@tauri-apps/api/core';

import VcCard from '../Credential/VcCard';
import { PresentationView } from '../types/generated';

export type AuthorizeProps = {
    presentation: PresentationView;
};

const Authorize = (props: AuthorizeProps) => {
    const { presentation } = props;

    const cred = Object.entries(presentation.credentials).length > 1 ? 'credentials' : 'credential';

    return (
        <Stack spacing={2} sx={{ pt: 2 }}>
            <Typography sx={{ pb: 1, textAlign: 'center' }}>
                {`Do you authorize presentation of the following ${cred}?`}
            </Typography>
            {Object.entries(presentation.credentials).map(([key, credential]) =>
                <Box key={key} sx={{ display: 'flex', justifyContent: 'center' }}>
                    <VcCard credential={credential} />
                </Box>
            )}
            <Box
                sx={{
                    display: 'flex',
                    my: 2,
                    justifyContent: 'center',
                    gap: 4
                }}
            >
                <Button
                    onClick={() => invoke('reset')}
                    variant="outlined"
                >
                    Cancel
                </Button>
                <Button
                    onClick={() => invoke('authorize')}
                    variant="contained"
                >
                    Authorize
                </Button>
            </Box>
        </Stack>
    )
};

export default Authorize;
