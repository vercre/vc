import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import Typography from "@mui/material/Typography";
import { invoke } from '@tauri-apps/api/core';

import VcCard from '../Credential/VcCard';
import { IssuanceView } from '../types/generated';

export type AcceptProps = {
    issuance: IssuanceView;
};

const Accept = (props: AcceptProps) => {
    const { issuance } = props;

    return (
        <Stack spacing={2} sx={{ pt: 2 }}>
            <Typography sx={{ pb: 1, textAlign: 'center' }}>
                Do you accept the following credentials?
            </Typography>
            {Object.entries(issuance?.credentials).map(([key, credential]) => (
                <Box key={key} sx={{ display: 'flex', justifyContent: 'center'}}>
                    <VcCard credential={credential} />
                </Box>
            ))}
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
                    onClick={() => invoke('accept')}
                    variant="contained"
                >
                    Accept
                </Button>
            </Box>
        </Stack>
    );
};

export default Accept;
