import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import Typography from "@mui/material/Typography";
import { invoke } from '@tauri-apps/api/core';

import VcCard, { VcCardProps } from '../Credentials/VcCard';
import { CredentialConfiguration } from '../model/credential';
import { IssuanceViewModel } from '../model/issuance';

export type AcceptProps = {
    model: IssuanceViewModel;
};

export const Accept = (props: AcceptProps) => {
    const { model } = props;

    const displayProps = (credential: CredentialConfiguration) : VcCardProps => {
        const display = credential.display?.at(0);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: model.issuer,
            logo: undefined,
            logoUrl: display?.logo?.uri || undefined,
            name: display?.name,
            onSelect: undefined,
            size: 'large'
        };
    };

    return (
        <Stack spacing={2} sx={{ pt: 2 }}>
            <Typography sx={{ pb: 1, textAlign: 'center' }}>
                Do you accept the following credentials?
            </Typography>
            {Object.entries(model?.offered).map(([key, supported]) => (
                <Box key={key} sx={{ display: 'flex', justifyContent: 'center'}}>
                    <VcCard { ...displayProps(supported) } />
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
                    onClick={() => invoke('cancel')}
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
}

export default Accept;
