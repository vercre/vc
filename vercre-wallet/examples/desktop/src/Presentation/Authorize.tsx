import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import Typography from "@mui/material/Typography";
import { invoke } from '@tauri-apps/api/core';
import { Credential, PresentationView } from "shared_types/types/shared_types";

import VcCard, { VcCardProps } from "../Credentials/VcCard";

export type AuthorizeProps = {
    model: PresentationView;
};

export const Authorize = (props: AuthorizeProps) => {
    const { model } = props;

    const displayProps = (credential: Credential) : VcCardProps => {
        const display = credential.metadata.display?.at(0);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: credential.issuer,
            logo: credential.logo || undefined,
            logoUrl: undefined,
            name: display?.name,
            onSelect: undefined,
            size: 'large'
        }
    };

    return (
        <Stack spacing={2} sx={{ pt: 2 }}>
            <Typography sx={{ pb: 1, textAlign: 'center' }}>
                Do you authorize presentation of the following credentials?
            </Typography>
            {model?.credentials.map((credential, index) =>
                <Box key={index} sx={{ display: 'flex', justifyContent: 'center' }}>
                    <VcCard { ...displayProps(credential) } />
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
                    onClick={() => invoke('cancel')}
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
    );
}

export default Authorize;
