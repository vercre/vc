// TODO: Combine with Issuance/Error.tsx as a shared component. (See web example).

import { useEffect, useRef } from "react";

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import Alert from '@mui/material/Alert';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import { invoke } from "@tauri-apps/api/core";

import { useShellState } from "../Shell/Context";

const Error = () => {
    const { setShellState } = useShellState();
    const initialLoad = useRef<boolean>(true);
    const theme = useTheme();

    useEffect(() => {
        if (!initialLoad.current) {
            return;
        }
        initialLoad.current = false;
        setShellState({
            title: 'Present Credential',
            action: (
                <IconButton onClick={() => invoke('cancel')} size="large">
                    <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
            secondaryAction: undefined,
        });
    }, [setShellState, theme.palette.primary.contrastText]);
    
    return (
        <Stack spacing={2} sx={{ my: 2 }}>
            <Alert severity="error">
                An error occurred. Please try again or contact the verifier.
            </Alert>
        </Stack>
    );
};

export default Error;
