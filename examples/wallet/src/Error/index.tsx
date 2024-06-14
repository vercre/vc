import { useEffect, useRef } from 'react';

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import Alert from '@mui/material/Alert';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import Typography from '@mui/material/Typography';
import { invoke } from "@tauri-apps/api/core";
import { useSetRecoilState } from 'recoil';

import { header } from "../Layout";

export type ErrorProps = {
    message?: string;
};

const Error = (props: ErrorProps) => {
    const { message } = props;
    const theme = useTheme();
    const setHeader = useSetRecoilState(header);
    const init = useRef<boolean>(false);

    useEffect(() => {
        if (init.current) {
            return;
        }
        init.current = true;
        setHeader({
            title: 'Error',
            action: (
                <IconButton onClick={() => invoke('reset')} size="large">
                    <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
            secondaryAction: undefined,
        });
    }, [setHeader, theme.palette.primary.contrastText]);

    return (
        <Stack spacing={2} sx={{ my: 2 }}>
            <Alert severity="error">
                <Typography>An error occurred. Please try again or contact the service provider.</Typography>
                <Typography>{message}</Typography>
            </Alert>
        </Stack>
    );
};

export default Error;
