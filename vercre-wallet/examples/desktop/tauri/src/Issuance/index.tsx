import { useEffect, useRef, useState } from "react";

import Box from '@mui/material/Box';
import Slide from '@mui/material/Slide';
import { useTheme } from '@mui/material/styles';
import { IssuanceView } from 'shared_types/types/shared_types';

import Accept from './Accept';
import EnterPin from './EnterPin';
import Error from './Error';
import Request from './Request';
import { useShellState } from '../Shell/Context';

export type IssuanceProps = {
    model: IssuanceView
}

export const Issuance = (props: IssuanceProps) => {
    const { model } = props;
    const [mode, setMode] = useState<'accept' | 'pin' | 'request' | 'error'>('accept');
    const { setShellState } = useShellState();
    const initialLoad = useRef<boolean>(true);
    const theme = useTheme();

    // set the default shell state
    useEffect(() => {
        if (!initialLoad.current) {
            return;
        }
        initialLoad.current = false;
        setShellState({
            title: 'Accept Credential',
            action: undefined,
            secondaryAction: undefined,
        });
    }, [setShellState]);

    // translate status to mode
    useEffect(() => {
        console.log('status', model.status);
        const status = Object(model.status);
        if (Object.prototype.hasOwnProperty.call(status, 'Failed')) {
            setMode('error');
            return;
        }
        switch (String(model.status)) {
            case 'PendingPin':
                setMode('pin');
                break;
            case 'Accepted':
            case 'Requested':
            case 'Completed':
                setMode('request');
                break;
            default:
                setMode('accept');
                break;
        }
    }, [model, theme.palette.primary.contrastText]);

    return (
        <Box sx={{ pt: 1, position: 'relative'}}>
            {mode === 'accept' &&
                <Accept model={model} />
            }
            <Slide direction="left" in={mode === 'pin'} mountOnEnter unmountOnExit>
                <Box>
                    <EnterPin />
                </Box>
            </Slide>
            {mode === 'request' &&
                <Request model={model} />
            }
            {mode === 'error' &&
                <Error />
            }
        </Box>
    );
}

export default Issuance;
