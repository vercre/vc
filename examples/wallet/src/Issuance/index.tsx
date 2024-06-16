import { useEffect, useState } from "react";

import Box from '@mui/material/Box';
import Slide from '@mui/material/Slide';

import Accept from './Accept';
import Pin from './Pin';
import Error from '../Error';
import Request from './Request';
import { IssuanceView } from '../types/generated';

export type IssuanceProps = {
    issuance: IssuanceView
}

export const Issuance = (props: IssuanceProps) => {
    const { issuance } = props;
    const [mode, setMode] = useState<'accept' | 'pin' | 'request' | 'error'>('accept');

    // translate status to mode
    useEffect(() => {
        switch (issuance.status) {
            case 'PendingPin':
                setMode('pin');
                break;
            case 'Accepted':
            case 'Requested':
                setMode('request');
                break;
            case 'Failed':
                setMode('error');
                break;
            default:
                setMode('accept');
                break;
        }
    }, [issuance]);

    return (
        <Box sx={{ pt: 1, position: 'relative'}}>
            {mode === 'accept' &&
                <Accept issuance={issuance} />
            }
            <Slide direction="left" in={mode === 'pin'} mountOnEnter unmountOnExit>
                <Box>
                    <Pin issuance={issuance} />
                </Box>
            </Slide>
            {mode === 'request' &&
                <Request issuance={issuance} />
            }
            {mode === 'error' &&
                <Error />
            }
        </Box>
    );
}

export default Issuance;
