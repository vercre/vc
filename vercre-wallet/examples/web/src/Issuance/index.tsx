import { useEffect, useRef, useState } from "react";

import Box from '@mui/material/Box';
import Slide from '@mui/material/Slide';

import Accept from './Accept';
import EnterPin from './EnterPin';
import Error from '../components/Error';
import RequestStatus from '../components/RequestStatus';
import { useShellState } from '../Shell/Context';
import { useViewState } from '../ViewState';

export const Issuance = () => {
    const [mode, setMode] = useState<'accept' | 'pin' | 'request' | 'error'>('accept');
    const { setShellState } = useShellState();
    const initialLoad = useRef<boolean>(true);
    const { viewModel } = useViewState();

    const model = viewModel.issuance;

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
        if (model.status.startsWith('Failed')) {
            setMode('error');
            return;
        }
        switch (model.status) {
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
    }, [model]);

    return (
        <Box sx={{ pt: 1, position: 'relative'}}>
            {mode === 'accept' &&
                <Accept />
            }
            <Slide direction="left" in={mode === 'pin'} mountOnEnter unmountOnExit>
                <Box>
                    <EnterPin />
                </Box>
            </Slide>
            {mode === 'request' &&
                <RequestStatus
                    title="Retrieving credentials..."
                    status={
                        model.status === 'Requested'
                        ? 'pending'
                        : 'complete'
                    }
                />
            }
            {mode === 'error' &&
                <Error
                    title="Accept Credential"
                    message="An error occurred. Please try again or contact the credential issuer."
                />
            }
        </Box>
    );
}

export default Issuance;
