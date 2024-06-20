import { useEffect, useState } from 'react';

import Box from '@mui/material/Box';
import { invoke } from '@tauri-apps/api/core';

import Authorize from './Authorize';
import Error from '../Error';
import Loading from '../Loading';
import { PresentationView } from '../types/generated';

export type PresentationProps = {
    presentation: PresentationView;
}

const Presentation = (props: PresentationProps) => {
    const { presentation } = props;
    const [mode, setMode] = useState<'authorize' | 'error' | 'loading'>('authorize');

    // Translate status to mode
    useEffect(() => {
        const status = Object(presentation.status);
        if (Object.prototype.hasOwnProperty.call(status, 'Failed')) {
            setMode('error');
            return;
        }
        switch (String(presentation.status)) {
            case "Authorized":
            case "Completed":
                setMode('loading');
                break;
            default:
                setMode('authorize');
                break;
        }
    }, [presentation.status]);

    // Present the credentials if the user has authorized
    useEffect(() => {
        if (presentation.status === 'Authorized') {
            invoke('present');
        }
    },[presentation.status]);

    return (
        <Box sx={{ pt: 1, position: 'relative'}}>
            { mode === 'authorize' &&
                <Authorize presentation={presentation} />
            }
            { mode === 'error' &&
                <Error />
            }
            { mode === 'loading' &&
                <Loading status="uploading" />
            }
        </Box>
    )
};

export default Presentation;
