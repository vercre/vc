import { useState } from 'react';

import AddIcon from '@mui/icons-material/Add';
import Box from '@mui/material/Box';
import Fab from '@mui/material/Fab';
import Slide from '@mui/material/Slide';
import Stack from '@mui/material/Stack';
import { invoke } from "@tauri-apps/api/core";

import Add from './Add';
import Detail from './Detail';
import List from './List';
import Present from './Present';
import { CredentialDetail, CredentialDisplay, CredentialView } from '../types/generated';

export type CredentialProps = {
    model: CredentialView | undefined;
}

const Credential = (props: CredentialProps) => {
    const credentials = props.model?.credentials || [];
    const [selected, setSelected] = useState<CredentialDetail | undefined>(undefined);
    const [viewMode, setViewMode] = useState<'list' | 'detail' | 'add' | 'present'>('list');

    const handleSelect = async (c: CredentialDisplay) => {
        try {
            const detail = await invoke<CredentialDetail>("select_credential", { id: c.id });
            setSelected(detail);
            setViewMode('detail');
        } catch (e) {
            console.error(e);
        }
    };

    const handleClose = () => {
        setSelected(undefined);
        setViewMode('list');
    };

    const handleAdd = () => {
        setSelected(undefined);
        setViewMode('add');
    };

    return (
        <Box
            sx={{
                position: 'relative',
            }}
        >
            <Slide direction="right" in={viewMode === 'list'} mountOnEnter unmountOnExit>
                <Stack
                    spacing={-16}
                    sx={{
                        position: 'absolute',
                        top: 0,
                        pt: 2,
                    }}
                >
                    <List
                        credentials={credentials}
                        onSecondaryAction={handleAdd}
                        onSelect={handleSelect}
                    />
                    <Fab
                        color="primary"
                        onClick={handleAdd}
                        sx={{ position: 'fixed', bottom: 56, right: 24 }}
                    >
                        <AddIcon />
                    </Fab>
                </Stack>
            </Slide>
            <Slide direction="left" in={viewMode === 'detail'} mountOnEnter unmountOnExit>
                <Box
                    sx={{
                        position: 'absolute',
                        top: 0,
                        pt: 2,
                    }}
                >
                    {selected &&
                        <Detail credential={selected} onClose={handleClose} />
                    }
                </Box>
            </Slide>
            <Slide direction="left" in={viewMode === 'add'} mountOnEnter unmountOnExit>
                <Box
                    sx={{
                        position: 'absolute',
                        top: 0,
                        pt: 2,
                    }}
                >
                    <Add onClose={handleClose} />
                </Box>
            </Slide>
            <Slide direction="left" in={viewMode === 'present'} mountOnEnter unmountOnExit>
                <Box
                    sx={{
                        position: 'absolute',
                        top: 0,
                        pt: 2,
                    }}
                >
                    <Present onClose={handleClose} />
                </Box>
            </Slide>
        </Box>
    );
};

export const domainFromUrl = (url: string | undefined): string => {
    if (!url) {
        return '';
    }
    const match = url.match(/:\/\/(.[^/]+)/);
    return match ? match[1] : url;
};

export const dateFromIso = (iso: string | undefined): string => {
    if (!iso) {
        return '';
    }
    const date = new Date(iso);
    return date.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });
}

export default Credential;
