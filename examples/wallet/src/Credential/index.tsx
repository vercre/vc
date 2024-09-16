import { ReactNode, useState } from 'react';

import AddIcon from '@mui/icons-material/Add';
import Box from '@mui/material/Box';
import Fab from '@mui/material/Fab';
import Slide from '@mui/material/Slide';
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
            const detail = await invoke<CredentialDetail>("select", { id: c.id });
            setSelected(detail);
            setViewMode('detail');
        } catch (e) {
            console.error(e);
        }
    };

    const handleClose = () => {
        setSelected(undefined);
        invoke("reset");
        setViewMode('list');
    };

    const handleAdd = () => {
        setSelected(undefined);
        setViewMode('add');
    };

    const handlePresent = () => {
        setSelected(undefined);
        setViewMode('present');
    };

    return (
        <Box
            sx={{
                pt: 1,
                position: 'relative',
            }}
        >
            <SlideItem direction="right" in={viewMode === 'list'}>
                <List
                    credentials={credentials}
                    onSecondaryAction={handlePresent}
                    onSelect={handleSelect}
                />
                <Fab
                    color="primary"
                    onClick={handleAdd}
                    sx={{ position: 'fixed', bottom: 56, right: 24 }}
                >
                    <AddIcon />
                </Fab>
            </SlideItem>
            <SlideItem direction="left" in={viewMode === 'detail'}>
                {selected &&
                    <Detail credential={selected} onClose={handleClose} />
                }
            </SlideItem>
            <SlideItem direction="left" in={viewMode === 'add'}>
                <Add onClose={handleClose} />
            </SlideItem>
            <SlideItem direction="left" in={viewMode === 'present'}>
                <Present onClose={handleClose} />
            </SlideItem>
        </Box>
    );
};

const SlideItem = (props: {
    children: ReactNode,
    direction: 'left' | 'right',
    in: boolean }) => {

    return (
        <Slide direction={props.direction} in={props.in} mountOnEnter unmountOnExit>
            <Box sx={{ position: 'absolute', top: 0, pt: 2 }} >
                {props.children}
            </Box>
        </Slide>
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
