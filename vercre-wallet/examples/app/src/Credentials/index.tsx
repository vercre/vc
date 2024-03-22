import { useEffect, useMemo, useRef, useState } from "react";

import AddIcon from '@mui/icons-material/Add';
import BadgeIcon from '@mui/icons-material/BadgeOutlined';
import Box from '@mui/material/Box';
import Fab from '@mui/material/Fab';
import IconButton from '@mui/material/IconButton';
import Slide from '@mui/material/Slide';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import { invoke } from "@tauri-apps/api/core";

import Add from './Add';
import Detail from './Detail';
import Present from './Present';
import VcCard, { VcCardProps } from './VcCard';
import { Credential, CredentialViewModel } from '../model/credential';
import { useShellState } from '../Shell/Context';

export type CredentialsProps = {
    model: CredentialViewModel | undefined;
}

export const Credentials = (props: CredentialsProps) => {
    const credentials = props.model?.credentials || [];
    const [selected, setSelected] = useState<Credential | undefined>(undefined);
    const [viewMode, setViewMode] = useState<'list' | 'detail' | 'add' | 'present'>('list');
    const { setShellState } = useShellState();
    const initialLoad = useRef<boolean>(true);
    const theme = useTheme();

    const listShellState = useMemo(() => ({
        title: 'Credentials',
        action: undefined,
        secondaryAction: (
            <IconButton onClick={() => setViewMode('present')} size="large">
                <BadgeIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
            </IconButton>
        ),
    }), [theme.palette.primary.contrastText]);

    useEffect(() => {
        if (!initialLoad.current) {
            return;
        }
        initialLoad.current = false;
        setShellState({...listShellState});
        invoke("get_list", { filter: "" });
    }, [listShellState, setShellState]);

    const handleSelect = (c: Credential) => {
        setSelected(c);
        setViewMode('detail');
    };

    const handleClose = () => {
        setSelected(undefined);
        setViewMode('list');
        setShellState({...listShellState});
    };

    const handleAdd = () => {
        setSelected(undefined);
        setViewMode('add');
    };

    const displayProps = (credential: Credential) : VcCardProps => {
        const locale = navigator.language; // TODO: use user preference from settings
        const display = credential.metadata.display?.find(d => d.locale === locale);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: credential.issuer,
            logo: credential.logo || undefined,
            logoUrl: undefined,
            name: display?.name || 'Credential',
            onSelect: () => handleSelect(credential),
            size: 'large'
        }
    };

    return (
        <Box
            sx={{
                pt: 1,
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
                    {credentials?.map((credential, index) =>
                        <Stack key={index} spacing={-2} sx={{ pt: 2 }}>
                            <VcCard key={index} { ...displayProps(credential) } />
                        </Stack>
                    )}
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
}

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

export default Credentials;
