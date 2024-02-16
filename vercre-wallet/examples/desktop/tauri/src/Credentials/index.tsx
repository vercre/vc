import { useEffect, useState, useRef } from "react";

// import AddIcon from '@mui/icons-material/Add';
import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import DeleteForeverIcon from "@mui/icons-material/DeleteForever";
import Box from '@mui/material/Box';
// import Fab from '@mui/material/Fab';
import IconButton from '@mui/material/IconButton';
import Slide from '@mui/material/Slide';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import { invoke } from "@tauri-apps/api/core";
import { Credential } from "shared_types/types/shared_types";

import VcCard, { VcCardProps } from "./VcCard";
import VcDelete from "./VcDelete";
import VcDetail from "./VcDetail";
import { useShellState } from "../Shell/Context";

export type CredentialsProps = {
    credentials: Credential[] | undefined;
    onAdd?: () => void;
}

export const Credentials = (props: CredentialsProps) => {
    const { credentials } = props;
    const [selected, setSelected] = useState<Credential | undefined>(undefined);
    const [confirmDelete, setConfirmDelete] = useState<boolean>(false);
    const [showDetail, setShowDetail] = useState<boolean>(false);
    const { setShellState } = useShellState();
    const initialLoad = useRef<boolean>(true);
    const theme = useTheme();

    useEffect(() => {
        if (!initialLoad.current) {
            return;
        }
        initialLoad.current = false;
        setShellState({
            title: "Credentials",
            action: undefined,
            secondaryAction: undefined,
        });
    }, [setShellState]);

    useEffect(() => {
        invoke("get_list", { filter: "" });
    }, []);

    const handleSelect = (c: Credential) => {
        setSelected(c);
        setShowDetail(true);
        setShellState({
            title: c.metadata.display?.at(0)?.name || "Credential Detail",
            action: (
                <IconButton onClick={handleClose} size="large">
                    <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
            secondaryAction: (
                <IconButton onClick={handleConfirmDelete} size="large">
                    <DeleteForeverIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
        })
    };

    const handleClose = () => {
        setShowDetail(false);
        setShellState({
            title: "Credentials",
            action: undefined,
            secondaryAction: undefined,
        })
    };

    const handleConfirmDelete = () => {
        setConfirmDelete(true);
    };

    const handleDelete = (id?: string) => {
        setConfirmDelete(false);
        if (!id) {
            return;
        }
        invoke("delete", { id });
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
            <Slide direction="right" in={!showDetail} mountOnEnter unmountOnExit>
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
                    {/* <Fab
                        color="primary"
                        onClick={props.onAdd}
                        sx={{ position: 'fixed', bottom: 56, right: 24 }}
                    >
                        <AddIcon />
                    </Fab> */}
                </Stack>
            </Slide>
            <Slide direction="left" in={showDetail} mountOnEnter unmountOnExit>
                <Box
                    sx={{
                        position: 'absolute',
                        top: 0,
                        pt: 2,
                    }}
                >
                    {selected &&
                        <VcDetail credential={selected} />
                    }
                </Box>
            </Slide>
            <VcDelete
                name={selected ? displayProps(selected).name : 'Credential'}
                open={confirmDelete}
                onClose={() => setConfirmDelete(false)}
                onDelete={() => handleDelete(selected?.id)}
            />
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
