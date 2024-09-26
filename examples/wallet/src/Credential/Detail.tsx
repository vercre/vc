import { useEffect, useRef, useState } from 'react';

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import DeleteForeverIcon from "@mui/icons-material/DeleteForever";
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import Typography from '@mui/material/Typography';
import { invoke } from "@tauri-apps/api/core";
import { useSetRecoilState } from 'recoil';

import { dateFromIso, domainFromUrl } from '.';
import Delete from './Delete';
import VcCard from "./VcCard";
import { header } from '../Layout';
import { CredentialDetail } from '../types/generated';

export type DetailProps = {
    credential: CredentialDetail;
    onClose: () => void;
};

const Detail = (props: DetailProps) => {
    const { credential, onClose } = props;
    const [confirmDelete, setConfirmDelete] = useState<boolean>(false);
    const theme = useTheme();
    const setHeader = useSetRecoilState(header);
    const init = useRef<boolean>(false);

    useEffect(() => {
        if (init.current) {
            return;
        }
        init.current = true;
        setHeader({
            title: credential.display.name || "Credential Detail",
            action: (
                <IconButton onClick={onClose} size="large">
                    <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText }} />
                </IconButton>
            ),
            secondaryAction: (
                <IconButton onClick={() => setConfirmDelete(true)} size="large">
                    <DeleteForeverIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText }} />
                </IconButton>
            ),
        });
    }, [credential.display.name, onClose, setHeader, theme.palette.primary.contrastText]);

    const handleDelete = (id?: string) => {
        setConfirmDelete(false);
        if (!id) {
            return;
        }
        invoke("delete", { id });
        onClose();
    };

    return (<>
        <Stack spacing={2} sx={{ pt: 2 }}>
            <VcCard credential={credential.display} />
            <Typography variant="h5">
                Verified Info
            </Typography>
            <ClaimDefinition name="Description" value={credential.description} />
            {Object.entries(credential.claims).map(([key, value]) => (
                <ClaimDefinition key={key} name={value} value={value} />
            ))}
            <ClaimDefinition name="Issued on" value={dateFromIso(credential.issuance_date)} />
            <ClaimDefinition name="Expires on" value={
                credential.expiration_date ? dateFromIso(credential.expiration_date) : 'Never'
            } />
            <ClaimDefinition name="Issued by" value={domainFromUrl(credential.display.issuer)} />
        </Stack>
        <Delete
            name={credential.display.name || 'Credential'}
            open={confirmDelete}
            onClose={() => setConfirmDelete(false)}
            onDelete={() => handleDelete(credential.display.id)}
        />
    </>);
};

export default Detail;

const ClaimDefinition = (props: { name: string, value?: string }) => {
    return (<>
        {props.name === 'id' ? null :
            <Box>
                <Typography variant="caption">
                    {props.name}
                </Typography>
                <Typography variant="body1">
                    {props.value}
                </Typography>
            </Box>
        }
    </>);
};
