import { useState } from 'react';

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import DeleteForeverIcon from "@mui/icons-material/DeleteForever";
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import Typography from '@mui/material/Typography';
import { invoke } from "@tauri-apps/api/core";

import { dateFromIso, domainFromUrl } from '.';
import Delete from './Delete';
import VcCard from "./VcCard";
import Layout from '../Layout';
import { CredentialDetail } from '../types/generated';

export type DetailProps = {
    credential: CredentialDetail;
    onClose: () => void;
};

const Detail = (props: DetailProps) => {
    const { credential, onClose } = props;
    const [confirmDelete, setConfirmDelete] = useState<boolean>(false);
    const theme = useTheme();

    const handleDelete = (id?: string) => {
        setConfirmDelete(false);
        if (!id) {
            return;
        }
        invoke("delete", { id });
        onClose();
    };

    return (<Layout
            headerProps={{
                title: credential.display.name || "Credential Detail",
                action: (
                    <IconButton onClick={onClose} size="large">
                        <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                    </IconButton>
                ),
                secondaryAction: (
                    <IconButton onClick={() => setConfirmDelete(true)} size="large">
                        <DeleteForeverIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                    </IconButton>
                ),
            }}
        >
        <Stack spacing={2} sx={{ pt: 2 }}>
            <VcCard credential={credential.display} />
            <Typography variant="h5">
                Verified Info
            </Typography>
            <ClaimEntry name="Description" value={credential.description} />
            {Object.entries(credential.claims).map(([key, value]) => (
                <ClaimEntry key={key} name={value} value={value} />
            ))}
            <ClaimEntry name="Issued on" value={dateFromIso(credential.issuance_date)} />
            <ClaimEntry name="Expires on" value={
                credential.expiration_date ? dateFromIso(credential.expiration_date) : 'Never'
            } />
            <ClaimEntry name="Issued by" value={domainFromUrl(credential.display.issuer)} />
        </Stack>
        <Delete
            name={credential.display.name || 'Credential'}
            open={confirmDelete}
            onClose={() => setConfirmDelete(false)}
            onDelete={() => handleDelete(credential.display.id)}
        />
    </Layout>);
};

export default Detail;

const ClaimEntry = (props: { name: string, value?: string }) => {
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
