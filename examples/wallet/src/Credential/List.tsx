import { useEffect, useRef } from 'react';

import BadgeIcon from '@mui/icons-material/BadgeOutlined';
import Box from '@mui/material/Box';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import { useSetRecoilState } from 'recoil';

import VcCard from "./VcCard";
import { header } from "../Layout";
import { CredentialDisplay } from "../types/generated";

export type ListProps = {
    credentials: CredentialDisplay[];
    onSecondaryAction: () => void;
    onSelect: (c: CredentialDisplay) => void;
};

const List = (props: ListProps) => {
    const { credentials, onSecondaryAction, onSelect } = props;
    const theme = useTheme();
    const setHeader = useSetRecoilState(header);
    const init = useRef<boolean>(false);

    useEffect(() => {
        if (init.current) {
            return;
        }
        init.current = true;
        setHeader({
            title: 'Credentials',
            action: undefined,
            secondaryAction: (
                <IconButton onClick={onSecondaryAction} size="large">
                    <BadgeIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
        });
    }, [onSecondaryAction, setHeader, theme.palette.primary.contrastText]);

    return (
        <Box>
            {credentials.map((c, i) =>
                <Stack key={i} spacing={-2} sx={{ pt: 2 }}>
                    <VcCard credential={c} onSelect={() => onSelect(c)} />
                </Stack>
            )}
        </Box>
    );
};

export default List;