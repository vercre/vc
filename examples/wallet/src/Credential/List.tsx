import BadgeIcon from '@mui/icons-material/BadgeOutlined';
import IconButton from '@mui/material/IconButton';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';

import VcCard from "./VcCard";
import Layout from "../Layout";
import { CredentialDisplay } from "../types/generated";

export type ListProps = {
    credentials: CredentialDisplay[];
    onSecondaryAction: () => void;
    onSelect: (c: CredentialDisplay) => void;
};

const List = (props: ListProps) => {
    const { credentials, onSecondaryAction, onSelect } = props;
    const theme = useTheme();

    return (
        <Layout headerProps={{
            title: 'Credentials',
            action: undefined,
            secondaryAction: (
                <IconButton onClick={onSecondaryAction} size="large">
                    <BadgeIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
        }}>
            {credentials.map((c, i) =>
                <Stack key={i} spacing={-2} sx={{ pt: 2 }}>
                    <VcCard credential={c} onSelect={() => onSelect(c)} />
                </Stack>
            )}
        </Layout>
    );
};

export default List;