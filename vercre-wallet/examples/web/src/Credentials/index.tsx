import { useEffect, useMemo, useRef, useState } from "react";

import AddIcon from '@mui/icons-material/Add';
import BadgeIcon from '@mui/icons-material/BadgeOutlined';
import Box from '@mui/material/Box';
import Fab from '@mui/material/Fab';
import IconButton from '@mui/material/IconButton';
import Slide from '@mui/material/Slide';
import Stack from '@mui/material/Stack';
import { useTheme } from '@mui/material/styles';
import { Credential } from 'shared_types/types/shared_types';

// import Add from './Add';
// import Detail from './Detail';
// import List from './List';
// import Present from './Present';
import VcCard, { VcCardProps } from './VcCard';
import { useShellState } from '../Shell/Context';

export type CredentialsProps = {
    credentials: Credential[] | undefined;
}

const Credentials = (props: CredentialsProps) => {
    const { credentials } = props;

    console.log(credentials?.length);
    return(
        <Box>
            {credentials?.map((c, i) => (
                <div key={i}>{i}</div>
            ))}
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

export default Credentials;