import { JSX } from 'react';

import { Box } from '@mui/material';
import AppBar from '@mui/material/AppBar';
import Toolbar from '@mui/material/Toolbar';
import Typography from '@mui/material/Typography';

import BrandIcon from './BrandIcon';

export type HeaderProps = {
    action?: JSX.Element;
    secondaryAction?: JSX.Element;
    title?: string;
};

const Header = (props: HeaderProps) => {
    const { action, secondaryAction, title } = props;
    return (
        <AppBar
            elevation={0}
            position="fixed"
            sx = {{
                backgroundColor: theme => theme.palette.primary.main,
            }}
        >
            <Toolbar>
                {action || <BrandIcon fontSize="large" /> }
                <Typography variant="h4" sx={{ px: 3 }}>{title}</Typography>
                <Box sx={{ flexGrow: 1 }} />
                {secondaryAction}
            </Toolbar>
        </AppBar>
    );
};

export default Header;
