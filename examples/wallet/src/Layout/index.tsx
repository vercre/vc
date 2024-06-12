import { ReactNode } from 'react';

import { Box } from "@mui/material";
import Container from "@mui/material/Container";
import Stack from "@mui/material/Stack";
import Toolbar from '@mui/material/Toolbar';
import { atom, useRecoilValue } from 'recoil';

import Footer from './Footer';
import Header, { HeaderProps } from './Header';

export type LayoutProps = {
    children?: ReactNode;
};

export const header = atom<HeaderProps>({
    key: 'header',
    default: {
        title: 'Title',
        action: undefined,
        secondaryAction: undefined,
    },
});

const Layout = (props: LayoutProps) => {
    const { children } = props;
    const headerProps = useRecoilValue(header);
    return (
        <Stack
            sx = {{
                flexGrow: 1,
                minHeight: '100vh',
            }}            
        >
        <Header { ...headerProps } />
        <Container maxWidth="sm">
            <Box
                sx = {{
                    flexGrow: 1
                }}
            >
                <Toolbar/>
                {children}
            </Box>
        </Container>
        <Footer />
        </Stack>
    );
};

export default Layout;