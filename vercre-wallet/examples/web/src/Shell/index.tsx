import { useEffect  } from "react";

import { Box } from "@mui/material";
import Container from "@mui/material/Container";
import Stack from "@mui/material/Stack";
import Toolbar from '@mui/material/Toolbar';
import { Outlet, useNavigate, useLocation } from 'react-router-dom';

import Footer from './Footer';
import Header from './Header';
import { useViewState } from '../ViewState';

const Shell = () => {
    const location = useLocation();
    const navigate = useNavigate();
    const { viewModel, update } = useViewState();

    // Redirect to the correct sub-app based on the view model. Bypass any special handling
    // for linking.
    useEffect(() => {
        if ([
            '/credential_offer',
            '/request_uri',
            '/credentials',
            '/issuance',
            '/presentation',
        ].includes(location.pathname)) {
            return;
        }
        if (viewModel.view === 'Credential') {
            navigate('credentials');
        } else if (viewModel.view === 'Issuance') {
            navigate('issuance');
        } else if (viewModel.view === 'Presentation') {
            navigate('presentation');
        }
    }, [viewModel.view, location.pathname]);
  
    return (
        <Stack
            sx = {{
                flexGrow: 1,
                minHeight: '100vh',
            }}            
        >
        <Header />
        <Container maxWidth="sm">
            <Box
                sx = {{
                    flexGrow: 1
                }}
            >
                <Toolbar/>
                <Outlet />
            </Box>
        </Container>
        <Footer />
        </Stack>
    );
};

export default Shell;
