// A no-render component that processes a presentation request from a deep link of the form
// https://example.com/request_uri?request_uri=<url-encoded-uri>

import { useEffect, useRef } from "react";

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import IconButton from '@mui/material/IconButton';
import { useTheme } from '@mui/material/styles';
import { useLocation, useNavigate } from 'react-router-dom';
import * as st from 'shared_types/types/shared_types';

import { useShellState } from '../Shell/Context';
import { useViewState } from "../ViewState";

const Request = () => {
    const runOnce = useRef<boolean>(false);
    const location = useLocation();
    const navigate = useNavigate();
    const theme = useTheme();
    const { setShellState } = useShellState();
    const { viewModel, update } = useViewState();

    // Process the presentation request query string
    useEffect(() => {
        if (runOnce.current) {
            return;
        }
        runOnce.current = true;
        setShellState({
            title: 'Present Credential',
            action: (
                <IconButton onClick={() => navigate('/credentials')} size="large">
                    <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
            secondaryAction: undefined,
        });

        const params = new URLSearchParams(location.search);
        const uri = params.get('request_uri');
        if (uri !== null) {
            update(new st.EventVariantPresentation(new st.PresentationEventVariantRequested(uri)));
        } else {
            update(new st.EventVariantCancel());
            navigate('credentials');
        }
    }, [location.search]);

    // Listen for changes to the view model and navigate to the main presentation sub-app.
    useEffect(() => {
        if (viewModel.view === 'Presentation') {
            navigate('presentation');
        }
    }, [viewModel.view]);

    return (<></>);
};

export default Request;