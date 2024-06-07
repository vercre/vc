// A no-render component that processes a credential offer from a deep link of the form
// https://example.com/credential_offer?credential_offer=<url-encoded-json-string>

import { useEffect, useRef } from "react";

import ArrowBackIosIcon from '@mui/icons-material/ArrowBackIos';
import IconButton from '@mui/material/IconButton';
import { useTheme } from '@mui/material/styles';
import { useLocation, useNavigate } from 'react-router-dom';
import * as st from 'shared_types/types/shared_types';

import { useShellState } from '../Shell/Context';
import { useViewState } from "../ViewState";

const Offer = () => {
    const runOnce = useRef<boolean>(false);
    const location = useLocation();
    const navigate = useNavigate();
    const theme = useTheme();
    const { setShellState } = useShellState();
    const { viewModel, update } = useViewState();

    // Process the credential offer query string
    useEffect(() => {
        if (runOnce.current) {
            return;
        }
        runOnce.current = true;
        setShellState({
            title: 'Add Credential',
            action: (
                <IconButton onClick={() => navigate('/credentials')} size="large">
                    <ArrowBackIosIcon fontSize="large" sx={{ color: theme.palette.primary.contrastText}} />
                </IconButton>
            ),
            secondaryAction: undefined,
        });

        const params = new URLSearchParams(location.search);
        const offer = params.get('credential_offer');
        if (offer !== null) {
            update(new st.EventVariantIssuance(new st.IssuanceEventVariantOffer(offer)));
        } else {
            update(new st.EventVariantCancel());
            navigate('credentials');
        }
    }, [location.search]);

    // Listen for changes to the view model and navigate to the main issuance sub-app.
    useEffect(() => {
        if (viewModel.view === 'Issuance') {
            navigate('issuance');
        }
    }, [viewModel.view]);

    return (<></>);
};

export default Offer;
