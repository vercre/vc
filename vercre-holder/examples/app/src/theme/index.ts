import { createTheme, responsiveFontSizes } from '@mui/material/styles';

import { typography } from './typography';

export const theme = responsiveFontSizes(createTheme({
    typography,
}));
