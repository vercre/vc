import { createTheme, responsiveFontSizes } from '@mui/material/styles';

import { components } from './components';
import { palette } from './palette';
import { typography } from './typography';

export const theme = responsiveFontSizes(createTheme({
    palette,
    typography,
    components,
}));
