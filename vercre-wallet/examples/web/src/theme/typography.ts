import { CSSProperties } from "react";

declare module '@mui/material/styles' {
    interface TypographyVariants {
        fineprint: CSSProperties;
    }
    // This allows configuration using 'createTheme'
    interface TypographyVariantsOptions {
        fineprint?: CSSProperties;
    }
}

declare module '@mui/material/Typography' {
    interface TypographyPropsVariantOverrides {
        fineprint: true,
    }
}

const systemFont = [
    '-apple-system',
    'BlinkMacSystemFont',
    'Segoe UI',
    'Helvetica',
    'Arial',
    'sans-serif',
    'Apple Color Emoji',
    'Segoe UI Emoji',
].join(',');

export const typography = {
    fontFamily: systemFont,
    h1: {
        fontSize: '3rem',
        fontWeight: 700,
        lineHeight: 1.375,
        letterSpacing: '-0.0625rem',
    },
    h2: {
        fontSize: '2.625rem',
        fontWeight: 500,
        lineHeight: 1.375,
        letterSpacing: '-0.0625rem',
    },
    h3: {
        fontSize: '2rem',
        fontWeight: 700,
        lineHeight: 1.375,
    },
    h4: {
        fontFamily: systemFont,
        fontSize: '1.625rem',
        fontWeight: 700,
        lineHeight: 1.375,
    },
    h5: {
        fontSize: '1rem',
        fontWeight: 700,
        lineHeight: 1.375,
        textTransform: 'uppercase' as const,
    },
    h6: {
        fontSize: '0.875rem',
        fontWeight: 500,
        lineHeight: 1.375,
        textTransform: 'uppercase' as const,
    },
    subtitle1: {
        fontSize: '1rem',
        fontWeight: 700,
        lineHeight: 1.375,
    },
    subtitle2: {
        fontSize: '0.875rem',
        fontWeight: 500,
        lineHeight: 1.375,
    },
    body1: {
        fontSize: '1rem',
        fontWeight: 400,
        lineHeight: 1.25,
    },
    body2: {
        fontSize: '0.875rem',
        fontWeight: 300,
    },
    caption: {
        fontSize: '0.825rem',
        fontWeight: 300,
    },
    fineprint: {
        fontSize: '0.75rem',
        fontWeight: 200,
    },
};
