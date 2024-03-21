import { CSSProperties } from "react";

declare module '@mui/material/styles' {
    interface TypographyVariants {
        brand1: CSSProperties;
        brand2: CSSProperties;
        fineprint: CSSProperties;
        body3: CSSProperties;
    }
    // This allows configuration using 'createTheme'
    interface TypographyVariantsOptions {
        brand1?: CSSProperties;
        brand2?: CSSProperties;
        fineprint?: CSSProperties;
        body3?: CSSProperties;
    }
}

declare module '@mui/material/Typography' {
    interface TypographyPropsVariantOverrides {
        brand1: true,
        brand2: true,
        fineprint: true,
        body3: true,
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

const brandTitleFont = [
    'GT Ultra Median Light',
    '-apple-system',
    'BlinkMacSystemFont',
    'Segoe UI',
    'Helvetica',
    'Arial',
    'sans-serif',
    'Apple Color Emoji',
    'Segoe UI Emoji',
].join(',');

const brandCopyFont = [
    'GT Ultra Standard Light',
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
        fontFamily: brandTitleFont,
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
    brand1: {
        fontFamily: brandTitleFont,
        fontSize: '2rem',
        fontWeight: 700,
        textTransform: 'uppercase' as const,
    },
    brand2: {
        fontFamily: brandCopyFont,
        fontSize: '1.625rem',
        fontWeight: 400,
        textTransform: 'uppercase' as const,
    },
    caption: {
        fontSize: '0.825rem',
        fontWeight: 300,
    },
    fineprint: {
        fontSize: '0.75rem',
        fontWeight: 200,
    },
    body3: {
        fontSize: '0.875rem',
        fontWeight: 300,
        lineHeight: 1.3,
    },
};
