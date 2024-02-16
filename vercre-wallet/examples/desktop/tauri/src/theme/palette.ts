declare module '@mui/material/styles' {
    interface Palette {
        brandRoyal: Palette['primary'];
        brandCobalt: Palette['primary'];
        brandAzure: Palette['primary'];
        brandAquamarine: Palette['primary'];
    }

    interface PaletteOptions {
        brandRoyal: PaletteOptions['primary'];
        brandCobalt: PaletteOptions['primary'];
        brandAzure: PaletteOptions['primary'];
        brandAquamarine: PaletteOptions['primary'];
    }
}

export const palette = {
    primary: {
        light: '#7088ff',
        main: '#4d6bff',
        dark: '#354ab2',
        constrastText: '#ffffff',
    },
    secondary: {
        light: '#33ffff',
        main: '#00ffff',
        dark: '#00b2b2',
    },
    background: {
        default: '#ffffff',
        paper: '#ffffff',
    },
    brandRoyal: {
        light: '#7088ff',
        main: '#4d6bff',
        dark: '#354ab2',
        constrastText: '#ffffff',
    },
    brandCobalt: {
        light: '#5d6bf1',
        main: '#3546ee',
        dark: '#2531a6',
        contrastText: '#ffffff',
    },
    brandAzure: {
        light: '#5b64db',
        main: '#323ed2',
        dark: '#232b93',
        contrastText: '#ffffff',
    },
    brandAquamarine: {
        light: '#33ffff',
        main: '#00ffff',
        dark: '#00b2b2',
        contrastText: '#323ed2',
    },
};
