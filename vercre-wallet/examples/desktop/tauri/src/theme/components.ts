import GTUltraMedian from './GT-Ultra-Median-Light.woff2';
import GTUltraStandard from './GT-Ultra-Standard-Light.woff2';

export const components = {
    MuiCssBaseline: {
        styleOverrides: `
            @font-face [
                {
                    font-family: 'GT Ultra Standard Light';
                    font-style: normal;
                    font-weight: 300;
                    src: local('GT Ultra Standard Light'), local('GTUltraStandard-Light'),
                        url(${GTUltraStandard}) format('woff2');
                    font-display: swap;
                },
                {
                    font-family: 'GT Ultra Median Light';
                    font-style: normal;
                    font-weight: 300;
                    src: local('GT Ultra Median Light'), local('GTUltraMedian-Light'),
                        url(${GTUltraMedian}) format('woff2');
                    font-display: swap;
                },
            ]
        `,
    },
};
