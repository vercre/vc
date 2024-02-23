import { useState } from "react";

import CheckCircleOutlineIcon from '@mui/icons-material/CheckCircleOutline';
import FingerprintIcon from '@mui/icons-material/Fingerprint';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import { useTheme } from '@mui/material/styles';
import Typography from '@mui/material/Typography';
import { EncodedLogo } from "shared_types/types/shared_types";
import tinycolor from 'tinycolor2';

import { domainFromUrl } from ".";

export type VcCardProps = {
    backgroundColor?: string;
    color?: string;
    issuer?: string;
    logo?: EncodedLogo;
    logoUrl?: string;
    name?: string;
    onSelect?: (selected: boolean) => void;
    size?: 'small' | 'medium' | 'large';
};

const cardSize = {
    small: { width: 150, body2: '0.5rem', h5: '1rem' },
    medium: { width: 220, body2: '0.75rem', h5: '1.25rem' },
    large: { width: 300, body2: '0.875rem', h5: '1.5rem' },
};
const ratio = 1.59;

// const tempImage = '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';

export const VcCard = (props: VcCardProps) => {
    const {
        backgroundColor,
        color,
        issuer,
        logo,
        logoUrl,
        name,
        onSelect,
        size = 'large'
    } = props;
    const specs = cardSize[size];
    const [selected, setSelected] = useState(false);
    const theme = useTheme();

    const handleSelect = () => {
        setSelected(!selected);
        onSelect && onSelect(!selected);
    };

    const bg = backgroundColor || theme.palette.primary.main;
    const shadeColor = tinycolor(bg).brighten(33).toString();

    return (
        <Card
            elevation={4}
            sx={{
                background: `linear-gradient(135deg, ${bg} 30%, ${shadeColor})`,
                color: color || theme.palette.primary.contrastText,
                cursor: 'pointer',
                height: specs.width / ratio,
                width: specs.width,
            }}
            onClick={handleSelect}
        >
            <CardContent
                sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    height: '100%',
                    pt: 0,
                }}>
                <CardHeader issuer={issuer} logo={logo} logoUrl={logoUrl} name={name} />
                <Box sx={{ flexGrow: 2 }}>&nbsp;</Box>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Typography component="div" variant="body2" sx={{ flexGrow: 1 }}>
                        {domainFromUrl(issuer)}
                    </Typography>
                    <Box>
                    {selected === true &&
                        <CheckCircleOutlineIcon />
                    }
                    </Box>
                </Box>
            </CardContent>
        </Card>
    );
}

type CardHeaderProps = {
    issuer?: string;
    logo?: EncodedLogo;
    logoUrl?: string;
    name?: string;
}

const CardHeader = (props: CardHeaderProps) => {
    const { issuer, logo, logoUrl, name } = props;
    return (
        <Box sx={{ display: 'flex', alignItems: 'flex-start', flexGrow: 1, pt: 2 }}>
            <Box sx={{ height: 36, maxWidth: '50%' }}>
                {logo    
                    ? <img
                        src={`data:${logo.media_type};charset=utf-8;base64, ${logo.image}`}
                        alt={issuer}
                        style={{ maxHeight: '100%', maxWidth: '100%' }}
                    />
                    : <>
                        {logoUrl
                            ? <img
                                src={logoUrl}
                                alt={issuer}
                                style={{ maxHeight: '100%', maxWidth: '100%' }}
                                />
                            : <FingerprintIcon />
                        }
                    </>
                }
            </Box>
            <Box sx={{ textAlign: 'right', flexGrow: 1, mt: '-2px' }}>
                <Typography component="span">
                    {name}
                </Typography>
            </Box>
        </Box>
    );
};

export default VcCard;