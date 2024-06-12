import FingerprintIcon from '@mui/icons-material/Fingerprint';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import { useTheme } from '@mui/material/styles';
import Typography from '@mui/material/Typography';
import tinycolor from 'tinycolor2';

import { domainFromUrl } from ".";
import { CredentialDisplay, Logo } from '../types/generated';

export type VcCardProps = {
    credential: CredentialDisplay;
    onSelect?: () => void;
};

const VcCard = (props: VcCardProps) => {
    const { credential, onSelect } = props;
    const theme = useTheme();

    const bg = credential.background_color || theme.palette.primary.main;
    const shadeColor = tinycolor(bg).brighten(33).toString();

    return (
        <Card
            elevation={4}
            sx={{
                background: `linear-gradient(135deg, ${bg} 30%, ${shadeColor})`,
                color: credential.color || theme.palette.primary.contrastText,
                cursor: 'pointer',
                height: 189,
                width: 300,
            }}
            onClick={onSelect}
        >
            <CardContent
                sx={{
                    display: 'flex',
                    flexDirection: 'column',
                    height: '100%',
                    pt: 0,
                }}
            >
                <CardHeader
                    issuer={credential.issuer}
                    logo={credential.logo}
                    logoUrl={credential.logo_url}
                    name={credential.name}
                />
                <Box sx={{ flexGrow: 2 }}>&nbsp;</Box>
                <Box sx={{ display: 'flex', alignItems: 'center' }}>
                    <Typography component="div" variant="body2" sx={{ flexGrow: 1 }}>
                        {domainFromUrl(credential.issuer)}
                    </Typography>
                </Box>
            </CardContent>
        </Card>
    );
};

type CardHeaderProps = {
    issuer?: string;
    logo?: Logo;
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