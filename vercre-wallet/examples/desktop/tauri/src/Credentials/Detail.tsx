import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import Typography from '@mui/material/Typography';
import { Optional } from 'shared_types/serde/types';
import { Credential } from "shared_types/types/shared_types";

import { dateFromIso, domainFromUrl } from '.';
import VcCard, { VcCardProps } from "./VcCard";

export type DetailProps = {
    credential: Credential;
};

const Detail = (props: DetailProps) => {
    const { credential } = props;

    const claimValues = credential.vc.credentialSubject;
    const display = credential.metadata.display?.at(0);

    const displayProps = (): VcCardProps => {
        const display = credential.metadata.display?.at(0);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: credential.issuer,
            logo: credential.logo || undefined,
            logoUrl: undefined,
            name: display?.name,
            onSelect: undefined,
            size: 'large'
        }
    };

    const claimNames = credential.metadata.credential_definition.credentialSubject;
    const claimName = (key: string): string => {
        if (claimNames) {
            const locale = navigator.language;  // TODO: use user's preferred language (settings)
            for (const [k, v] of Object.entries(claimNames)) {
                if (k === key && v.display) {
                    for (const d of v.display) {
                        if (d.locale === locale) {
                            return d.name;
                        }
                    }
                }
            }
        }
        return key;
    };

    return (
        <Stack spacing={2} sx={{ pt: 2 }}>
            <VcCard { ...displayProps() } />
            <Typography variant="h5">
                Verified Info
            </Typography>
            <ClaimEntry name="Description" value={display?.description} />
            {claimValues && Object.entries(claimValues).map(([key, value]) => (
                <ClaimEntry key={key} name={claimName(key)} value={value} />
            ))}
            <ClaimEntry name="Issued on" value={dateFromIso(credential.vc.issuanceDate)} />
            <ClaimEntry name="Expires on" value={
                credential.vc.expirationDate ? dateFromIso(credential.vc.expirationDate) : 'Never'
            } />
            <ClaimEntry name="Issued by" value={domainFromUrl(credential.issuer)} />
        </Stack>
    );
}

export default Detail;

const ClaimEntry = (props: { name: string, value: Optional<string> | undefined }) => {
    return (<>
        {props.name === 'id' ? null :
            <Box>
                <Typography variant="caption">
                    {props.name}
                </Typography>
                <Typography variant="body1">
                    {props.value}
                </Typography>
            </Box>
        }
    </>);
};
