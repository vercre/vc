import Typography from "@mui/material/Typography";
import Grid from "@mui/material/Unstable_Grid2";
import { IssuanceView, CredentialConfiguration } from "shared_types/types/shared_types";

import VcCard, { VcCardProps } from '../Credentials/VcCard';

export type AcceptProps = {
    model: IssuanceView;
    onChange: () => void;
};

export const Accept = (props: AcceptProps) => {
    const { model, onChange } = props;

    const handleAccept = () => {
        onChange();
    }

    const displayProps = (credential: CredentialConfiguration) : VcCardProps => {
        const display = credential.display?.at(0);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: model.issuer,
            logo: undefined,
            logoUrl: display?.logo?.url || undefined,
            name: display?.name,
            onSelect: handleAccept,
            size: 'medium'
        };
    };

    return (
        <>
            <Typography variant="h5" gutterBottom>
                Accept Credentials
            </Typography>
            <Typography variant="body2" sx={{ pb: 4 }}>
                Click credential to select
            </Typography>

            <Grid container spacing={2}>
                {Object.entries(model?.offered).map(([key, supported]) => (
                    <Grid key={key} xs={12} sm={6}>
                        <VcCard { ...displayProps(supported) } />
                    </Grid>
                ))}
            </Grid>
        </>
    );
}

export default Accept;
