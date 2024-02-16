import Typography from "@mui/material/Typography";
import Grid from "@mui/material/Unstable_Grid2";
import { Credential, PresentationView } from "shared_types/types/shared_types";

import VcCard, { VcCardProps } from "../Credentials/VcCard";

export type AuthorizeProps = {
    model: PresentationView | undefined;
    value: boolean;
    onChange: () => void;
};

export const Authorize = (props: AuthorizeProps) => {
    const { model, onChange } = props;

    const handleAuthorize = () => {
        onChange();
    }

    const displayProps = (credential: Credential) : VcCardProps => {
        const display = credential.metadata.display?.at(0);
        return {
            backgroundColor: display?.background_color || undefined,
            color: display?.text_color || undefined,
            issuer: credential.issuer,
            logo: credential.logo || undefined,
            logoUrl: undefined,
            name: display?.name,
            onSelect: handleAuthorize,
            size: 'medium'
        }
    };

    return (
        <>
            <Typography variant="h5" gutterBottom>
                Authorize Presentation
            </Typography>
            <Typography variant="body2" sx={{ pb: 4 }}>
                Click credentials to present
            </Typography>

            <Grid container spacing={2}>
                {model?.credentials.map((credential, index) =>
                    <Grid key={index} xs={12} sm={6}>
                        <VcCard { ...displayProps(credential) } />
                    </Grid>
                )}
            </Grid>
        </>
    );
}

export default Authorize;
