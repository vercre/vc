import { ChangeEvent, useState } from 'react';

import LoadingButton from '@mui/lab/LoadingButton';
import Alert from '@mui/material/Alert';
import Box from '@mui/material/Box';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Typography from '@mui/material/Typography';

export type VcAddProps = {
    onSubmit: (url: string) => void;
};

const VcAdd = (props: VcAddProps) => {
    const [offer, setOffer] = useState<string>("");
    const [error, setError] = useState<string | undefined>(undefined);

    const handleChange = (e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
        const val = e.target.value.trim();
        setOffer(val);
        if (val === "") {
            setError("Offer is required");
        }
    };

    return (
        <Stack>
            <Typography gutterBottom>
                Paste the Verifiable Credential offer.
            </Typography>
            <Alert severity="info">You will have a chance to review the Credential before it is added</Alert>
            <TextField
                error={!!error}
                fullWidth
                helperText={error}
                inputProps={{ maxLength: 1024 }}
                label="Offer"
                margin="normal"
                multiline
                name="offer"
                onChange={(e) => handleChange(e)}
                required
                rows={6}
                size="small"
                value={offer}
                variant="outlined"
            />
            <Box
                sx={{
                    display: 'flex',
                    my: 2,
                    justifyContent: 'center',
                }}
            >
                <LoadingButton
                    color="primary"
                    disabled={!!error && offer === ""}
                    loading={false}
                    onClick={() => props.onSubmit(offer)}
                    variant="contained"
                >
                    Review
                </LoadingButton>
            </Box>
        </Stack>
    );
};

export default VcAdd;
