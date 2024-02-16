import TextField from '@mui/material/TextField';
import Typography from "@mui/material/Typography";

export type EnterPinProps = {
    value: string;
    onChange: (offer: string) => void;
};

export const EnterPin = (props: EnterPinProps) => {
    const { value, onChange } = props;

    return (
        <>
            <Typography variant="h5" gutterBottom>
                Enter Pin
            </Typography>
            <Typography variant="body2" sx={{ pb: 4 }}>
                Enter user pin sent via email
            </Typography>
            <TextField  variant="outlined"
                label="Pin"
                helperText="Enter your user pin"
                value={value}
                onChange={(e) => onChange(e.target.value)}
            />
        </>
    );
}

export default EnterPin;
