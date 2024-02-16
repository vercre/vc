import CheckIcon from '@mui/icons-material/Check';
import DownloadingIcon from '@mui/icons-material/Downloading';
import Box from '@mui/material/Box';
import CircularProgress from '@mui/material/CircularProgress';
import { green } from '@mui/material/colors';
import Fab from '@mui/material/Fab';
import Typography from '@mui/material/Typography';
import { IssuanceView } from "shared_types/types/shared_types";

export type RequestProps = {
    model: IssuanceView | undefined;
};

export const Request = (props: RequestProps) => {
    const { model } = props;
    const status = String(model?.status);

    const buttonSx = {
        ...(status === "Requested" && {
            bgcolor: green[500],
            '&:hover': {
                bgcolor: green[700],
            },
        }),
    };

    return (
        <>
            <Typography variant="h5" gutterBottom>
                {status === "Requested" ? 'Requesting Credentials' : 'Credentials Requested'}
            </Typography>

            <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <Box sx={{ m: 1, position: 'relative' }}>
                    <Fab
                        aria-label="save"
                        color="primary"
                        sx={buttonSx}

                    >
                        {status === "Requested" ? <DownloadingIcon /> : <CheckIcon />}
                    </Fab>
                    {status === "Requested" && (
                        <CircularProgress
                            size={68}
                            sx={{
                                color: green[500],
                                position: 'absolute',
                                top: -6,
                                left: -6,
                                zIndex: 1,
                            }}
                        />
                    )}
                </Box>
            </Box>
        </>
    );
}

export default Request;
