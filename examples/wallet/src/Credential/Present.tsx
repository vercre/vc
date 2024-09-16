import { ChangeEvent, useEffect, useRef, useState } from "react";

import ArrowBackIosIcon from "@mui/icons-material/ArrowBackIos";
import Alert from "@mui/material/Alert";
import Box from "@mui/material/Box";
import Button from "@mui/material/Button";
import IconButton from "@mui/material/IconButton";
import Stack from "@mui/material/Stack";
import { useTheme } from "@mui/material/styles";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";
import { invoke } from "@tauri-apps/api/core";
import { useSetRecoilState } from "recoil";

import { header } from "../Layout";

export type PresentProps = {
    onClose: () => void;
};

const Present = (props: PresentProps) => {
    const { onClose } = props;
    const [request, setRequest] = useState<string>("");
    const [error, setError] = useState<string | undefined>(undefined);
    const theme = useTheme();
    const setHeader = useSetRecoilState(header);
    const init = useRef<boolean>(false);

    useEffect(() => {
        if (init.current) {
            return;
        }
        init.current = true;
        setHeader({
            title: "Present Credential",
            action: (
                <IconButton onClick={onClose} size="large">
                    <ArrowBackIosIcon
                        fontSize="large"
                        sx={{ color: theme.palette.primary.contrastText }}
                    />
                </IconButton>
            ),
            secondaryAction: undefined,
        });
    }, [onClose, setHeader, theme.palette.primary.contrastText]);

    const handleChange = (
        e: ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
    ) => {
        const val = e.target.value.trim();
        setRequest(val);
        if (val === "") {
            setError("Request is required");
        } else {
            setError(undefined);
        }
    };

    const handleSubmit = () => {
        if (request === "") {
            return;
        }
        const encoded = encodeURIComponent(request);
        const requestEndpoint = async () => {
            try {
                await invoke("request", { request: encoded });
            } catch {
                setError("Failed to send presentation request");
            }
        };
        requestEndpoint();
    };

    return (
        <Stack>
            <Typography gutterBottom>
                Paste the presentation request URL.
            </Typography>
            <Alert severity="info">
                You will have a chance to authorize the presentation before it
                is sent
            </Alert>
            <TextField
                error={!!error}
                fullWidth
                helperText={error}
                inputProps={{ maxLength: 1024 }}
                label="Presentation request URL"
                margin="normal"
                name="request"
                onChange={handleChange}
                required
                size="small"
                value={request}
                variant="outlined"
            />
            <Box
                sx={{
                    display: "flex",
                    my: 2,
                    justifyContent: "center",
                }}>
                <Button
                    color="primary"
                    disabled={!!error || request === ""}
                    onClick={handleSubmit}
                    variant="contained">
                    Present
                </Button>
            </Box>
        </Stack>
    );
};

export default Present;
