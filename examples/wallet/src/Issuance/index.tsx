import { useEffect, useState } from "react";

import Box from "@mui/material/Box";
import Slide from "@mui/material/Slide";
import { invoke } from "@tauri-apps/api/core";

import Accept from "./Accept";
import Pin from "./Pin";
import Error from "../Error";
import Loading from "../Loading";
import { IssuanceView } from "../types/generated";

export type IssuanceProps = {
    issuance: IssuanceView;
};

export const Issuance = (props: IssuanceProps) => {
    const { issuance } = props;
    const [mode, setMode] = useState<"accept" | "pin" | "request" | "error">(
        "accept"
    );

    // Translate status to mode
    useEffect(() => {
        switch (issuance.status) {
            case "PendingPin":
                setMode("pin");
                break;
            case "Accepted":
                setMode("request");
                break;
            default:
                setMode("accept");
                break;
        }
    }, [issuance]);

    // Go get the credentials if the user has accepted (and entered a pin if necessary)
    useEffect(() => {
        if (issuance.status === "Accepted") {
            const requestEndpoint = async () => {
                try {
                    await invoke("credentials");
                } catch {
                    setMode("error");
                }
            };
            requestEndpoint();
        }
    }, [issuance.status]);

    return (
        <Box sx={{ pt: 1, position: "relative" }}>
            {mode === "accept" && <Accept issuance={issuance} />}
            <Slide
                direction="left"
                in={mode === "pin"}
                mountOnEnter
                unmountOnExit>
                <Box>
                    <Pin issuance={issuance} />
                </Box>
            </Slide>
            {mode === "request" && <Loading status="downloading" />}
            {mode === "error" && <Error />}
        </Box>
    );
};

export default Issuance;
