import { useEffect, useState } from "react";

import KeyboardArrowLeft from '@mui/icons-material/KeyboardArrowLeft';
import KeyboardArrowRight from '@mui/icons-material/KeyboardArrowRight';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import MobileStepper from '@mui/material/MobileStepper';
import { invoke } from "@tauri-apps/api/core";
import { IssuanceView } from "shared_types/types/shared_types";

import Accept from "./Accept";
import EnterPin from "./EnterPin";
import Request from "./Request";

type Input = {
    accepted: boolean
    pin: string
}

const initInput: Input = {
    accepted: false,
    pin: ""
};

export type IssuanceProps = {
    model: IssuanceView
    onCancel: () => void
}

export const Issuance = (props: IssuanceProps) => {
    const { model, onCancel } = props;
    const [step, setStep] = useState(0);
    const [input, setInput] = useState(initInput);
    const maxSteps = 3;

    // translate status to step
    useEffect(() => {
        switch (String(model.status)) {
            case "PendingPin":
                setStep(1);
                break;
            case "Accepted":
            case "Requested":
            case "Completed":
                setStep(2);
                break;
            default:
                setStep(0);
                break;
        }
    }, [model]);


    const handleAcceptChange = () => {
        setInput((prev) => { return { ...prev, accepted: true } });
    }
    const handlePinChange = (pin: string) => {
        setInput((prev) => { return { ...prev, pin } });
    }

    const allowNext = () => {
        switch (step) {
            case 0:
                return input.accepted;
            case 1:
                return input.pin.length > 0;
            case 2:
                return true;
            default:
                return false;
        }
    }

    const handleNext = () => {
        switch (step) {
            case 0:
                invoke("accept");
                break;
            case 1:
                invoke("set_pin", { pin: input.pin });
                break;
            case 2:
                onCancel();
                break;
            default:
                break;
        }
    };

    const handleBack = () => {
        if (step === 0) {
            onCancel();
        }
        setStep((prevStep) => prevStep - 1);
    };

    return (
        <>
            <Box sx={{ width: '100%', p: 2 }}>
                {step === 0 &&
                    // <Accept value={input.accepted} onChange={handleAcceptChange} model={model} />
                    <Accept onChange={handleAcceptChange} model={model} />
                }
                {step === 1 &&
                    <EnterPin value={input.pin} onChange={handlePinChange} />
                }
                {step === 2 &&
                    <Request model={model} />
                }
            </Box>
            <MobileStepper variant="dots" steps={maxSteps} position="static" activeStep={step}
                nextButton={<>
                    {step === maxSteps - 1 &&
                        <Button size="small" variant="contained" onClick={onCancel}>
                            Done
                        </Button>

                    }
                    {step !== maxSteps - 1 &&
                        <Button size="small" disabled={!allowNext()} onClick={handleNext}>
                            Next<KeyboardArrowRight />
                        </Button>
                    }
                </>}
                backButton={<>
                    {step === 0 &&
                        <Button size="small" variant="contained" onClick={onCancel}>
                            Cancel
                        </Button>
                    }
                    {step !== 0 &&
                        <Button size="small" onClick={handleBack}>
                            <KeyboardArrowLeft />Back
                        </Button>
                    }
                </>}
            />
        </>
    );
}

export default Issuance;
