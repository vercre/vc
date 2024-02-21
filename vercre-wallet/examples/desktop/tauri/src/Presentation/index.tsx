import { useEffect, useState } from "react";

import KeyboardArrowLeft from '@mui/icons-material/KeyboardArrowLeft';
import KeyboardArrowRight from '@mui/icons-material/KeyboardArrowRight';
import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import MobileStepper from '@mui/material/MobileStepper';
import { invoke } from "@tauri-apps/api/core";
import { PresentationView } from "shared_types/types/shared_types";

import Authorize from "./Authorize";
import Request from "./Request";

type Input = {
    authorized: boolean
}

const initInput: Input = {
    authorized: false,
};

export type PresentationProps = {
    model: PresentationView
}

export const Presentation = (props: PresentationProps) => {
    const { model } = props;
    const [step, setStep] = useState(0);
    const [input, setInput] = useState(initInput);
    const maxSteps = 2;

    // translate status to step
    useEffect(() => {
        switch (String(model.status)) {
            case "Authorized":
            case "Completed":
                setStep(1);
                break;
            default:
                setStep(0);
                break;
        }
    }, [model]);


    const handleAuthorizeChange = () => {
        setInput((prev) => { return { ...prev, authorized: true } });
    }

    const handleCancel = () => {
        invoke('cancel');
    };

    const allowNext = () => {
        switch (step) {
            case 0:
                return input.authorized;
            case 1:
                return true;
            default:
                return false;
        }
    }

    const handleNext = () => {
        switch (step) {
            case 0:
                invoke("authorize");
                break;
            case 1:
                handleCancel();
                break;
            default:
                break;
        }
    };

    const handleBack = () => {
        if (step === 0) {
            handleCancel();
        }
        setStep((prevStep) => prevStep - 1);
    };

    return (
        <>
            <Box sx={{ width: '100%', p: 2 }}>
                {step === 0 &&
                    <Authorize value={input.authorized} onChange={handleAuthorizeChange} model={model} />
                }
                {step === 1 &&
                    <Request model={model} />
                }
            </Box>
            <MobileStepper variant="dots" steps={maxSteps} position="static" activeStep={step}
                nextButton={
                    <>
                        {step === maxSteps - 1 &&
                            <Button size="small" variant="contained" onClick={handleCancel}>
                                Done
                            </Button>

                        }
                        {step !== maxSteps - 1 &&
                            <Button size="small" disabled={!allowNext()} onClick={handleNext}>
                                Next<KeyboardArrowRight />
                            </Button>
                        }
                    </>
                }
                backButton={
                    <>
                        {step === 0 &&
                            <Button size="small" variant="contained" onClick={handleCancel}>
                                Cancel
                            </Button>
                        }
                        {step !== 0 &&
                            <Button size="small" onClick={handleBack}>
                                <KeyboardArrowLeft />Back
                            </Button>
                        }
                    </>
                }
            />
        </>
    );
}

export default Presentation;
