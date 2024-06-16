import { ChangeEvent, useEffect, useRef, useState } from 'react';

import Box from '@mui/material/Box';
import Button from '@mui/material/Button';
import Stack from '@mui/material/Stack';
import TextField from '@mui/material/TextField';
import Typography from "@mui/material/Typography";
import { invoke } from '@tauri-apps/api/core';

import { IssuanceView, PinInputMode, PinSchema } from '../types/generated';

export type PinProps = {
    issuance: IssuanceView
}

const Pin = (props: PinProps) => {
    const { issuance } = props;
    const [ pin, setPin ] = useState<Array<string>>([]);
    const [ pinDef, setPinDef ] = useState<PinSchema | undefined>(undefined);
    const inputRef = useRef<Array<HTMLInputElement>>([]);

    useEffect(() => {
        if (!issuance.pin_schema) {
            return;
        }
        if ((issuance.pin_schema?.description !== pinDef?.description)
            || (issuance.pin_schema?.length !== pinDef?.length)
            || (issuance.pin_schema?.input_mode !== pinDef?.input_mode)) {
            setPinDef({...issuance.pin_schema});
            setPin(new Array(issuance.pin_schema.length).fill(''));
        }
    }, [issuance.pin_schema, pinDef]);

    const handleInputChange = (index: number) => (e: ChangeEvent<HTMLInputElement>) => {
        let val = e.target.value.trim();
        if (pinDef?.input_mode === PinInputMode.Numeric) {
            val = val.replace(/\D/g, '');
        }
        val = val.slice(0, 1);
        let nextIndex = index + 1;
        const len = pinDef?.length || 6;
        if (nextIndex >= len) {
            nextIndex = len - 1;
        }
        inputRef.current[nextIndex].focus();
        setPin((prev) => {
            const newPin = [...prev];
            newPin[index] = val;
            return newPin;
        });
    }

    const handleSubmit = () => {
        invoke('pin', { pin: pin.join('') });
    }

    return(
        <Stack spacing={2} sx={{ pt: 2 }}>
            <Typography sx={{ pb: 1, textAlign: 'center' }}>
                {pinDef?.description}
            </Typography>
            <Box
                sx={{
                    display: 'flex',
                    justifyContent: 'center',
                    gap: 2,
                }}
            >
                {pin.map((p, index) => (
                    <TextField
                        key={index}
                        inputRef={ref => inputRef.current[index] = ref}
                        inputProps={{ maxLength: 1 }}
                        onChange={handleInputChange(index)}
                        size="small"
                        value={p}
                        variant="outlined"
                        sx={{
                            maxWidth: 40,
                            textAlign: 'center',
                        }}
                    />
                ))}
            </Box>
            <Box
                sx={{
                    display: 'flex',
                    my: 2,
                    justifyContent: 'center',
                    gap: 4
                }}
            >
                <Button
                    onClick={() => invoke('cancel')}
                    variant="outlined"
                >
                    Cancel
                </Button>
                <Button
                    onClick={handleSubmit}
                    variant="contained"
                >
                    Enter
                </Button>
            </Box>
        </Stack>
    );
};

export default Pin;
