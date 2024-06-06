import { useEffect, useRef, useState } from 'react';

import Button from '@mui/material/Button';
import CssBaseline from '@mui/material/CssBaseline';
import FormControl from '@mui/material/FormControl';
import InputLabel from '@mui/material/InputLabel';
import MenuItem from '@mui/material/MenuItem';
import Select from '@mui/material/Select';
import { ThemeProvider } from "@mui/material/styles";
import Typography from '@mui/material/Typography';
import { invoke } from '@tauri-apps/api/core';
import { listen, UnlistenFn } from '@tauri-apps/api/event';
import { useRecoilValue } from 'recoil';

import { appState } from './model';
import Splash from './Splash';
import { theme } from "./theme";

const App = () => {
  const view = useRecoilValue(appState);
  const [inputStatus, setInputStatus] = useState<string>("Inactive");
  const [outputStatus, setOutputStatus] = useState<string>("Inactive");
  const init = useRef<boolean>(false);

  type Model = {
    status: string;
  }

  // register listener for Tauri events
  useEffect(() => {
    if (init.current) {
        return;
    }
    init.current = true;
    let unlisten: UnlistenFn;
    const statusListener = async () => {
        unlisten = await listen<Model>("status_updated", ({ payload }) => {
            const model = payload as Model;
            console.log("status_updated", model);
            setOutputStatus(model.status);
        });
    }
    statusListener();

    return () => {
        unlisten?.();
    };
  }, []);

  const submit = () => {
    invoke("update_status", { status: inputStatus });
  }

  return (
    <ThemeProvider theme={theme}>
        <CssBaseline />
          {view.subApp === "splash" && <Splash />}
          <Typography variant="body1">{`Current status: ${outputStatus}`}</Typography>
          <FormControl>
            <InputLabel id="status">Status</InputLabel>
            <Select
              labelId="status"
              id="status"
              value={inputStatus}
              label="Status"
              onChange={(e) => setInputStatus(e.target.value as string)}
            >
              <MenuItem value="Inactive">Inactive</MenuItem>
              <MenuItem value="Offered">Offered</MenuItem>
              <MenuItem value="Ready">Ready</MenuItem>
              <MenuItem value="PendingPin">PendingPIN</MenuItem>
              <MenuItem value="Accepted">Accepted</MenuItem>
              <MenuItem value="Requested">Requested</MenuItem>
            </Select>
          </FormControl>
          <Button onClick={submit}>Submit</Button>
    </ThemeProvider>
  );
}

export default App
