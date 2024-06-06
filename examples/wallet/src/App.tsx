import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from "@mui/material/styles";
import { useRecoilValue } from 'recoil';

import { appState } from './model';
import Splash from './Splash';
import { theme } from "./theme";

const App = () => {
  const view = useRecoilValue(appState);

  return (
    <ThemeProvider theme={theme}>
        <CssBaseline />
          {view.subApp === "splash"
            ? <Splash />
            : <div>Hello World</div>
          } 
    </ThemeProvider>
  );
}

export default App
