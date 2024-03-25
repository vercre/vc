import CssBaseline from '@mui/material/CssBaseline';
import { ThemeProvider } from '@mui/material/styles';
import { createBrowserRouter, RouterProvider } from 'react-router-dom';

import Credentials from './Credentials';
import Issuance from './Issuance';
import Offer from './Issuance/Offer';
import Presentation from './Presentation';
import Shell from './Shell';
import { ShellStateProvider } from './Shell/Context';
import { theme } from './theme';

const router = createBrowserRouter([
    {
      path: '/',
      element: <Shell />,
      errorElement: <Shell />,
      children: [
        {
          path: 'credentials',
          element: <Credentials />,
        },
        {
          path: 'issuance',
          element: <Issuance />,
        },
        {
          path: 'presentation',
          element: <Presentation />,
        },
        {
          path: 'credential_offer',
          element: <Offer />,
        }
      ]
    },
  ]);
  
const App = () => {
    return (
        <ThemeProvider theme={theme}>
            <CssBaseline />
            <ShellStateProvider>
                <RouterProvider router={router} />
            </ShellStateProvider>
        </ThemeProvider>
    );
}

export default App;
