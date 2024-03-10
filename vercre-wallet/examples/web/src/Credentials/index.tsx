import Box from '@mui/material/Box';
import { Credential } from 'shared_types/types/shared_types';

export type CredentialsProps = {
    credentials: Credential[] | undefined;
}

const Credentials = (props: CredentialsProps) => {
    const { credentials } = props;

    console.log(credentials?.length);
    return(
        <Box>
            {credentials?.map((c, i) => (
                <div key={i}>{i}</div>
            ))}
        </Box>
    );
};

export default Credentials;