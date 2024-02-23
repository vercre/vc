import { Box } from '@mui/material';
import { useTheme } from '@mui/material/styles';

const Watermark = () => {
    const theme = useTheme();

    const color = theme.palette.brandAquamarine.main;

    return (
        <Box
            sx={{
                position: 'absolute',
                bottom: 0,
                right: 0,
                overflow: 'hidden',
            }}
        >
            <svg id="Layer_2"
                xmlns="http://www.w3.org/2000/svg"
                viewBox="0 0 681.49 736.43"
                width="800"
                opacity={0.8}
                style={{
                    transform: 'rotate(180deg)',
                    marginRight: '-360px',
                    marginBottom: '-120px',
                }}
            >
                <g id="Layer_1-2">
                    <ellipse cx="348.4" cy="224.44" rx="33.61" ry="33.75" fill={color} strokeWidth="0"/>
                    <circle cx="486.07" cy="77.01" r="72.48" fill={color} strokeWidth="0"/>
                    <circle cx="350.81" cy="525.74" r="42.5" fill={color} strokeWidth="0"/>
                    <circle cx="178.92" cy="530.71" r="103.2" fill={color} strokeWidth="0"/>
                    <circle cx="263.87" cy="374.6" r="34.43" fill={color} strokeWidth="0"/>
                    <circle cx="135.84" cy="135.84" r="135.83" fill={color} strokeWidth="0"/>
                    <circle cx="560.88" cy="255.76" r="42.5" fill={color} strokeWidth="0"/>
                    <circle cx="601.18" cy="559.38" r="80.3" fill={color} strokeWidth="0"/>
                    <circle cx="505.14" cy="705.96" r="30.46" fill={color} strokeWidth="0"/>
                    <line x1="178.73" y1="531.11" x2="567.25" y2="251.63" fill="none" stroke={color} strokeMiterlimit="10" strokeWidth="10.84"/>
                    <line x1="601.15" y1="558.95" x2="142.24" y2="143.94" fill="none" stroke={color} strokeMiterlimit="10" strokeWidth="10.84"/>
                    <line x1="345.64" y1="216.5" x2="499.1" y2="688.98" fill="none" stroke={color} strokeMiterlimit="10" strokeWidth="10.84"/>
                    <line x1="483.14" y1="88.41" x2="348.72" y2="533.67" fill="none" stroke={color} strokeMiterlimit="10" strokeWidth="10.84"/>
                    <line x1="257.06" y1="374.21" x2="396.88" y2="374.21" fill="none" stroke={color} strokeMiterlimit="10" strokeWidth="10.84"/>
                </g>
            </svg>
        </Box>
    );
};

export default Watermark;