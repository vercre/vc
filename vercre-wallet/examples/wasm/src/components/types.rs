use std::fmt::{self, Display, Formatter};

// The direction of layout, usually in a flexbox.
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum Direction {
    Row,
    Column,
}

impl Display for Direction {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Row => write!(f, "row"),
            Direction::Column => write!(f, "column"),
        }
    }
}

// Preset widths for various screen sizes.
#[derive(Clone, Copy, PartialEq)]
#[non_exhaustive]
pub(crate) struct MediaWidth;

impl MediaWidth {
    pub const EXTRA_SMALL: u16 = 0;
    pub const SMALL: u16 = 600;
    pub const MEDIUM: u16 = 900;
    pub const LARGE: u16 = 1200;
    pub const EXTRA_LARGE: u16 = 1536;
}