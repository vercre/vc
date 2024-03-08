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
pub(crate) enum MediaWidth {
    Xs,
    Sm,
    Md,
    Lg,
    Xl,
}

impl MediaWidth {
    // Converts the enum to a minimum width class string.
    pub(crate) fn min_width(&self) -> String {
        match self {
            MediaWidth::Xs => "min-w-xs",
            MediaWidth::Sm => "min-w-sm",
            MediaWidth::Md => "min-w-md",
            MediaWidth::Lg => "min-w-lg",
            MediaWidth::Xl => "min-w-xl",
        }
        .to_string()
    }

    // Converts the enum to a maximum width class string.
    pub(crate) fn max_width(&self) -> String {
        match self {
            MediaWidth::Xs => "max-w-xs",
            MediaWidth::Sm => "max-w-sm",
            MediaWidth::Md => "max-w-md",
            MediaWidth::Lg => "max-w-lg",
            MediaWidth::Xl => "max-w-xl",
        }
        .to_string()
    }
}
