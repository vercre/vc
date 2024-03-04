mod header;

use yew::prelude::*;

use crate::components::{types::MediaWidth, Container, Stack};
use header::Header;
pub use header::HeaderProps;

#[derive(Properties, PartialEq)]
pub(crate) struct ShellProps {
    pub children: Html,
    #[prop_or_default]
    pub header: HeaderProps,
}

#[function_component(Shell)]
pub(crate) fn shell(props: &ShellProps) -> Html {
    html! {
        <Stack>
            <Header title="" />
            <Container min_width={MediaWidth::Md}>
                {props.children.clone()}
            </Container>
        </Stack>
    }
}

