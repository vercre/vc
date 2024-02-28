use yew::prelude::*;

use crate::components::{types::MediaWidth, Container, Stack};

#[derive(Properties, PartialEq)]
pub(crate) struct ShellProps {
    pub children: Html,
}

#[function_component(Shell)]
pub(crate) fn shell(props: &ShellProps) -> Html {
    html! {
        <Stack>
            <Container max_width={MediaWidth::SMALL}>
                {props.children.clone()}
            </Container>
        </Stack>
    }
}

