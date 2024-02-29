use yew::prelude::*;

use crate::components::types::MediaWidth;

#[derive(Properties, PartialEq)]
pub struct ContainerProps {
    pub children: Html,
    #[prop_or(MediaWidth::Md)]
    pub min_width: MediaWidth,
}

#[function_component(Container)]
pub fn container(props: &ContainerProps) -> Html {
    html! {
        <div
            class={classes!("mui-container-fluid", props.min_width.min_width())}
        >
            {props.children.clone()}
        </div>
    }
}
