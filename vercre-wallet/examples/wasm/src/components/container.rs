use yew::prelude::*;

#[derive(Properties, PartialEq)]
pub struct ContainerProps {
    pub children: Html,
    #[prop_or_default]
    pub max_width: u16,
}

fn container_style(width: u16) -> String {
    if width == 0 {
        return "width: 100%;".to_string();
    }
    format!("width: 100%; max-width: {width}px;")
}

#[function_component(Container)]
pub fn container(props: &ContainerProps) -> Html {
    html! {
        <div
            class={classes!("mui-container-fluid")}
            style={container_style(props.max_width)}
        >
            {props.children.clone()}
        </div>
    }
}
