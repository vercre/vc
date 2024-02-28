use yew::prelude::*;

use crate::components::types::Direction;

#[derive(Properties, PartialEq)]
pub struct StackProps {
    pub children: Html,
    #[prop_or(Direction::Column)]
    pub direction: Direction,
    #[prop_or_default]
    pub spacing: i8,
}

fn stack_style(direction: Direction, spacing: i8) -> String {
    format!("display: flex; flex-direction: {direction}; gap: {spacing}px;")
}

#[function_component(Stack)]
pub fn stack(props: &StackProps) -> Html {
    html! {
        <div
            style={stack_style(props.direction, props.spacing)}
        >
            {props.children.clone()}
        </div>
    }
}

