use yew::prelude::*;

#[derive(Default, Properties, PartialEq)]
pub struct HeaderProps {
    #[prop_or_default]
    pub primary_action: Html,
    #[prop_or_default]
    pub secondary_action: Html,
    #[prop_or_default]
    pub title: String,
}

#[function_component(Header)]
pub fn header(props: &HeaderProps) -> Html {
    html! {
        <header
            class={classes!("mui-appbar", "bg-primary-main")}
        >
            <div style="display: flex; flexgrow: 1;">
                {props.primary_action.clone()}
                <p class={classes!("brand-title")}>{props.title.clone()}</p>
                <div style="flex-grow: 1"/>
                {props.secondary_action.clone()}
            </div>
        </header>
    }
}
