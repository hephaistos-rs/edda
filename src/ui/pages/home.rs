use dioxus::prelude::*;

use crate::ui::components::{Echo, Hero};

/// Home page
#[component]
pub fn Home() -> Element {
    rsx! {
        Hero {}
        Echo {}
    }
}
