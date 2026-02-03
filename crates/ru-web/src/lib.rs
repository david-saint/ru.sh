mod app;

use wasm_bindgen::prelude::*;

#[wasm_bindgen(start)]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
