#[allow(clippy::unit_arg, clippy::unused_unit)]
mod app;

use wasm_bindgen::prelude::*;

/// Entry point for the WASM application.
///
/// This function is called automatically when the WASM module is loaded in the browser.
/// It sets up panic hooks and mounts the Leptos application to the document body.
#[wasm_bindgen(start)]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::mount_to_body(app::App);
}
