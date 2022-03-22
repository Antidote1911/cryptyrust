#![windows_subsystem = "windows"]

use orbtk::prelude::*;

pub use self::main_state::*;
pub use self::main_view::*;
pub use self::encryption::*;

mod main_state;
mod main_view;
mod encryption;

fn main() {
    Application::from_name("Cryptyrust Encryption")
        .window(move |ctx| {
            Window::new()
                .title("Cryptyrust Encryption")
                .position((100.0, 100.0))
                .size(300.0, 300.0)
                .resizable(true)
                .child(MainView::new().build(ctx))
                .build(ctx)
        })
        .run();
}
