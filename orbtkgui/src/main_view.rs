use orbtk::prelude::*;

use crate::{ MainState, Message };

widget!(
	DropArea: DropHandler {
		text: String
	}
);

impl Template for DropArea {
    fn template(self, id: Entity, ctx: &mut BuildContext) -> Self {

		self.name("Drop Area")
			.text("Hello")
			.child(Stack::new()
				.margin(10)
				.spacing(10)
				.child(ImageWidget::new()
					.image("assets/dnd.png")
					.h_align("center")
					.build(ctx)
				)
				.child(TextBlock::new()
					.text(id)
					.id("path_text")
					.h_align("center")
					.localizable(false)
					.build(ctx)
				)
				.build(ctx)
			)

	}

}

fn build_confirm_button(id: Entity, _ctx: &mut BuildContext) -> Button {
	Button::new()
		.text("Confirm")
		.on_click(move |states, _| {
			states.send_message(Message::Confirm, id);
			true
		})
}

fn build_cancel_button(id: Entity, _ctx: &mut BuildContext) -> Button {
	Button::new()
		.text("Cancel")
		.on_click(move |states, _| {
			states.send_message(Message::ClearFile, id);
			true
		})
}

fn build_error_text(id: Entity) -> TextBlock {
	TextBlock::new()
		.text(("error", id))
		.foreground("tomato")
		.h_align("center")
		.font_size(16)
}

widget!(
    MainView<MainState> {
        title: String,
		target_file: String,
		error: String,
		success: String,
		decrypt_ok: bool
    }
);

impl Template for MainView {
    fn template(self, id: Entity, ctx: &mut BuildContext) -> Self {

		let pager = Pager::new()
			.id("pager")
			.v_align("end")
			.h_align("center")
			.build(ctx);

		let blank_page = Container::new().build(ctx);

		let encrypt_page = Stack::new()
			.child(PasswordBox::new()
				.id("encrypt_password")
                .water_mark("Password...")
                .build(ctx)
            )
			.child(PasswordBox::new()
				.id("encrypt_password2")
                .water_mark("Confirm password...")
                .build(ctx)
            )
			.child(build_confirm_button(id, ctx).build(ctx))
			.child(build_cancel_button(id, ctx).build(ctx))
			.child(build_error_text(id).build(ctx))
			.build(ctx);

		let decrypt_page = Stack::new()
			.child(PasswordBox::new()
				.id("decrypt_password")
				.water_mark("Password...")
				.build(ctx)
			)
			.child(build_confirm_button(id, ctx)
				.id("decrypt_confirm")
				//.enabled(("decrypt_ok", id))
				.build(ctx)
			)
			.child(build_cancel_button(id, ctx).build(ctx))
			.child(build_error_text(id).build(ctx))
			.build(ctx);

		let success_page = TextBlock::new()
			.text(("success", id))
			.foreground("lime")
			.h_align("center")
			.v_align("center")
			.font_size(16)
			.build(ctx);


		let drop_area = DropArea::new()
			.on_drop_file(move |states,path,_| {
				states.send_message(Message::NewFile(path), id);
				true
			})
			.text(("target_file", id))
			.v_align("stretch")
			.h_align("center")
			.build(ctx);

        ctx.append_child(pager, blank_page);
        ctx.append_child(pager, encrypt_page);
        ctx.append_child(pager, decrypt_page);
		ctx.append_child(pager, success_page);

		self.name("MainView")
			.target_file("No file")
			.decrypt_ok(true)
			.child(Stack::new()
				.margin(10)
				.spacing(10)
				.child(drop_area)
				.child(pager)
				.build(ctx)
			)
    }
}

