//! gui.rs
//! by Lazuli Kleinhans
//! May 29th, 2025
//! CS347 Advanced Software Design

use eframe::egui::{self, Align, CentralPanel, Layout};

pub struct MyApp {
    show_confirmation_dialog: bool,
    selection: Option<Files>,
    // name: String,
    // age: u32,
    // slider_value: f32,
    // text_edit_content: String,
    // checkbox_state: bool,
    // counter: i32,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            show_confirmation_dialog: false,
            selection: None,
            // name: "Arthur".to_owned(),
            // age: 42,
            // slider_value: 50.0,
            // text_edit_content: "Hello, egui!".to_string(),
            // checkbox_state: false,
            // counter: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
enum Files {
    Opt0,
    Opt1,
    Opt2,
    Opt3,
    Opt4
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Choose a file to download:");
            ui.separator();

            ui.group(|ui| {                
                ui.with_layout(Layout::top_down_justified(Align::LEFT), |ui| {
                    ui.selectable_value(&mut self.selection, Some(Files::Opt0), "2.39 MiB        moby_dick.txt                           ");
                    ui.selectable_value(&mut self.selection, Some(Files::Opt1), "441 bytes       Cargo.toml                              ");
                    ui.selectable_value(&mut self.selection, Some(Files::Opt2), "3.72 GiB        The.Secret.Lives.of.Mormon.Wives.S02.zip");
                    ui.selectable_value(&mut self.selection, Some(Files::Opt3), "324 bytes       test_copy.txt                           ");
                    ui.selectable_value(&mut self.selection, Some(Files::Opt4), "22.8 KiB        Cargo.lock                              ");
                });
            });
            
            // ui.group(|ui| {
            //     ui.label("Personal Information:");
            //     ui.horizontal(|ui| {
            //         ui.label("Your nameeeeeeeeeeeeeeeee: ");
            //         ui.text_edit_singleline(&mut self.name);
            //     });
                
            //     ui.horizontal(|ui| {
            //         ui.label("Your age: ");
            //         ui.add(egui::Slider::new(&mut self.age, 0..=120));
            //     });
            // });
            
            // ui.separator();
            
            // // Interactive elements
            // ui.group(|ui| {
            //     ui.label("Interactive Elements:");
                
            //     ui.horizontal(|ui| {
            //         ui.label("Slider value:");
            //         ui.add(egui::Slider::new(&mut self.slider_value, 0.0..=100.0));
            //         ui.label(format!("{:.1}", self.slider_value));
            //     });
                
            //     ui.horizontal(|ui| {
            //         ui.label("Text editor:");
            //         ui.text_edit_singleline(&mut self.text_edit_content);
            //     });
                
            //     ui.checkbox(&mut self.checkbox_state, "Enable notifications");
                
            //     ui.horizontal(|ui| {
            //         if ui.button("Increment Counter").clicked() {
            //             self.counter += 1;
            //         }
            //         if ui.button("Decrement Counter").clicked() {
            //             self.counter -= 1;
            //         }
            //         ui.label(format!("Counter: {}", self.counter));
            //     });
            // });
            
            // ui.separator();
            
            // // Display current state
            // ui.group(|ui| {
            //     ui.label("Current State:");
            //     ui.label(format!("Hello {}! You are {} years old.", self.name, self.age));
            //     ui.label(format!("Checkbox is: {}", if self.checkbox_state { "checked" } else { "unchecked" }));
            //     ui.label(format!("Text content: '{}'", self.text_edit_content));
            // });
            
            ui.separator();
            
            // Action buttons
            ui.horizontal(|ui| {
                if ui.button("Add Ip").clicked() {
                    self.show_confirmation_dialog = true;
                }
                
                if ui.button("Request Catalog").clicked() {
                    *self = MyApp::default();
                }
            });
            
            // Confirmation dialog
            if self.show_confirmation_dialog {
                egui::Window::new("Confirmation")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label("This is a dialog window!");
                        ui.horizontal(|ui| {
                            if ui.button("OK").clicked() {
                                self.show_confirmation_dialog = false;
                            }
                            if ui.button("Cancel").clicked() {
                                self.show_confirmation_dialog = false;
                            }
                        });
                    });
            }
        });
    }
}