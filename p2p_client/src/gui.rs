//! gui.rs
//! by Lazuli Kleinhans
//! May 30th, 2025
//! CS347 Advanced Software Design

use std::path::PathBuf;

use eframe::egui::{self, Align, CentralPanel, Layout};
use crate::requester;

#[derive(Default)]
pub struct P2PGui {
    // show_confirmation_dialog: bool,
    error_string: String,
    peer: String,
    options: [String; 6],
    hashes: [String; 6]
    // slider_value: f32,
    // checkbox_state: bool,
}


impl P2PGui {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        // TODO
        // Customize egui here with cc.egui_ctx.set_fonts and cc.egui_ctx.set_visuals.
        // Restore app state using cc.storage (requires the "persistence" feature).
        // Use the cc.gl (a glow::Context) to create graphics shaders and buffers that you can use
        // for e.g. egui::PaintCallback.
        Self::default()
    }
    
    fn default() -> Self {
        Self {
            // show_confirmation_dialog: false,
            error_string: String::new(),
            peer: String::new(),
            options: Default::default(),
            hashes: Default::default(),
            // age: 42,
            // slider_value: 50.0,
            // checkbox_state: false,
            // counter: 0,
        }
    }
}


impl eframe::App for P2PGui {

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Request a file:");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Peer:");
                ui.add_sized([200.0, 20.0], |ui: &mut egui::Ui| {
                    ui.text_edit_singleline(&mut self.peer)
                });
                if ui.button("Request Catalog").clicked() {
                    if let Err(e) = requester::ping_addr(&self.peer) {
                        self.error_string = e
                    } else {
                        let catalog_string = match requester::request_catalog(&self.peer) {
                            Ok(c) => c,
                            Err(e) => {
                                self.error_string = e;
                                String::new()
                            }
                        };
                        // let catalog_lines = catalog_string.lines();
                        let catalog_lines: Vec<Vec<&str>> = catalog_string
                            .lines()
                            .filter(|line| line.contains('.'))
                            .map(|line| line
                                .split('|')
                                .rev()
                                .collect::<Vec<&str>>())
                            .collect();
                        for line in catalog_lines.iter().enumerate() {
                            let mut line_contents = line.1.to_owned();
                            self.hashes[line.0] = line_contents.split_off(2).join("").trim().to_string();
                            self.options[line.0] = line_contents.join("      ").trim().to_string();
                        }
                    }
                }
            });

            ui.group(|ui| {                
                ui.with_layout(Layout::top_down_justified(Align::LEFT), |ui| {
                    if ui.button(&self.options[0]).double_clicked() {
                        requester::request_file(self.peer.to_owned(), self.hashes[0].to_owned(), PathBuf::from("."));
                    }
                    if ui.button(&self.options[1]).double_clicked() {
                        requester::request_file(self.peer.to_owned(), self.hashes[1].to_owned(), PathBuf::from("."));
                    }
                    if ui.button(&self.options[2]).double_clicked() {
                        requester::request_file(self.peer.to_owned(), self.hashes[2].to_owned(), PathBuf::from("."));
                    }
                    if ui.button(&self.options[3]).double_clicked() {
                        requester::request_file(self.peer.to_owned(), self.hashes[3].to_owned(), PathBuf::from("."));
                    }
                    if ui.button(&self.options[4]).double_clicked() {
                        requester::request_file(self.peer.to_owned(), self.hashes[4].to_owned(), PathBuf::from("."));
                    }
                    if ui.button(&self.options[5]).double_clicked() {
                        requester::request_file(self.peer.to_owned(), self.hashes[5].to_owned(), PathBuf::from("."));
                    }
                });
            });
            
            // ui.horizontal(|ui| {
            //     ui.label("Slider value:");
            //     ui.add(egui::Slider::new(&mut self.slider_value, 0.0..=100.0));
            //     ui.label(format!("{:.1}", self.slider_value));
            // });
            
            // ui.checkbox(&mut self.checkbox_state, "Enable notifications");
        
            // ui.separator();
            
            // // Action buttons
            // ui.horizontal(|ui| {
            //     if ui.button("Add Ip").clicked() {
            //         self.show_confirmation_dialog = true;
            //     }
                
            //     if ui.button("Reset").clicked() {
            //         *self = P2PGui::default();
            //     }
            // });

            if self.error_string != String::new() {
                egui::Window::new("Error")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.heading("Oh no :(");
                        ui.add_space(10.0);
                        ui.label(&self.error_string);
                        if ui.button("aw dang").clicked() {
                            self.error_string = String::new();
                        }
                    });
            }
            
            // // Confirmation dialog
            // if self.show_confirmation_dialog {
            //     egui::Window::new("Confirmation")
            //         .collapsible(false)
            //         .resizable(false)
            //         .show(ctx, |ui| {
            //             ui.label("This is a dialog window!");
            //             ui.horizontal(|ui| {
            //                 if ui.button("OK").clicked() {
            //                     self.show_confirmation_dialog = false;
            //                 }
            //                 if ui.button("Cancel").clicked() {
            //                     self.show_confirmation_dialog = false;
            //                 }
            //             });
            //         });
            // }
        });
    }
}