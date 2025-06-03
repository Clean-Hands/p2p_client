//! gui.rs
//! by Lazuli Kleinhans
//! May 30th, 2025
//! CS347 Advanced Software Design

use std::path::PathBuf;

use eframe::egui::{self, Align, CentralPanel, Layout};
use crate::requester;

#[derive(Default)]
pub struct P2PGui {
    error_string: String,
    peer: String,
    save_path: String,
    options: Vec<String>,
    hashes: Vec<String>,
    modify_peers: bool
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
            error_string: String::new(),
            peer: String::new(),
            save_path: String::from(std::env::current_dir().unwrap_or(PathBuf::from(".")).to_str().unwrap_or(".")),
            options: vec![],
            hashes: vec![],
            modify_peers: false
        }
    }
}


impl eframe::App for P2PGui {

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        CentralPanel::default().show(ctx, |ui| {
            ui.heading("Request a file:");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Save path:");
                ui.add_sized([300.0, 20.0], |ui: &mut egui::Ui| {
                    ui.text_edit_singleline(&mut self.save_path)
                });
            });


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
                        let catalog_lines: Vec<Vec<&str>> = catalog_string
                            .lines()
                            .filter(|line| line.contains('.'))
                            .map(|line| line
                                .split('|')
                                .rev()
                                .collect::<Vec<&str>>())
                            .collect();
                        self.hashes = vec![];
                        self.options = vec![];
                        for mut line in catalog_lines {
                            self.hashes.push(line.split_off(2).join("").trim().to_string());
                            self.options.push(line.join("      ").trim().to_string());
                        }
                    }
                }
            });

            ui.group(|ui| {
                ui.with_layout(Layout::top_down_justified(Align::LEFT), |ui| {
                    egui::ScrollArea::vertical()
                        .min_scrolled_width(300.0)
                        // .min_scrolled_height(200.0)
                        .show(ui, |ui| {
                            if self.options.len() > 0 {
                                for i in 0..self.options.len() {
                                    if ui.button(&self.options[i]).double_clicked() {
                                        requester::request_file(self.peer.to_owned(), self.hashes[i].to_owned(), PathBuf::from(&self.save_path));
                                    }
                                }
                            } else {
                                ui.label("Catalog is empty.");
                            }
                        });
                });
            });
            
            // ui.horizontal(|ui| {
            //     ui.label("Slider value:");
            //     ui.add(egui::Slider::new(&mut self.slider_value, 0.0..=100.0));
            //     ui.label(format!("{:.1}", self.slider_value));
            // });
            
            // ui.checkbox(&mut self.checkbox_state, "Enable notifications");
        
            // ui.separator();
            
            // Action buttons
            ui.horizontal(|ui| {
                if ui.button("Add/Remove Peers").clicked() {
                    self.modify_peers = true;
                }
                
                if ui.button("Set Download Folder").clicked() {
                    *self = P2PGui::default();
                }
            });

            if self.error_string != String::new() {
                egui::Window::new("Error")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.heading("Oh no :(");
                        ui.add_space(10.0);
                        ui.label(&self.error_string);
                        if ui.button("aw dang it").clicked() {
                            self.error_string = String::new();
                        }
                    });
            }
            
            // Confirmation dialog
            if self.modify_peers {
                egui::Window::new("Known Peers")
                    .collapsible(false)
                    .resizable(false)
                    .show(ctx, |ui| {
                        ui.label("This is a dialog window!");
                        ui.horizontal(|ui| {
                            if ui.button("OK").clicked() {
                                self.modify_peers = false;
                            }
                            if ui.button("Cancel").clicked() {
                                self.modify_peers = false;
                            }
                        });
                    });
            }
        });
    }
}