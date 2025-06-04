//! gui.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! June 4th, 2025
//! CS347 Advanced Software Design

use crate::requester;
use eframe::egui::{self, Align, CentralPanel, Layout, TopBottomPanel};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Default, Debug, Clone, Copy, PartialEq)]
enum AppTab {
    #[default]
    Request,
    Listen,
}

#[derive(Default)]
pub struct P2PGui {
    error_string: String,
    peer: String,
    save_path: String,
    file_options: Vec<(String, String)>,
    peer_vec: Vec<(String, String)>,
    new_peer_vec: Vec<(String, String)>,
    modify_peers: bool,
    current_tab: AppTab,
}

impl P2PGui {
    fn show_request_tab(&mut self, ui: &mut egui::Ui) {
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
            let peer_input = ui.add(
                egui::TextEdit::singleline(&mut self.peer)
                    .desired_width(200.0)
                    .hint_text("Enter peer alias or IP")
            );
            if peer_input.lost_focus() || ui.button("Request Catalog").clicked() {
                if let Err(e) = requester::ping_peer(&self.peer) {
                    self.error_string = e;
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
                        .map(|line| line.split('|').rev().collect::<Vec<&str>>())
                        .collect();

                    self.file_options = vec![];
                    for mut line in catalog_lines {
                        let hash = line.split_off(2).join("").trim().to_string();
                        let file_info = line.join("      ").trim().to_string();
                        self.file_options.push((file_info, hash));
                    }
                }
            }
        });

        ui.group(|ui| {
            ui.with_layout(Layout::top_down_justified(Align::LEFT), |ui| {
                egui::ScrollArea::vertical()
                    .min_scrolled_width(300.0)
                    .show(ui, |ui| {
                        if self.file_options.len() > 0 {
                            for i in 0..self.file_options.len() {
                                if ui.button(&self.file_options[i].0).double_clicked() {
                                    requester::request_file(
                                        self.peer.to_owned(),
                                        self.file_options[i].1.to_owned(),
                                        PathBuf::from(&self.save_path)
                                    );
                                }
                            }
                        } else {
                            ui.label("Catalog is empty.");
                        }
                    });
            });
        });

        ui.horizontal(|ui| {
            if ui.button("Add/Remove Peers").clicked() {
                self.peer_vec = vec![];
                let peer_hashmap = match requester::get_deserialized_peer_list() {
                    Ok(c) => c,
                    Err(e) => {
                        self.error_string = e;
                        HashMap::new()
                    }
                };

                for peer in peer_hashmap {
                    self.peer_vec.push(peer.to_owned());
                }
                self.new_peer_vec = self.peer_vec.clone();
                self.modify_peers = true;
            }

            // if ui.button("Reset GUI").clicked() {
            //     *self = P2PGui::default();
            // }
        });
    }

    fn show_listen_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Share files (Listen mode):");
        ui.separator();
    }

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
            save_path: String::from(
                std::env::current_dir()
                    .unwrap_or(PathBuf::from("."))
                    .to_str()
                    .unwrap_or(".")
            ),
            file_options: vec![],
            peer_vec: vec![],
            new_peer_vec: vec![],
            modify_peers: false,
            current_tab: AppTab::Request,
        }
    }
}

impl eframe::App for P2PGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Top panel for navigation tabs
        TopBottomPanel::top("nav_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, AppTab::Request, "Request Files");
                ui.selectable_value(&mut self.current_tab, AppTab::Listen, "Share Files");
            });
        });

        // Main content panel
        CentralPanel::default().show(ctx, |ui| match self.current_tab {
            AppTab::Request => self.show_request_tab(ui),
            AppTab::Listen => self.show_listen_tab(ui),
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
                    ui.group(|ui| {
                        ui.with_layout(Layout::top_down_justified(Align::LEFT), |ui| {
                            egui::ScrollArea::vertical()
                                .min_scrolled_width(300.0)
                                .show(ui, |ui| {
                                    if self.peer_vec != vec![] {
                                        for (alias, addr) in &mut self.new_peer_vec {
                                            ui.horizontal(|ui| {
                                                ui.add_sized([150.0, 20.0], |ui: &mut egui::Ui| {
                                                    ui.text_edit_singleline(alias)
                                                });
                                                ui.add_sized([150.0, 20.0], |ui: &mut egui::Ui| {
                                                    ui.text_edit_singleline(addr)
                                                });
                                            });
                                        }
                                    } else {
                                        ui.label("Peer list is empty.");
                                    }
                                });
                        });
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            for i in 0..self.peer_vec.len() {
                                let (alias, addr) = &self.peer_vec[i];
                                let (new_alias, new_addr) = &self.new_peer_vec[i];
                                if alias != new_alias || addr != new_addr {
                                    if let Err(e) = requester::remove_from_peer_list(&alias) {
                                        self.error_string = format!("Failed to remove {alias} from list of peers: {e}");
                                    }
                                    if let Err(e) = requester::add_peer(&new_alias, &new_addr) {
                                        self.error_string = format!("Failed to add {new_alias} ({new_addr}) to list of peers: {e}");
                                    }
                                }
                            }
                            self.modify_peers = false;
                        }
                        if ui.button("Cancel").clicked() {
                            // close the peers window without submitting any changes
                            self.modify_peers = false;
                        }
                    });
                });
        }
    }
}