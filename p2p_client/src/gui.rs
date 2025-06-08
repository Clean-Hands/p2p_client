//! gui.rs
//! by Lazuli Kleinhans, Liam Keane, Ruben Boero
//! June 6th, 2025
//! CS347 Advanced Software Design

use crate::listener;
use crate::requester;
use eframe::egui::{self, Align, CentralPanel, Key, Layout, TextEdit, TopBottomPanel, Vec2};
use size::Size;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use rfd::FileDialog;

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
    catalog: Option<HashMap<String, listener::FileInfo>>,
    catalog_width: usize,
    catalog_edit_mode: bool,
    new_catalog: HashMap<String, listener::FileInfo>
}



impl P2PGui {
    fn show_request_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("Request a file:");
        ui.separator();

        ui.horizontal(|ui| {
            ui.label("Save path:");
            ui.add(
                TextEdit::singleline(&mut self.save_path)
                    .desired_width(f32::INFINITY)
            );
        });
        ui.add_space(5.0);
        ui.horizontal(|ui| {
            ui.label("Peer:");
            let peer_input = ui.add(
                TextEdit::singleline(&mut self.peer)
                    .desired_width(227.0) // set width to line up Request Catalog button with edge of window
                    .hint_text("Enter peer alias or IP"),
            );
            let enter_pressed = ui.ctx().input(|i| i.key_pressed(Key::Enter)) && peer_input.lost_focus();

            if enter_pressed || ui.button("Request Catalog").clicked() {                
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
        ui.add_space(5.0);

        // Displaying the requested catalog and its available files
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
                                        PathBuf::from(&self.save_path),
                                    );
                                }
                            }
                        } else {
                            ui.label("Catalog is empty.");
                        }
                    });
            });
        });
        ui.add_space(5.0);

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
        ui.heading("Local Catalog:");
        ui.separator();
        ui.group(|ui| {
            egui::ScrollArea::both()
                .min_scrolled_width(350.0)
                .show(ui, |ui| {
                    ui.allocate_ui_with_layout(
                        Vec2::new(self.catalog_width as f32, 0.0), // fixed width, auto height
                        Layout::top_down(Align::LEFT),
                        |ui| {
                            // refer to saved catalog to display available files (saved in update())
                            match &self.catalog {
                                Some(catalog_map) => {
                                    if catalog_map.is_empty() {
                                        ui.label("Your catalog is empty.");
                                    } else {
                                        let catalog_vec: Vec<_> = catalog_map.iter().collect();

                                        let max_name_len = catalog_vec
                                            .iter()
                                            .filter_map(|(_, info)| {
                                                Path::new(&info.file_path)
                                                    .file_name()
                                                    .and_then(|n| n.to_str())
                                                    .map(|name| name.len())
                                            })
                                            .max()
                                            .unwrap_or("File Name".len());

                                        let max_size_len = catalog_vec
                                            .iter()
                                            .map(|(_, info)| {
                                                Size::from_bytes(info.file_size).to_string().len()
                                            })
                                            .max()
                                            .unwrap_or("Size".len());

                                        // draw table header
                                        ui.monospace(format!(
                                            "{:<max_name_len$}  {:<max_size_len$}",
                                            "File Name", "Size",
                                        ));

                                        self.catalog_width = (max_name_len + max_size_len) * 8;

                                        ui.separator();

                                        // draw each row
                                        for (_hash, info) in catalog_vec {
                                            let file_name = Path::new(&info.file_path)
                                                .file_name()
                                                .and_then(|n| n.to_str())
                                                .unwrap_or("invalid UTF-8");
                                            let file_size =
                                                Size::from_bytes(info.file_size).to_string();

                                            let row_text = format!(
                                                "{:<max_name_len$}  {:<max_size_len$}",
                                                file_name, file_size,
                                            );

                                            // show the full file path when you hover over a row
                                            ui.monospace(row_text).on_hover_text(&info.file_path);
                                        }
                                    }
                                }
                                None => {
                                    ui.label("Failed to load catalog.");
                                }
                            }
                        },
                    );
                });
        });
        ui.horizontal(|ui| {
            if ui.button("Add/Remove Catalog Files").clicked() {
                self.new_catalog = match &self.catalog {
                    Some(map) => map.clone(),
                    None => HashMap::new(),
                };
                self.catalog_edit_mode = true;
            }
        });
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
                    .unwrap_or("."),
            ),
            file_options: vec![],
            peer_vec: vec![],
            new_peer_vec: vec![],
            modify_peers: false,
            current_tab: AppTab::Request,
            catalog: None,
            catalog_width: 500,
            catalog_edit_mode: false,
            new_catalog: HashMap::new(),
        }
    }
}



impl eframe::App for P2PGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        let previous_tab = self.current_tab;

        // Top panel for navigation tabs
        TopBottomPanel::top("nav_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if ui
                    .selectable_label(self.current_tab == AppTab::Request, "Request Files")
                    .clicked() {
                    self.current_tab = AppTab::Request;
                }

                if ui
                    .selectable_value(&mut self.current_tab, AppTab::Listen, "Share Files")
                    .clicked() {
                    self.current_tab = AppTab::Listen;
                }
            });
        });

        // only reload catalog when switching to listen tab
        if previous_tab != self.current_tab && self.current_tab == AppTab::Listen {
            let catalog_path = match listener::get_catalog_path() {
                Ok(p) => p,
                Err(e) => {
                    self.error_string = e;
                    PathBuf::new()
                }
            };

            // save catalog to be used later
            self.catalog = match listener::get_deserialized_catalog(&catalog_path) {
                Ok(c) => Some(c),
                Err(e) => {
                    self.error_string = e;
                    None
                }
            };
        }

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
                    ui.add_space(10.0);
                    if ui.button("aw dang it").clicked() {
                        self.error_string = String::new();
                    }
                });
        }

        // Modify peer dialog window
        if self.modify_peers {
            egui::Window::new("Known Peers")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.group(|ui| {
                        egui::ScrollArea::vertical()
                            .max_height(100.0)
                            .show(ui, |ui| {
                                if self.peer_vec != vec![] {
                                    for (new_alias, new_addr) in &mut self.new_peer_vec {
                                        // if new_alias.len() != 0 || new_addr.len() != 0 {
                                            ui.horizontal(|ui| {
                                                ui.add_sized([150.0, 20.0],
                                                    TextEdit::singleline(new_alias).hint_text("Alias")
                                                );
                                                ui.add_sized([120.0, 20.0],
                                                    TextEdit::singleline(new_addr).hint_text("IP Address")
                                                );
                                                if ui.button("🗑").clicked() {
                                                    new_alias.clear();
                                                    new_addr.clear();
                                                }
                                            });
                                        // }
                                    }
                                } else {
                                    ui.label("Peer list is empty.");
                                }
                            });
                            ui.add_space(5.0);
                            ui.allocate_ui_with_layout(Vec2::new(0.0, 0.0), Layout::left_to_right(Align::Center), |ui| {
                                if ui.add_sized(Vec2::new(305.0, 0.0), egui::Button::new("+ Add New Peer")).clicked() {
                                    // self.new_peer_vec.push(("New Alias".to_string(), "New IP Address".to_string()));
                                    self.new_peer_vec.push(("".to_string(), "".to_string()));
                                }
                            });
                    });
                    ui.horizontal(|ui| {
                        if ui.button("Save").clicked() {
                            for i in 0..self.new_peer_vec.len() {

                                let (new_alias, new_addr) = &self.new_peer_vec[i];
                                // if a peer was added, add new peer to local peer list
                                if i >= self.peer_vec.len() {
                                    if new_alias.len() > 0 && new_addr.len() > 0 {
                                        if let Err(e) = requester::add_peer(&new_alias, &new_addr) {
                                            self.error_string = format!("Failed to add {new_alias} ({new_addr}) to list of peers: {e}");
                                        }
                                    }
                                    continue;
                                }

                                let (alias, addr) = &self.peer_vec[i];
                                // if a peer was deleted, remove peer from local peer list
                                if new_alias.len() == 0 && new_addr.len() == 0 {
                                    if let Err(e) = requester::remove_from_peer_list(&alias) {
                                        self.error_string = format!("Failed to remove {alias} from list of peers: {e}");
                                    }
                                    continue;
                                }

                                // if a peer was modified, update the local peer list
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

        if self.catalog_edit_mode {
            egui::Window::new("Edit Catalog")
                .collapsible(false)
                .resizable(false)
                .show(ctx, |ui| {
                    ui.group(|ui| {
                        egui::ScrollArea::vertical()
                            .max_height(100.0)
                            .show(ui, |ui| {
                                let mut to_remove = Vec::new();
                                for (hash, info) in self.new_catalog.iter() {
                                    ui.horizontal(|ui| {
                                        let total_width = ui.available_width();
                                        let delete_button_width = 40.0;
                                        let file_name_width = total_width - delete_button_width - ui.spacing().item_spacing.x;

                                        let file_name = std::path::Path::new(&info.file_path)
                                            .file_name()
                                            .and_then(|n| n.to_str())
                                            .unwrap_or("");

                                        ui.add_sized(
                                            [file_name_width, 20.0],
                                            TextEdit::singleline(&mut file_name.to_string())
                                                .interactive(false),
                                        )
                                        .on_hover_text(&info.file_path);

                                        if ui.button("🗑").clicked() {
                                            if let Err(e) = listener::remove_file_from_catalog(hash) {
                                                self.error_string = format!("Error removing from catalog: {e}");
                                            } else {
                                                to_remove.push(hash.clone());
                                            }
                                        }
                                    });
                                }
                                // remove deleted items from the edit window's version of the catalog
                                for hash in to_remove {
                                    self.new_catalog.remove(&hash);
                                }
                            });

                        ui.allocate_ui_with_layout(
                            Vec2::new(0.0, 0.0),
                            Layout::left_to_right(Align::Center),
                            |ui| {
                                if ui.add_sized(Vec2::new(305.0, 0.0), egui::Button::new("+ Add File")).clicked() {
                                    if let Some(picked_path) = FileDialog::new().pick_file() {
                                        let path_str = picked_path.to_string_lossy().to_string();

                                        if let Err(e) = listener::add_file_to_catalog(&path_str) {
                                            self.error_string = format!("Failed to add to catalog: {e}");
                                        } else {
                                            // update catalog
                                            // probably better to do this without needing to re-read the 
                                            // catalog from disk. would need to manually insert all parts 
                                            // of the dictionary entry
                                            if let Some(catalog_path) = listener::get_catalog_path().ok() {
                                                if let Ok(catalog_map) = listener::get_deserialized_catalog(&catalog_path) {
                                                    // need to update new catalog as well to show changes 
                                                    // immediately
                                                    self.new_catalog = catalog_map;
                                                }
                                            }
                                        }
                                    }
                                }

                            },
                        );
                    });

                    ui.horizontal(|ui| {
                        if ui.button("Cancel").clicked() {
                            // update catalog to reflect removed files
                            self.catalog = Some(self.new_catalog.clone());

                            self.catalog_edit_mode = false;
                        }
                    });
                });
        }
    }
}