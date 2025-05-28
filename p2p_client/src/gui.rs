use eframe::egui;

// fn main() -> Result<(), eframe::Error> {
//     let options = eframe::NativeOptions {
//         viewport: egui::ViewportBuilder::default().with_inner_size([400.0, 500.0]),
//         ..Default::default()
//     };
    
//     eframe::run_native(
//         "My egui App",
//         options,
//         Box::new(|_cc| Box::new(MyApp::default())),
//     )
// }

pub struct MyApp {
    name: String,
    age: u32,
    show_confirmation_dialog: bool,
    slider_value: f32,
    text_edit_content: String,
    color: Color,
    checkbox_state: bool,
    counter: i32,
}

impl Default for MyApp {
    fn default() -> Self {
        Self {
            name: "Arthur".to_owned(),
            age: 42,
            show_confirmation_dialog: false,
            slider_value: 50.0,
            text_edit_content: "Hello, egui!".to_string(),
            color: Color::Blue,
            checkbox_state: false,
            counter: 0,
        }
    }
}

#[derive(Debug, PartialEq)]
enum Color {
    Red,
    Green,
    Blue,
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("My egui Application");
            ui.separator();

            if ui.add_sized([200.0, 20.0], egui::SelectableLabel::new(self.color == Color::Red, "Red")).clicked() {
                self.color = Color::Red
            }
            ui.group(|ui| {
                ui.new_child(|ui| {
                    ui.selectable_value(&mut self.color, Color::Red, "Red");
                    ui.selectable_value(&mut self.color, Color::Green, "Green");
                    ui.selectable_value(&mut self.color, Color::Blue, "Blue");
                });
            });
            
            // Personal info section
            ui.group(|ui| {
                ui.label("Personal Information:");
                ui.horizontal(|ui| {
                    ui.label("Your nameeeeeeeeeeeeeeeee: ");
                    ui.text_edit_singleline(&mut self.name);
                });
                
                ui.horizontal(|ui| {
                    ui.label("Your age: ");
                    ui.add(egui::Slider::new(&mut self.age, 0..=120));
                });
            });
            
            ui.separator();
            
            // Interactive elements
            ui.group(|ui| {
                ui.label("Interactive Elements:");
                
                ui.horizontal(|ui| {
                    ui.label("Slider value:");
                    ui.add(egui::Slider::new(&mut self.slider_value, 0.0..=100.0));
                    ui.label(format!("{:.1}", self.slider_value));
                });
                
                ui.horizontal(|ui| {
                    ui.label("Text editor:");
                    ui.text_edit_singleline(&mut self.text_edit_content);
                });
                
                ui.checkbox(&mut self.checkbox_state, "Enable notifications");
                
                ui.horizontal(|ui| {
                    if ui.button("Increment Counter").clicked() {
                        self.counter += 1;
                    }
                    if ui.button("Decrement Counter").clicked() {
                        self.counter -= 1;
                    }
                    ui.label(format!("Counter: {}", self.counter));
                });
            });
            
            ui.separator();
            
            // Display current state
            ui.group(|ui| {
                ui.label("Current State:");
                ui.label(format!("Hello {}! You are {} years old.", self.name, self.age));
                ui.label(format!("Checkbox is: {}", if self.checkbox_state { "checked" } else { "unchecked" }));
                ui.label(format!("Text content: '{}'", self.text_edit_content));
            });
            
            ui.separator();
            
            // Action buttons
            ui.horizontal(|ui| {
                if ui.button("Show Dialog").clicked() {
                    self.show_confirmation_dialog = true;
                }
                
                if ui.button("Reset All").clicked() {
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