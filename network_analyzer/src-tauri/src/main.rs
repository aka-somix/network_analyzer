#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use network_analyzer::frontend_api;

fn main() {
  tauri::Builder::default()
    .invoke_handler(tauri::generate_handler![frontend_api::get_all_devices])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
