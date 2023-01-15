/**
 * Lib.rs centrally exports all the modules for the package
 */

// Backend Logic for network sniffing
mod net_logic;
pub use crate::net_logic::sniffer;

// Frontend Integration using Tauri
mod tauri;
pub use crate::tauri::frontend_api;
