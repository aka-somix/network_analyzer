#![cfg_attr(
  all(not(debug_assertions), target_os = "windows"),
  windows_subsystem = "windows"
)]

use std::thread; // NOT USED
use std::time::Duration; // NOT USED
use network_analyzer::sniffer::Sniffer; // NOT USED

use network_analyzer::frontend_api;

fn main() {
  tauri::Builder::default()
    .manage(frontend_api::SnifferState(Default::default()))
    .invoke_handler(tauri::generate_handler![
      frontend_api::get_all_devices, 
      frontend_api::set_device,
      frontend_api::get_device,
      frontend_api::start_sniffer,
      frontend_api::stop_sniffer,
      frontend_api::pause_sniffer,
      frontend_api::get_sniffed_data,
      frontend_api::generate_report,
    ])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}

// ---

/**
 * ! THIS CODE WAS USED FOR TESTING PURPOSE ONLY !
 * -------------------------------------------------
 * This is the old main before implementing a
 * frontend client with TAURI, that just followed a 
 * scripted procedure to record and save data using the
 * sniffer
 * 
 */
fn _old_main_demo() {
    let mut sniffer = Sniffer::new();

    let device = Sniffer::get_all_available_devices().unwrap()[5].clone();
    sniffer.set_device(device).unwrap();
    sniffer.set_file("report.txt".to_string()).unwrap();
    sniffer.set_time_interval(30);
    sniffer.run().unwrap();
    sniffer.run_with_interval().unwrap();
    sniffer.generate_report().unwrap();
    thread::sleep(Duration::from_secs(40));
    // sniffer.stop();
    println!("Finish");
}
