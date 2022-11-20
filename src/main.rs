use std::thread;
use std::time::Duration;
use network_analyzer::sniffer::{Sniffer};

fn main() {
    let mut sniffer = Sniffer::new();
        let device = Sniffer::get_all_available_devices().unwrap()[5].clone();
        sniffer.set_device(device);
        sniffer.set_file("marracash12345.txt".to_string());
        sniffer.run();
        thread::sleep(Duration::from_secs(10));
        sniffer.generate_report();
        println!("Finish");

}
