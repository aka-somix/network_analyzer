use std::thread;
use std::time::Duration;
use network_analyzer::sniffer::Sniffer;

fn main() {
    println!("Hello, world!");
    let mut sniffer = Sniffer::new();
    sniffer.set_file("prova.txt".to_string());
    let device = Sniffer::get_all_available_devices().unwrap()[0].clone();
    sniffer.set_device(device);
    sniffer.run();
    thread::sleep(Duration::from_secs(3));
    sniffer.generate_report();
}
