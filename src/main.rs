use std::thread;
use std::time::Duration;
use network_analyzer::sniffer::{Sniffer};

fn main() {
    let mut sniffer = Sniffer::new();
        let device = Sniffer::get_all_available_devices().unwrap()[5].clone();
        sniffer.set_device(device);
        sniffer.set_file("report.txt".to_string());
        //non capisco perché però ci mette più di 30 secondi poi a interrompere se lo provi. forse deve aspettare il lock.
        //sniffer.set_time_interval(30);
        sniffer.run();
        //sniffer.run_with_interval();
        sniffer.generate_report();
        thread::sleep(Duration::from_secs(20));
        sniffer.stop();
        thread::sleep(Duration::from_secs(20));
        //println!("Finish");

}
