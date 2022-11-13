// analyzing incoming and outgoing traffic through the network interfaces of a computer.

extern crate core;
extern crate prettytable;
pub mod sniffer {
    use std::collections::HashMap;
    use std::{fmt, thread};
    use std::fmt::{Display, Formatter};
    use std::fs::File;
    use std::path::Path;
    use std::sync::{Arc, Condvar, Mutex};
    use std::sync::mpsc::channel;
    use std::time::Duration;
    use pcap::{Capture, Device, Packet};
    use pktparse::{ethernet, ipv4, ipv6};
    use pktparse::ethernet::EtherType;
    use pktparse::ip::IPProtocol;
    use pktparse::ipv4::{IPv4Header, parse_ipv4_header};
    use pktparse::ipv6::{IPv6Header, parse_ipv6_header};
    use pktparse::tcp::parse_tcp_header;
    use pktparse::udp::parse_udp_header;


    //ERRORE CUSTOMIZZATO DURANTE LA DECODIFICA DEL PACCHETTO
    #[derive(Debug, Clone)]
    pub enum NetworkAnalyzerError {
        PacketDecodeError(String),
        UserError(String),
        UserWarning(String),
        PcapError(String)
    }

    impl Display for NetworkAnalyzerError {
        fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
            match self {
                NetworkAnalyzerError::PacketDecodeError(e)  => write!(f, "{}", e),
                NetworkAnalyzerError::UserError(e)  => write!(f, "{}", e),
                NetworkAnalyzerError::UserWarning(e)  => write!(f, "{}", e),
                NetworkAnalyzerError::PcapError(e)  => write!(f, "{}", e),
            }
        }
    }

    //ENUM CHE SERVE PER DIRE SE IL PACCHETTO E' STATO INVIATO O RICEVUTO
    #[derive(Debug, Clone, PartialEq)]
    pub enum Direction {
        Received,
        Transmitted
    }

    //INFO ESTRATTE CHE VERRANNO STAMPATE NEL REPORT
    #[derive(Debug, Clone)]
    pub struct PacketResult {
        address: String,
        port: u16,
        protocol: IPProtocol,
        byte_transmitted: usize,
        direction:Direction
    }

    impl PacketResult {
        pub fn new(address: String, port: u16, protocol: IPProtocol, byte_transmitted: usize, direction : Direction) -> Self {
            PacketResult { address, port, protocol, byte_transmitted, direction}
        }

        pub fn get_address(&self) -> String { return self.address.clone() }
        pub fn get_port(&self) -> u16 { return self.port }
        pub fn get_protocol(&self) -> IPProtocol { return self.protocol.clone() }
        pub fn get_byte_transmitted(&self) -> usize { return self.byte_transmitted }
        pub fn get_direction(&self) -> Direction { return self.direction.clone() }
    }

    fn get_direction_ipv4(header: IPv4Header, device: Device) -> Direction {
        if device.addresses.iter().any(|a| a.addr.to_string() == header.dest_addr.to_string()) {
            Direction::Transmitted
        } else { Direction::Received }
    }

    fn  get_direction_ipv6(header: IPv6Header, device: Device) -> Direction {
        if device.addresses.iter().any(|a| a.addr.to_string() == header.dest_addr.to_string()) {
            Direction::Transmitted
        } else { Direction::Received }
    }

    /*
    fn extract_info_from_packet(device: Device, packet : Packet) -> Result<PacketResult, NetworkAnalyzerError> {
        let (remaining, eth_frame) = ethernet::parse_ethernet_frame(packet.data);

        return match eth_frame.ethertype {
            EtherType::IPv4 => {
                let (remaining, ipv4_header) = parse_ipv4_header(remaining);
                let direction = get_direction_ipv4(ipv4_header.clone(), device.clone());

                match ipv4_header.protocol {
                    IPProtocol::UDP => {
                        let (remaining, udp_header) = parse_udp_header(remaining);
                        let byte_transmitted = udp_header.length; //TODO penso sia sbagliato, è la lunghezza dell'header non del payload immagino
                        let address;
                        let port;
                        if direction == Direction::Received {
                            address = ipv4_header.source_addr.to_string();
                            port = udp_header.source_port;
                        } else {
                            address = ipv4_header.dest_addr.to_string();
                            port = udp_header.dest_port;
                        }
                        Ok(PacketResult::new(address, port, IPProtocol::UDP, byte_transmitted, direction))
                    },
                    IPProtocol::TCP => {
                        let (remaining, tcp_header) = parse_tcp_header(remaining);
                        let byte_transmitted = tcp_header.length; //TODO penso sia sbagliato, è la lunghezza dell'header non del payload immagino
                        let address;
                        let port;
                        if direction == Direction::Received {
                            address = ipv4_header.source_addr.to_string();
                            port = tcp_header.source_port;
                        } else {
                            address = ipv4_header.dest_addr.to_string();
                            port = tcp_header.dest_port;
                        }
                        Ok(PacketResult::new(address, port, IPProtocol::TCP, byte_transmitted, direction))
                    },
                    _ => NetworkAnalyzerError::PacketDecodeError("Trasport level protocol not found. Only UDP and TCP are permitted.".parse().unwrap()),
                        //Err(PacketDecodeError { msg: format!("Trasport level protocol not found. Only UDP and TCP are permitted.") }),
                }
            },
            EtherType::Ipv6 => {
                let (remaining, ipv6_header) = parse_ipv6_header(remaining);
                let direction = get_direction_ipv6(ipv6_header.clone(), device.clone());

                match ipv6_header.protocol {
                    IPProtocol::UDP => {
                        let (remaining, udp_header) = parse_udp_header(remaining);
                        let byte_transmitted = udp_header.length; //TODO penso sia sbagliato, è la lunghezza dell'header non del payload immagino
                        let address;
                        let port;
                        if direction == Direction::Received {
                            address = ipv6_header.source_addr.to_string();
                            port = udp_header.source_port;
                        } else {
                            address = ipv6_header.dest_addr.to_string();
                            port = udp_header.dest_port;
                        }
                        Ok(PacketResult::new(address, port, IPProtocol::UDP, byte_transmitted, direction))
                    },
                    IPProtocol::TCP => {
                        let (remaining, tcp_header) = parse_tcp_header(remaining);
                        let byte_transmitted = tcp_header.length; //TODO penso sia sbagliato, è la lunghezza dell'header non del payload immagino
                        let address;
                        let port;
                        if direction == Direction::Received {
                            address = ipv6_header.source_addr.to_string();
                            port = tcp_header.source_port;
                        } else {
                            address = ipv6_header.dest_addr.to_string();
                            port = tcp_header.dest_port;
                        }
                        Ok(PacketResult::new(address, port, IPProtocol::TCP, byte_transmitted, direction))
                    },
                    _ => NetworkAnalyzerError::PacketDecodeError("Trasport level protocol not found. Only UDP and TCP are permitted.".parse().unwrap()),
                }
            },
            _ => NetworkAnalyzerError::PacketDecodeError("Ip level protocol not found. Only IPv4 and IPv6 are permitted.".parse().unwrap()),
            //_ => Err(PacketDecodeError { msg: format!("Ip level protocol not found. Only IPv4 and IPv6 are permitted.") }),
        };
    }
     */

    // i diversi stati dell'applicazione
    #[derive(PartialEq, Debug, Clone, Eq)]
    pub enum Status {
        // Al bootstrap o quando viene salvato il report
        Idle,
        // Lo sniffing può essere messo in pausa usando il metodo wait
        Waiting,
        // Processo in esecuzione
        Running,
        // Stato di errore
        Error(String)
    }

    pub struct Sniffer {
        device: Option<pcap::Device>,
        status: Arc<(Mutex<Status>, Condvar)>,
        file: Option<String>,
        time_interval: u64,
        hashmap: Arc<Mutex<HashMap<(String, u16), (IPProtocol, usize, u64, u64)>>>,
    }

    impl Sniffer {

        pub fn new() -> Self {
            return Sniffer {
                device: None,
                status: Arc::new((Mutex::new(Status::Idle), Condvar::new())),
                file: None,
                time_interval: 0,
                hashmap: Arc::new(Mutex::new(HashMap::new()))
            }
        }

        pub fn get_status(&self) -> Status {
            let s = self.status.0.lock().unwrap();
            return (*s).clone();
        }

        pub fn set_status(&self, status: Status) -> () {
            let mut s = self.status.0.lock().unwrap();
            *s = status;
        }

        pub fn get_device(&self) -> &Option<pcap::Device> {
            &self.device
        }

        pub fn set_device(&mut self, device: pcap::Device) -> Result<(), NetworkAnalyzerError> {
            return match Sniffer::get_all_available_devices() {
                Ok(devices) => {
                    for dev in &devices {
                        if dev.name == device.name {
                            self.device = Some(device);
                            return Ok(())
                        }
                    }
                    return Err(NetworkAnalyzerError::UserError("The device selected is not in list ...".to_string()))
                },
                Err(error) => Err(error)
            }
        }

        pub fn get_hashmap(&self) -> &Arc<Mutex<HashMap<(String, u16), (IPProtocol, usize, u64, u64)>>> {
            &self.hashmap
        }

        pub fn get_file(&self) -> Option<String> {
            self.file.clone()
        }

        pub fn set_file(&mut self, filename: String) -> Result<(), NetworkAnalyzerError> {
            let file = File::create(Path::new(&filename));
            match file {
                Ok(_) => {
                    self.file = Some(filename);
                    Ok(())
                },
                Err(_) => Err(NetworkAnalyzerError::UserError("Error while file creation.".to_string()))
            }
        }

        pub fn get_all_available_devices() -> Result<Vec<pcap::Device>, NetworkAnalyzerError> {
            let devices = pcap::Device::list();
            return match devices {
                Ok(devices) => Ok(devices),
                Err(e) => Err(NetworkAnalyzerError::PcapError(e.to_string())),
            }
        }

        pub fn wait(&mut self) -> Result<(), NetworkAnalyzerError> {
            let status = self.get_status();
            match &status {
                Status::Running => {
                    self.set_status(Status::Waiting);
                    Ok(())
                },
                Status::Error(error) => Err(NetworkAnalyzerError::UserError(error.to_string())),
                Status::Idle => { return Err(NetworkAnalyzerError::UserWarning("There is no sniffing process in execution.".to_string())); },
                Status::Waiting => { return Err(NetworkAnalyzerError::UserWarning("The sniffing process is already stopped.".to_string())); }
            }
        }

        pub fn restart(&mut self) -> Result<(), NetworkAnalyzerError> {
            let status = self.get_status();
            match &status {
                Status::Waiting => {
                    self.set_status(Status::Running);
                    self.status.1.notify_all();
                    Ok(())
                },
                Status::Error(error) => Err(NetworkAnalyzerError::UserError(error.to_string())),
                Status::Idle => { return Err(NetworkAnalyzerError::UserWarning("The sniffing process is already stopped.".to_string())); },
                Status::Running => { return Err(NetworkAnalyzerError::UserWarning("The sniffing process is already running.".to_string())); }
            }
        }

        pub fn run(&mut self) -> Result<(), NetworkAnalyzerError> {
            let status = self.get_status();
            //TODO il check sullo status si potrebbe fare in un metodo a parte e qui implementare solo i passi successivi
            // se questo metodo non ritorna error
            return match &status {
                Status::Idle => {
                    if self.get_file().is_none() {
                        return Err(NetworkAnalyzerError::UserError("FileName is blank.".to_string()));
                    }
                    if self.get_device().is_none() {
                        return Err(NetworkAnalyzerError::UserError("Missing device".to_string()));
                    }

                    self.set_status(Status::Running);
                    let device = self.get_device().clone().unwrap();

                    //let (tx, rx) = channel();
                    let tuple = self.status.clone();

                    let sender = thread::spawn(move || {
                        let mut cap = Capture::from_device(device).unwrap().promisc(true).open().unwrap();
                        loop {
                            let mut _s = tuple.0.lock().unwrap();
                            let status = (*_s).clone();

                            match &status {
                                Status::Running => {
                                    drop(_s);
                                    match cap.next_packet() {
                                        Ok(packet) => {
                                            /*
                                            let result = tx.send(packet);
                                            match result {
                                                Ok(()) => continue,
                                                Err(error) => NetworkAnalyzerError::UserError(error.to_string())
                                            };

                                             */
                                        },
                                        Err(error) => {
                                            NetworkAnalyzerError::PcapError(error.to_string());
                                        }
                                    }
                                },
                                Status::Waiting => {
                                    _s = tuple.1.wait_while(_s, |status| { *status == Status::Waiting }).unwrap();
                                },
                                Status::Idle => { break; }
                                Status::Error(e) => { println!("{}", e) }
                            }
                            thread::sleep(Duration::from_millis(1));
                        };
                    });

                    //TODO QUESTO SI POTREBBE SPOSTARE IN UN ALTRO METODO VOLENDO
                    let device = self.get_device().clone().unwrap();
                    let hashmap = self.get_hashmap().clone();

                    let reader = thread::spawn(move || {
                        //while let Ok(packet) = rx.recv() {
                            /*
                            match extract_info_from_packet(device.clone(), packet) {
                                Ok(info) => {
                                    let mut hm = hashmap.lock().unwrap();
                                    let existing_pkt = hm.get(&(info.get_address(), info.get_port()));
                                    match existing_pkt {
                                        None => {
                                            hm.insert((info.get_address(), info.get_port()),
                                                      (info.get_protocol(), info.get_byte_transmitted(), info.get_time_stamp().into(), info.get_time_stamp().into()));
                                        },
                                        value => {
                                            let bytes = info.get_byte_transmitted() + value.unwrap().clone().1;
                                            let first_time = value.unwrap().clone().2;
                                            hm.insert((info.get_address(), info.get_port()),
                                                      (info.get_protocol(), bytes, first_time, info.get_time_stamp().into()));
                                        }
                                    }
                                },
                                Err(_) => {}
                            }

                        }  */
                    });
                    Ok(())
                },

                Status::Error(_) => {
                    return Err(NetworkAnalyzerError::UserWarning("Internal error. Try to instantiate a new sniffer object.".to_string()));
                },
                _ => {return Err(NetworkAnalyzerError::UserWarning("Another scanning is already running ...".to_string()))}
            }
        }
    }


    }