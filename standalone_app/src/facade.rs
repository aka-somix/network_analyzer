
pub mod frontend_api {
  use pcap::Device;
  use serde::Serialize;
  use crate::sniffer::Sniffer;
  use tauri::State;
  use std::sync::Mutex;

  /**
   * TODO: Documentare
   */
  #[derive(Serialize)]
  pub struct FrontendDevice {
    id: String,
    name: String,
    ipv4_addr: String,
    netmask: String
  }
  impl FrontendDevice {
    pub fn new(dev: Device) -> Self {
        
      // Resolve Descriptive Name
      let name: String;
      match dev.desc {
        None => name = dev.name.clone(),
        Some(descriptive_name) => name = descriptive_name,
      }

      // Resolve Netmask Address
      let netmask: String;
      match dev.addresses[0].netmask {
        None => netmask = String::from(""),
        Some(existing_netmask) => netmask = existing_netmask.to_string(),
      }

      return FrontendDevice {
        id: dev.name,
        name,
        ipv4_addr: dev.addresses[0].addr.to_string(),
        netmask,
      }
    }
  }

  pub struct SnifferState(pub Mutex<Sniffer>);

  #[tauri::command]
  pub fn get_all_devices () -> Vec<FrontendDevice> {
    let devices = Sniffer::get_all_available_devices().unwrap().clone();

    let frontend_devices: Vec<FrontendDevice> = devices.into_iter()
    .filter(|dev| {
      // Return only running Devices
      return dev.flags.is_running() && dev.addresses.len() > 0;
    })
    .map(|dev| FrontendDevice::new(dev)).collect();

    return frontend_devices;
  }

  #[tauri::command]
  pub fn set_device(device_name: String, sniffer: State<SnifferState>) -> Result<String, String> {
    
    let mut sniffer = sniffer.0.lock().unwrap();
    
    let devs_candidate: Vec<Device> = Sniffer::get_all_available_devices()
    .unwrap()
    .clone()
    .into_iter()
    .filter(|dev| {dev.name == device_name})
    .collect();

    if devs_candidate.len() == 0 {
      return Err(String::from("Error. No Device Found with this name!"));
    }

    let result = sniffer.set_device(devs_candidate[0].clone());

    match result {
      Ok(_) => Ok(String::from("OK")),
      Err(_) => Err(String::from("Could not Set the Device!"))
    }
  }

  #[tauri::command]
  pub fn get_device(sniffer: State<SnifferState>) -> Result<FrontendDevice, String> {
    let sniffer = sniffer.0.lock().unwrap();
    
    match sniffer.get_device() {
      Some(device) => Ok(FrontendDevice::new(device.clone())),
      None => Err(String::from("Error. Could Not find a device associated."))
    }
  }

}
