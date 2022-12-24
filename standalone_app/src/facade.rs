
pub mod frontend_api {
  use pcap::Device;
use serde::Serialize;

use crate::sniffer::{Sniffer, NetworkAnalyzerError};

  #[derive(Serialize)]
  pub struct FrontendDevice {
    id: String,
    name: String,
    ipv4_addr: String,
    netmask: String
  }

  impl FrontendDevice {
    pub fn new(id: String, name: String, ipv4_addr: String, netmask: String) -> Self {
        return FrontendDevice {
          id,
          name,
          ipv4_addr,
          netmask,
        }
    }
  }


  pub fn get_all_devices () -> Result<Vec<FrontendDevice>, NetworkAnalyzerError> {
    let devices: Vec<Device> = Sniffer::get_all_available_devices().unwrap().clone();
    
    let frontend_devices: Vec<FrontendDevice> = devices.into_iter()
    .filter(|dev| {
      // Return only running Devices
      return dev.flags.is_running() && dev.addresses.len() > 0;
    })
    .map(|dev| {
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

      FrontendDevice::new(
        dev.name,
        name,
        dev.addresses[0].addr.to_string(),
        netmask
      )
    }).collect();

    return Ok(frontend_devices);
  }

}
