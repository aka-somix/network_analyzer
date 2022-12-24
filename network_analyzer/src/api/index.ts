import { Device } from "../models/network";
import { invoke } from '@tauri-apps/api/tauri'
import { FrontendDevice } from "../models/rust_structs";

export class TauriAPI {
  static async getAllDevices (): Promise<Device[]> {
    const devicesFromBE: FrontendDevice[] = await invoke('get_all_devices');

    return devicesFromBE.map((dev: FrontendDevice): Device => {
      return {
        id: dev.id,
        name: dev.name,
        ipv4Address: dev.ipv4_addr,
        netmask: dev.netmask 
      }
    });
  }
}